package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	sec "github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

func (s *Server) redirectURLLogin() string {
	return s.cfg.BaseURL + callbackPath
}

func (s *Server) redirectURLLink() string {
	return s.cfg.BaseURL + linkCBPath
}

func (s *Server) now() time.Time { return s.nowFunc() }

// loadTenantProvider 解析租户 slug + issuer 查询参数，并确保该租户启用了该 IdP。
func (s *Server) loadTenantProvider(ctx context.Context, slug, issuer string) (
	*models.Tenant, *models.Provider, *APIError) {
	tenant, err := s.store.TenantBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, tenantForbidden("unknown tenant")
		}
		return nil, nil, newAPIError(http.StatusInternalServerError, "internal_error", "lookup tenant failed")
	}
	if issuer == "" {
		return nil, nil, badRequest("issuer query parameter is required")
	}
	prov, err := s.store.ProviderByIssuer(ctx, tenant.ID, issuer)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// 租户未授权该 issuer —— 与签名失败明确区分。
			return nil, nil, tenantForbidden("this issuer is not authorized for the tenant")
		}
		return nil, nil, newAPIError(http.StatusInternalServerError, "internal_error", "lookup provider failed")
	}
	if !prov.Enabled {
		return nil, nil, tenantForbidden("identity provider is disabled for the tenant")
	}
	return tenant, prov, nil
}

// safeReturnTo 仅允许应用内相对路径跳转，防止登录后 open redirect。
func safeReturnTo(v string) string {
	if v == "" || !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") {
		return "/"
	}
	return v
}

// GET /t/{slug}/login?issuer=...&return_to=/...
func (s *Server) loginStart(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	issuer := r.URL.Query().Get("issuer")
	tenant, prov, ae := s.loadTenantProvider(r.Context(), slug, issuer)
	if ae != nil {
		writeAPIError(w, ae)
		return
	}

	redirectURI := s.redirectURLLogin()
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		// 只允许数据库中为该 provider 登记过的回调地址。
		writeAPIError(w, badRequest("callback url is not registered for this provider"))
		return
	}

	state, err := sec.State()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "state generation failed"))
		return
	}
	nonce, err := sec.Nonce()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "nonce generation failed"))
		return
	}
	verifier, err := sec.PKCEVerifier()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "pkce generation failed"))
		return
	}

	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	if err := s.store.CreateAuthRequest(r.Context(), &models.AuthRequest{
		State:        state,
		Kind:         "login",
		TenantID:     tenant.ID,
		IDPID:        prov.ID,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		ReturnTo:     returnTo,
	}); err != nil {
		s.logger.Printf("persist auth request failed: %v", err)
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "persist auth request failed"))
		return
	}

	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		s.logger.Printf("oidc config error: %v", err)
		writeAPIError(w, authn("failed to initialize provider configuration"))
		return
	}
	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	authURL := oidcx.AuthCodeURL(cfg, state, nonce, challenge, "S256", false, nil)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// GET /oauth/callback?state=...&code=...
//
// 重复到达（同一 state 两次）在 ConsumeAuthRequest 处被原子拦截，
// 因此第二个回调绝不会再走“找到/创建成员”，也就不可能创建多个成员。
func (s *Server) loginCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")
	if state == "" || code == "" {
		writeAPIError(w, badRequest("missing state or code"))
		return
	}
	if errParam := q.Get("error"); errParam != "" {
		// IdP 返回的错误码本身不含敏感材料，但描述可能不可信，仅回传错误码。
		writeAPIError(w, authn("provider returned error: "+sanitizeErrParam(errParam)))
		return
	}

	// 原子取出并消费 state：伪造 state 与重放回调得到同样结果。
	ar, err := s.store.ConsumeAuthRequest(r.Context(), state)
	if err != nil {
		writeAPIError(w, badRequest("authorization request is unknown or has already been used"))
		return
	}
	if ar.Kind != "login" {
		writeAPIError(w, badRequest("state is not valid for the login callback"))
		return
	}

	// 回调必须在租户仍授权该 issuer 的前提下继续。
	prov, err := s.store.ProviderByID(r.Context(), ar.TenantID, ar.IDPID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAPIError(w, tenantForbidden("provider is no longer authorized for the tenant"))
			return
		}
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "lookup provider failed"))
		return
	}
	if !prov.Enabled {
		writeAPIError(w, tenantForbidden("identity provider is disabled for the tenant"))
		return
	}
	redirectURI := s.redirectURLLogin()
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		writeAPIError(w, badRequest("callback url is not registered for this provider"))
		return
	}

	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		s.logger.Printf("oidc config error: %v", err)
		writeAPIError(w, authn("failed to initialize provider configuration"))
		return
	}
	ver, err := s.oidc.Verifier(r.Context(), prov, ar.Nonce)
	if err != nil {
		s.logger.Printf("oidc verifier error: %v", err)
		writeAPIError(w, authn("failed to initialize token verifier"))
		return
	}

	// 令牌交换 + 签名/受众/issuer/过期/nonce/PKCE 校验。
	// 授权码重放、PKCE 不匹配会在这里失败（state 已消费，不可再试）。
	claims, _, err := s.oidc.ExchangeAndVerify(r.Context(), prov, cfg, ver, code, ar.PKCEVerifier)
	if err != nil {
		s.logVerifyFailure(err)
		writeAPIError(w, authn("token exchange or id token verification failed"))
		return
	}

	// 业务身份只基于已核实的 (issuer, subject)，邮箱不参与。
	result, err := s.store.LoginOrRegisterMember(r.Context(), store.LoginIdentity{
		TenantID:      ar.TenantID,
		Issuer:        claims.Issuer,
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		DisplayName:   claims.Name,
	})
	if err != nil {
		s.logger.Printf("login upsert failed: %v", err)
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "login failed"))
		return
	}

	token, err := sec.SessionToken()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "session token failed"))
		return
	}
	if _, err := s.store.CreateSession(r.Context(), ar.TenantID, result.Member.ID,
		sec.HashToken(token), s.cfg.SessionTTL); err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "create session failed"))
		return
	}
	s.setSessionCookie(w, token)

	target := ar.ReturnTo
	if target == "" {
		target = "/"
	}
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	sec := http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: sameSite(s.cfg.CookieSameSite),
		MaxAge:   int(s.cfg.SessionTTL.Seconds()),
	}
	http.SetCookie(w, &sec)
}

func (s *Server) logVerifyFailure(err error) {
	if ve, ok := oidcx.AsVerifyError(err); ok {
		// 只记录分类，不记录令牌或授权码。
		s.logger.Printf("oidc verification failed: kind=%s", ve.Kind)
		return
	}
	s.logger.Printf("oidc verification failed (untyped)")
}

func sameSite(v string) http.SameSite {
	switch strings.ToLower(v) {
	case "none":
		return http.SameSiteNoneMode
	case "strict":
		return http.SameSiteStrictMode
	default:
		return http.SameSiteLaxMode
	}
}

func sanitizeErrParam(v string) string {
	// 只保留 OIDC 标准错误码字符，防止把任意文本反射到响应。
	v = url.QueryEscape(v)
	if len(v) > 40 {
		v = v[:40]
	}
	return v
}
