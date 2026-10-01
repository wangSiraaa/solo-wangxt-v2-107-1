package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	sec "github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

type linkStartRequest struct {
	Issuer string `json:"issuer"`
	// AnchorIssuer 指定用当前成员的哪个已核实身份作为 A。
	// 成员只有一个身份时可省略；有多个身份时必填。
	AnchorIssuer string `json:"anchor_issuer"`
}

// POST /t/{slug}/api/links
// body: {"issuer": "<target issuer>", "anchor_issuer": "<current issuer>"}
//
// 返回 201 + {"link_token": "...", "link_url": "..."}，调用方让浏览器跳转 link_url。
// 两个身份各自重新认证：
//   - A（当前会话身份）：linkStart 时刻记录 a_auth_time，完成时校验仍在强认证窗口内；
//   - B（目标 IdP 身份）：授权请求强制 prompt=login,max_age=0，
//     回调核对 IdP 返回的 auth_time 必须足够新。
func (s *Server) linkStart(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	var req linkStartRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
		writeAPIError(w, badRequest("invalid JSON body"))
		return
	}
	if req.Issuer == "" {
		writeAPIError(w, badRequest("issuer is required"))
		return
	}

	slug := r.PathValue("slug")
	tenant, targetProv, ae := s.loadTenantProvider(r.Context(), slug, req.Issuer)
	if ae != nil {
		writeAPIError(w, ae) // 租户未授权该 issuer 时为 403 tenant_unauthorized
		return
	}

	// 选择锚点身份 A：必须是该成员已经拥有的、由已核实 (issuer,subject) 标识的身份。
	ids, err := s.store.IdentitiesOfMember(r.Context(), tenant.ID, ac.member.ID)
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "load identities failed"))
		return
	}
	if len(ids) == 0 {
		writeAPIError(w, authn("current member has no verified identity to anchor the link"))
		return
	}
	var anchor *models.Identity
	if req.AnchorIssuer == "" {
		if len(ids) != 1 {
			writeAPIError(w, badRequest("anchor_issuer is required when the member has multiple identities"))
			return
		}
		anchor = &ids[0]
	} else {
		for i := range ids {
			if ids[i].Issuer == req.AnchorIssuer {
				anchor = &ids[i]
				break
			}
		}
		if anchor == nil {
			writeAPIError(w, conflict("anchor issuer is not bound to the current member"))
			return
		}
	}

	redirectURI := s.redirectURLLink()
	if !sec.RedirectURIAllowed(targetProv.RedirectURIs, redirectURI) {
		writeAPIError(w, badRequest("callback url is not registered for this provider"))
		return
	}

	linkTok, err := sec.LinkToken()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "link token failed"))
		return
	}

	// A 的重新认证锚点为当前会话的时刻；CompleteLink 用 maxAge 复核新鲜度。
	ls := &models.LinkSession{
		Token:          linkTok,
		TenantID:       tenant.ID,
		AnchorMemberID: ac.member.ID,
		SessionID:      ac.session.ID,
		TargetIDPID:    targetProv.ID,
		AIssuer:        anchor.Issuer,
		ASubject:       anchor.Subject,
	}
	ls.AAuthTime = sql.NullTime{Time: s.now(), Valid: true}
	if err := s.store.CreateLinkSession(r.Context(), ls, s.cfg.LinkTTL); err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "create link session failed"))
		return
	}

	state, err := sec.State()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "state failed"))
		return
	}
	nonce, err := sec.Nonce()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "nonce failed"))
		return
	}
	verifier, err := sec.PKCEVerifier()
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "pkce failed"))
		return
	}
	sessionID := ac.session.ID
	if err := s.store.CreateAuthRequest(r.Context(), &models.AuthRequest{
		State:        state,
		Kind:         "link_b",
		TenantID:     tenant.ID,
		IDPID:        targetProv.ID,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		ReturnTo:     "/",
		LinkToken:    nullString(linkTok),
		SessionID:    &sessionID,
	}); err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "persist auth request failed"))
		return
	}
	// 把 leg B 的 state 绑定在 link session 上，回调必须与之一致。
	if err := s.store.SetLinkLegBState(r.Context(), linkTok, state); err != nil {
		writeAPIError(w, conflict("link session is not in a usable state"))
		return
	}

	cfg, err := s.oidc.OAuth2Config(r.Context(), targetProv, redirectURI)
	if err != nil {
		writeAPIError(w, authn("failed to initialize provider configuration"))
		return
	}
	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	linkURL := oidcx.AuthCodeURL(cfg, state, nonce, challenge, "S256", true, nil)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"link_token": linkTok,
		"link_url":   linkURL,
	})
}

// GET /oauth/link/callback?state=...&code=...
//
// 完成 B 身份的强制重新认证与全套校验，随后原子完成关联。
// state 与 link token 都是一次性的：任何重放都在消费环节被拒绝。
func (s *Server) linkCallback(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		writeAPIError(w, badRequest("missing state or code"))
		return
	}
	if ep := r.URL.Query().Get("error"); ep != "" {
		writeAPIError(w, authn("provider returned error: "+sanitizeErrParam(ep)))
		return
	}

	// 原子消费 state（防重放；未知 state 与已消费 state 行为一致）。
	ar, err := s.store.ConsumeAuthRequest(r.Context(), state)
	if err != nil {
		writeAPIError(w, badRequest("link authorization request is unknown or already used"))
		return
	}
	if ar.Kind != "link_b" || !ar.LinkToken.Valid {
		writeAPIError(w, badRequest("state is not valid for account linking"))
		return
	}
	// 必须用发起关联时的同一个会话、同一个租户完成。
	if ar.SessionID == nil || *ar.SessionID != ac.session.ID {
		writeAPIError(w, authn("link must be completed in the same browser session that started it"))
		return
	}
	if ar.TenantID != ac.session.TenantID {
		writeAPIError(w, tenantForbidden("link crosses tenant boundary"))
		return
	}

	ls, err := s.store.LinkSession(r.Context(), ar.LinkToken.String)
	if err != nil {
		writeAPIError(w, conflict("link session not found or already used"))
		return
	}
	if ls.Status != "pending" {
		writeAPIError(w, conflict("link session already completed or consumed"))
		return
	}
	if ls.AnchorMemberID != ac.member.ID {
		writeAPIError(w, tenantForbidden("link session belongs to another member"))
		return
	}
	if ls.TargetIDPID != ar.IDPID {
		writeAPIError(w, badRequest("state was issued for a different target provider"))
		return
	}

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
	redirectURI := s.redirectURLLink()
	if !sec.RedirectURIAllowed(prov.RedirectURIs, redirectURI) {
		writeAPIError(w, badRequest("callback url is not registered for this provider"))
		return
	}

	cfg, err := s.oidc.OAuth2Config(r.Context(), prov, redirectURI)
	if err != nil {
		writeAPIError(w, authn("failed to initialize provider configuration"))
		return
	}
	ver, err := s.oidc.Verifier(r.Context(), prov, ar.Nonce)
	if err != nil {
		writeAPIError(w, authn("failed to initialize token verifier"))
		return
	}
	claims, _, err := s.oidc.ExchangeAndVerify(r.Context(), prov, cfg, ver, code, ar.PKCEVerifier)
	if err != nil {
		s.logVerifyFailure(err)
		writeAPIError(w, authn("token exchange or id token verification failed"))
		return
	}

	// B 身份必须来自声明的 issuer，且在 provider 窗口内交互式重新认证过。
	if claims.Issuer != prov.Issuer {
		writeAPIError(w, authn("id token issuer does not match the configured provider"))
		return
	}
	maxAge := providerAuthMaxAge(prov)
	bAuthTime := claims.AuthTime
	if bAuthTime.IsZero() {
		writeAPIError(w, reauthRequired(
			"provider did not report auth_time; cannot prove recent re-authentication"))
		return
	}
	if s.now().Sub(bAuthTime) > maxAge {
		writeAPIError(w, reauthRequired("second identity authentication is stale; re-authenticate"))
		return
	}

	// 原子写入 B leg（state 必须与创建时绑定值一致，防止替换/重放）。
	if err := s.store.AttachLinkLegB(r.Context(), ls.Token, state,
		claims.Issuer, claims.Subject, claims.Email, bAuthTime, prov.ID); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeAPIError(w, conflict("link leg has already been recorded"))
			return
		}
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "persist link leg failed"))
		return
	}

	// 原子完成全部冲突检查与绑定；link token 随即消费，杜绝重放。
	if err := s.store.CompleteLink(r.Context(), ls.Token, s.now(), maxAge); err != nil {
		writeAPIError(w, s.mapLinkError(err))
		return
	}
	if err := s.store.ConsumeCompletedLink(r.Context(), ls.Token); err != nil {
		writeAPIError(w, conflict("link completed but the one-time token could not be consumed"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "linked",
		"link_token":   ls.Token,
		"new_identity": map[string]string{"issuer": claims.Issuer, "subject": claims.Subject},
	})
}

// GET /t/{slug}/api/links/{token}
// 查询关联会话状态。已消费 token 返回 409 binding_conflict，防止重放探测。
func (s *Server) linkFinalize(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	token := r.PathValue("token")
	ls, err := s.store.LinkSession(r.Context(), token)
	if err != nil {
		writeAPIError(w, conflict("link session not found"))
		return
	}
	if ls.AnchorMemberID != ac.member.ID || ls.TenantID != ac.session.TenantID {
		writeAPIError(w, tenantForbidden("link session belongs to another member or tenant"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"link_token": token,
		"status":     ls.Status,
	})
}

func (s *Server) mapLinkError(err error) *APIError {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return conflict("link session expired or was not found")
	case errors.Is(err, store.ErrConflict):
		// 目标 (issuer,subject) 已属于别的成员、同身份自关联或会话状态非法。
		return conflict("target identity is already bound to another member")
	}
	if msg, ok := store.AsReauth(err); ok {
		return reauthRequired(msg)
	}
	s.logger.Printf("complete link failed: %v", err)
	return newAPIError(http.StatusInternalServerError, "internal_error", "complete link failed")
}

func providerAuthMaxAge(p *models.Provider) time.Duration {
	secs := p.AuthTimeMaxAge
	if secs <= 0 {
		secs = 300
	}
	return time.Duration(secs) * time.Second
}

func nullString(v string) sql.NullString {
	return sql.NullString{String: v, Valid: v != ""}
}
