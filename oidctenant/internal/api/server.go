package api

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/config"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

const (
	// callbackPath 是应用唯一的 OIDC 回调路径，redirect_uri 由 BASE_URL 拼接。
	callbackPath  = "/oauth/callback"
	linkCBPath    = "/oauth/link/callback"
	sessionCookie = "sid"
)

type ctxKey string

const (
	ctxSession ctxKey = "session"
	ctxMember  ctxKey = "member"
)

// Server 聚合路由处理器依赖。
type Server struct {
	cfg     *config.Config
	store   *store.Store
	oidc    *oidcx.Manager
	logger  *log.Logger
	nowFunc func() time.Time
}

func NewServer(cfg *config.Config, st *store.Store, om *oidcx.Manager, logger *log.Logger) *Server {
	return &Server{
		cfg:     cfg,
		store:   st,
		oidc:    om,
		logger:  logger,
		nowFunc: time.Now,
	}
}

// Routes 注册全部 HTTP 路由（Go 1.22+ 的方法+模式匹配）。
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.health)

	// 登录
	mux.HandleFunc("GET /t/{slug}/login", s.loginStart)
	mux.HandleFunc("GET "+callbackPath, s.loginCallback)

	// 账号关联
	mux.HandleFunc("POST /t/{slug}/api/links", s.requireSession(s.linkStart))
	mux.HandleFunc("GET "+linkCBPath, s.requireSession(s.linkCallback))
	mux.HandleFunc("GET /t/{slug}/api/links/{token}", s.requireSession(s.linkFinalize))

	// 受保护的业务接口
	mux.HandleFunc("GET /t/{slug}/api/me", s.requireSession(s.me))
	mux.HandleFunc("POST /t/{slug}/api/logout", s.requireSession(s.logout))

	return s.loggingMiddleware(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------- 会话中间件 ----------

type authedContext struct {
	session *models.Session
	member  *models.Member
}

// requireSession 解析不透明会话 Cookie（数据库存的是哈希），
// 校验未过期未吊销，并加载成员。失败一律 401 authentication_failed。
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeAPIError(w, authn("missing session cookie"))
			return
		}
		sess, err := s.store.SessionByHash(r.Context(), auth.HashToken(c.Value))
		if err != nil {
			writeAPIError(w, authn("session not found or expired"))
			return
		}
		// 会话必须属于 URL 所指租户，禁止跨租户使用会话。
		slug := r.PathValue("slug")
		tenant, err := s.store.TenantByID(r.Context(), sess.TenantID)
		if err != nil || (slug != "" && tenant.Slug != slug) {
			writeAPIError(w, tenantForbidden("session does not belong to this tenant"))
			return
		}
		member, err := s.store.Member(r.Context(), sess.TenantID, sess.MemberID)
		if err != nil {
			writeAPIError(w, authn("member no longer exists"))
			return
		}
		ac := &authedContext{session: sess, member: member}
		ctx := context.WithValue(r.Context(), ctxSession, ac)
		next(w, r.WithContext(ctx))
	}
}

func authed(r *http.Request) *authedContext {
	return r.Context().Value(ctxSession).(*authedContext)
}

// ---------- 日志（不记录任何凭据/令牌） ----------

var sensitiveQueryParams = map[string]bool{
	"code": true, "id_token": true, "access_token": true,
	"refresh_token": true, "state": true, "token": true,
}

// loggingMiddleware 记录方法、脱敏后的路径与状态码。
// query 中的 code/id_token/state 等一律替换为 "[REDACTED]"，
// 整个应用只有 ID token 解析后的结果进入内存，原始值从不传给 logger。
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.logger.Printf("%s %s -> %d", r.Method, redactedURL(r.URL), rec.status)
	})
}

func redactedURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	q := u.Query()
	changed := false
	for key := range q {
		if sensitiveQueryParams[strings.ToLower(key)] {
			q.Set(key, "[REDACTED]")
			changed = true
		}
	}
	if changed {
		return u.Path + "?" + q.Encode()
	}
	return u.Path
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
