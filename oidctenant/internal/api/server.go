package api

import (
	"context"
	"errors"
	"log"
	"net"
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

	// 设备会话管理
	mux.HandleFunc("GET /t/{slug}/api/sessions", s.requireSession(s.listSessions))
	mux.HandleFunc("POST /t/{slug}/api/sessions/revoke-all", s.requireSession(s.revokeAllSessions))
	mux.HandleFunc("POST /t/{slug}/api/sessions/{id}/revoke", s.requireSession(s.revokeSession))

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
	lease   *store.SessionLease
	session *models.Session
	member  *models.Member
}

// requireSession 解析不透明会话 Cookie（数据库存的是哈希），
// 取出行级租约锁并校验未过期未吊销，然后加载成员。
//
// 租约锁在整个下游处理期间持有：任何撤销（本设备/其他设备/全部退出）都必须
// 等待当前受保护操作完成，反之撤销一旦提交，后续请求获取租约时即看到 revoked_at。
// 因此“被撤销会话继续访问受保护接口（包括写入型接口）”在并发下也不可能发生。
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeAPIError(w, authn("missing session cookie"))
			return
		}
		lease, err := s.store.AcquireSessionLease(r.Context(), auth.HashToken(c.Value))
		if err != nil {
			if errors.Is(err, store.ErrLockBusy) {
				writeAPIError(w, busy("session is busy; retry the request"))
				return
			}
			// 未知/已撤销/已过期得到一致结果；顺手清掉浏览器里失效的 Cookie。
			s.clearSessionCookie(w)
			writeAPIError(w, authn("session not found, revoked or expired"))
			return
		}
		sess := lease.Sess
		// 会话必须属于 URL 所指租户，禁止跨租户使用会话。
		slug := r.PathValue("slug")
		tenant, err := s.store.TenantByID(r.Context(), sess.TenantID)
		if err != nil || (slug != "" && tenant.Slug != slug) {
			lease.Rollback(r.Context())
			writeAPIError(w, tenantForbidden("session does not belong to this tenant"))
			return
		}
		member, err := s.store.Member(r.Context(), sess.TenantID, sess.MemberID)
		if err != nil {
			lease.Rollback(r.Context())
			writeAPIError(w, authn("member no longer exists"))
			return
		}
		ac := &authedContext{lease: lease, session: sess, member: member}
		ctx := context.WithValue(r.Context(), ctxSession, ac)
		next(w, r.WithContext(ctx))
		// 处理器返回后统一结束租约：正常路径刷新 last_seen_at 并提交；
		// 若处理器在租约内撤销了自身（logout/撤销当前设备/全部退出），
		// 撤销与请求完成在同一个事务提交点原子发生。
		// 提交失败仅记日志（行锁随连接释放）。
		if err := lease.Finalize(r.Context(), clientIP(r)); err != nil {
			s.logger.Printf("session lease finalize failed: %v", err)
		}
	}
}

func authed(r *http.Request) *authedContext {
	return r.Context().Value(ctxSession).(*authedContext)
}

// clearSessionCookie 让浏览器删除失效的 sid Cookie（与 setSessionCookie 同 Path/属性）。
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  time.Now().AddDate(0, 0, -1),
		SameSite: sameSite(s.cfg.CookieSameSite),
		Secure:   s.cfg.CookieSecure,
	})
}

// clientIP 提取展示用对端地址（RemoteAddr 去掉端口）；不解析可能伪造的
// X-Forwarded-* 头，除非部署方明确在反代处覆盖。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
