package api

import (
	"context"
	"errors"
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

	// 设备会话管理：列出本机/其他设备、撤销指定设备、全部设备退出。
	mux.HandleFunc("GET /t/{slug}/api/sessions", s.requireSession(s.listSessions))
	mux.HandleFunc("DELETE /t/{slug}/api/sessions/{id}", s.requireSession(s.revokeSession))
	mux.HandleFunc("POST /t/{slug}/api/sessions/revoke-all", s.requireSession(s.revokeAllSessions))

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
// 在单个请求事务里锁定会话行、校验未过期未撤销、刷新最近活动时间并加载成员。
//
// 行锁持续到整个请求处理结束（事务提交）为止：并发的设备撤销必须等待本事务，
// 反之亦然，因此“撤销会话”与“受保护接口写入”在数据库层面严格串行，
// 已撤销会话不可能在撤销提交之后再成功访问/写入任何受保护接口。
// 认证失败一律 401 authentication_failed，并清理已失效的 sid Cookie。
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			writeAPIError(w, authn("missing session cookie"))
			return
		}
		tokenHash := auth.HashToken(c.Value)

		// 开启请求事务；TouchSession 的行锁随该事务保持到请求结束。
		rtx, txCtx, err := store.BeginRequestTx(r.Context(), s.store.DB())
		if err != nil {
			s.logger.Printf("begin request tx: %v", err)
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "authentication failed"))
			return
		}
		committed := false
		defer func() {
			if !committed {
				_ = rtx.Rollback(r.Context())
			}
		}()

		var (
			sess   *models.Session
			tenant *models.Tenant
			member *models.Member
		)
		// 条件 UPDATE ... RETURNING 同时完成：取行、加排他行锁、
		// 拒绝已撤销/已过期会话、刷新最近活动时间。
		sess, err = s.store.TouchSession(txCtx, tokenHash)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				_ = rtx.Rollback(r.Context())
				committed = true
				s.clearSessionCookie(w, r, false)
				writeAPIError(w, authn("session not found, expired, or revoked"))
				return
			}
			s.logger.Printf("touch session: %v", err)
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "authentication failed"))
			return
		}
		tenant, err = s.store.TenantByID(txCtx, sess.TenantID)
		if err != nil {
			s.logger.Printf("load tenant: %v", err)
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "authentication failed"))
			return
		}
		// 会话必须属于 URL 所指租户，禁止跨租户使用会话。
		if slug := r.PathValue("slug"); slug != "" && tenant.Slug != slug {
			_ = rtx.Rollback(r.Context())
			committed = true
			writeAPIError(w, tenantForbidden("session does not belong to this tenant"))
			return
		}
		member, err = s.store.Member(txCtx, sess.TenantID, sess.MemberID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				_ = rtx.Rollback(r.Context())
				committed = true
				s.clearSessionCookie(w, r, false)
				writeAPIError(w, authn("member no longer exists"))
				return
			}
			s.logger.Printf("load member: %v", err)
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "authentication failed"))
			return
		}

		ac := &authedContext{session: sess, member: member}
		reqCtx := context.WithValue(txCtx, ctxSession, ac)

		// 提交闸门：handler 第一次写响应（WriteHeader/Write）之前先提交事务。
		// 这样客户端只有在会话行锁释放、撤销串行点过去之后才可能看到成功响应，
		// 绝不会出现“响应已成功、事务随后失败/回滚”。
		cw := &commitWriter{
			ResponseWriter: w,
			commit: func() bool {
				if committed {
					return true
				}
				if err := rtx.Commit(r.Context()); err != nil {
					s.logger.Printf("commit request tx before response: %v", err)
					return false
				}
				committed = true
				return true
			},
			rollback: func() {
				if !committed {
					_ = rtx.Rollback(r.Context())
					committed = true
				}
			},
		}
		defer cw.rollback()
		// handler 内所有 store 调用都在持有行锁的同一事务内执行。
		next(cw, r.WithContext(reqCtx))
	}
}

// commitWriter 在响应头第一次写出前提交请求事务；
// 提交失败则把响应改写为 500（handler 的 body 尚未写出）。
type commitWriter struct {
	http.ResponseWriter
	commit   func() bool
	rollback func()

	wrote    bool
	commitOK bool
}

func (c *commitWriter) WriteHeader(code int) {
	if c.wrote {
		return
	}
	c.wrote = true
	if !c.commit() {
		c.ResponseWriter.Header().Set("Content-Type", "application/json; charset=utf-8")
		c.ResponseWriter.WriteHeader(http.StatusInternalServerError)
		_, _ = c.ResponseWriter.Write([]byte(`{"error":"internal_error","message":"request failed"}` + "\n"))
		return
	}
	c.commitOK = true
	c.ResponseWriter.WriteHeader(code)
}

func (c *commitWriter) Write(p []byte) (int, error) {
	if !c.wrote {
		c.WriteHeader(http.StatusOK)
	}
	if !c.commitOK {
		// 提交失败：500 已写出，丢弃 handler 原本要写的 body。
		return len(p), nil
	}
	return c.ResponseWriter.Write(p)
}

var _ http.Flusher = (*commitWriter)(nil)

// Flush 在提交事务后透传底层 Flush；提交失败则不向下 flush。
func (c *commitWriter) Flush() {
	if !c.wrote {
		c.WriteHeader(http.StatusOK)
	}
	if !c.commitOK {
		return
	}
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
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
