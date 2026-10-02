package api

import (
	"net/http"
)

// identityView 暴露给业务接口的身份信息。
type identityView struct {
	Issuer        string `json:"issuer"`
	Subject       string `json:"subject"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// GET /t/{slug}/api/me
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	ids, err := s.store.IdentitiesOfMember(r.Context(), ac.session.TenantID, ac.member.ID)
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "load identities failed"))
		return
	}
	out := make([]identityView, 0, len(ids))
	for _, id := range ids {
		out = append(out, identityView{
			Issuer:        id.Issuer,
			Subject:       id.Subject,
			Email:         id.Email,
			EmailVerified: id.EmailVerified,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"member_id":  ac.member.ID.String(),
		"tenant_id":  ac.session.TenantID.String(),
		"name":       ac.member.DisplayName,
		"identities": out,
		// 当前设备会话 id（非 sid 本身），前端可用它高亮“当前设备”。
		"session_id": ac.session.ID.String(),
	})
}

// POST /t/{slug}/api/logout
//
// 保持既有“单设备退出”语义：只撤销当前浏览器的会话并清理 sid Cookie，
// 其他设备不受影响。撤销发生在鉴权请求事务内（持当前会话行锁），
// 与并发请求严格串行。
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	if err := s.store.RevokeCurrentSession(r.Context(), ac.session.ID); err != nil {
		s.logger.Printf("logout: %v", err)
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "logout failed"))
		return
	}
	s.clearSessionCookie(w, r, true)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}
