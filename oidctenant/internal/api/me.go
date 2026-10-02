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
	})
}

// POST /t/{slug}/api/logout
//
// 保持原有单设备退出语义：只撤销当前请求携带的这一个会话并清除 Cookie。
// 其他设备的会话不受影响（要下线其余设备请用 /api/sessions/...）。
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	// 在当前租约事务内撤销自身：与本请求原子提交，不会自锁。
	if err := ac.lease.RevokeSelf(r.Context(), reasonSelfLogout); err != nil {
		s.logger.Printf("logout revoke failed: %v", err)
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "logout failed"))
		return
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}
