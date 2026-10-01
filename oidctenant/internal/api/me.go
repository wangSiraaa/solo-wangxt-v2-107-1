package api

import (
	"errors"
	"net/http"

	"github.com/example/oidctenant/internal/store"
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
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	if err := s.store.RevokeSession(r.Context(), ac.session.ID); err != nil &&
		!errors.Is(err, store.ErrNotFound) {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "logout failed"))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
		Expires:  s.now().AddDate(0, 0, -1),
		SameSite: sameSite(s.cfg.CookieSameSite),
		Secure:   s.cfg.CookieSecure,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}
