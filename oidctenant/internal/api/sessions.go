package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/store"
)

// sessionView 是设备列表中每台设备的对外投影。
// 刻意只有非敏感字段：id 是会话行的内部 UUID（不是 sid 令牌本身），
// 任何位置都不返回 token_hash、sid、授权码或身份令牌。
type sessionView struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Current      bool   `json:"current"`
	Status       string `json:"status"`
	CreatedAt    string `json:"created_at"`
	LastActiveAt string `json:"last_active_at"`
	ExpiresAt    string `json:"expires_at"`
	RevokedAt    string `json:"revoked_at,omitempty"`
}

func toSessionView(si store.SessionInfo, currentID uuid.UUID, now time.Time) sessionView {
	status := "active"
	revoked := ""
	if si.RevokedAt.Valid {
		status = "revoked"
		revoked = si.RevokedAt.Time.UTC().Format(time.RFC3339)
	} else if !si.ExpiresAt.After(now) {
		status = "expired"
	}
	return sessionView{
		ID:           si.ID.String(),
		Label:        si.DisplayLabel,
		Current:      si.ID == currentID,
		Status:       status,
		CreatedAt:    si.CreatedAt.UTC().Format(time.RFC3339),
		LastActiveAt: si.LastActivityAt.UTC().Format(time.RFC3339),
		ExpiresAt:    si.ExpiresAt.UTC().Format(time.RFC3339),
		RevokedAt:    revoked,
	}
}

// GET /t/{slug}/api/sessions
//
// 列出当前成员在当前租户的全部设备会话（活跃在前，已撤销在后）。
// 只返回展示标签、时间与派生状态，不返回原始 sid / 哈希 / 任何令牌。
func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	infos, err := s.store.ListMemberSessions(r.Context(), ac.session.TenantID, ac.member.ID)
	if err != nil {
		s.logger.Printf("list sessions: %v", err)
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "list sessions failed"))
		return
	}
	now := s.now()
	out := make([]sessionView, 0, len(infos))
	for _, si := range infos {
		out = append(out, toSessionView(si, ac.session.ID, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"current_id": ac.session.ID.String(),
		"sessions":   out,
	})
}

// DELETE /t/{slug}/api/sessions/{id}
//
// 撤销成员自己在本租户的指定设备会话：
//   - 撤销“其他设备”：返回 200 {"status":"revoked"}，不动当前 Cookie；
//   - 撤销“当前设备”：等价 logout，撤销在请求事务内提交，并清理 sid Cookie；
//   - 重复撤销：稳定幂等，返回 200 {"status":"already_revoked"}；
//   - id 非法 / 不存在 / 属于别的成员或别的租户：一律 404 not_found，
//     无法借此枚举其他成员或跨租户（同邮箱）会话。
func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	raw := r.PathValue("id")
	id, err := uuid.Parse(raw)
	if err != nil {
		writeAPIError(w, notFound("session not found"))
		return
	}

	// 撤销当前设备：在鉴权请求事务内完成（持有同一行锁），语义等同 logout。
	if id == ac.session.ID {
		if err := s.store.RevokeCurrentSession(r.Context(), ac.session.ID); err != nil {
			s.logger.Printf("revoke current session: %v", err)
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "revoke failed"))
			return
		}
		s.clearSessionCookie(w, r, true)
		writeJSON(w, http.StatusOK, map[string]string{
			"id":     ac.session.ID.String(),
			"status": "revoked",
		})
		return
	}

	// 撤销其他设备：归属条件在 store 内强约束；独立事务、有序加锁、
	// 与对方正在进行的受保护请求严格串行。
	err = s.store.RevokeMemberSession(r.Context(), ac.session.TenantID, ac.member.ID, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeAPIError(w, notFound("session not found"))
	case errors.Is(err, store.ErrAlreadyRevoked):
		// 幂等：此前已撤销返回稳定结果。
		writeJSON(w, http.StatusOK, map[string]string{
			"id":     id.String(),
			"status": "already_revoked",
		})
	case err != nil:
		s.logger.Printf("revoke session: %v", err)
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "revoke failed"))
	default:
		writeJSON(w, http.StatusOK, map[string]string{
			"id":     id.String(),
			"status": "revoked",
		})
	}
}

// POST /t/{slug}/api/sessions/revoke-all
//
// 撤销成员在当前租户的全部其他设备，并清理本机 sid Cookie ——
// 即“退出所有设备”。当前会话也一并撤销；body 可空。
func (s *Server) revokeAllSessions(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)

	// 其他设备在独立事务中有序锁定/撤销（排除当前请求持锁的本行）。
	n, err := s.store.RevokeAllMemberSessions(r.Context(),
		ac.session.TenantID, ac.member.ID, ac.session.ID)
	if err != nil {
		s.logger.Printf("revoke all sessions: %v", err)
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "revoke failed"))
		return
	}
	// 当前设备随请求事务一起撤销。
	if err := s.store.RevokeCurrentSession(r.Context(), ac.session.ID); err != nil {
		s.logger.Printf("revoke current session: %v", err)
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "revoke failed"))
		return
	}
	s.clearSessionCookie(w, r, true)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "logged_out_all",
		"other_revoked":   n,
		"current_revoked": true,
	})
}
