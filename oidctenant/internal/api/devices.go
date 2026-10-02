package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/store"
)

// 撤销原因（仅服务端记录与审计用途；不是凭据）。
const (
	reasonSelfLogout   = "self_logout"
	reasonDeviceRevoke = "device_revoke"
	reasonRevokeAll    = "revoke_all"
)

// sessionView 是设备会话列表中暴露给成员本人的信息。
// 刻意不含 sid / token_hash / 任何授权码或身份令牌：
// 调用方只能看到展示标签、时间与状态，不能据此重建会话凭据。
type sessionView struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	Current    bool      `json:"current"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	LastIP     string    `json:"last_ip"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func toSessionView(sess models.Session, currentID uuid.UUID) sessionView {
	status := "active"
	if sess.RevokedAt.Valid {
		status = "revoked"
	}
	label := sess.DeviceLabel
	if label == "" {
		label = "Unknown device"
	}
	return sessionView{
		ID:         sess.ID.String(),
		Label:      label,
		Current:    sess.ID == currentID,
		Status:     status,
		CreatedAt:  sess.CreatedAt,
		LastSeenAt: sess.LastSeenAt,
		LastIP:     sess.LastIP,
		ExpiresAt:  sess.ExpiresAt,
	}
}

// GET /t/{slug}/api/sessions
//
// 列出当前成员在当前租户下的全部未过期会话（含已撤销的近期记录）。
// 永远只返回会话 UUID（随机 v4 UUID，与 sid 不可互相推导），不返回原始 sid。
func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	sessions, err := s.store.MemberSessions(r.Context(), ac.session.TenantID, ac.member.ID)
	if err != nil {
		writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "list sessions failed"))
		return
	}
	out := make([]sessionView, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, toSessionView(sess, ac.session.ID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// revokeSessionRequest 撤销指定设备会话。
type revokeSessionRequest struct {
	// 预留字段：当前无额外参数，空 body 也允许（保持接口可演进）。
}

// POST /t/{slug}/api/sessions/{id}/revoke
//
// 只能撤销“当前成员、当前租户”名下的会话：
//   - 未知 UUID、其他成员、其他租户的 id 一律 404 not_found，响应完全一致，无法枚举；
//   - 重复撤销返回稳定的幂等结果（200，revoked=false，状态保持 revoked）；
//   - 被撤销的恰为当前会话时清除 sid Cookie；
//   - 与该会话上正在执行的受保护操作线性互斥（行锁），撤销提交后不可能再写入成功。
func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeAPIError(w, badRequest("invalid session id"))
		return
	}
	// 允许空 body；有 body 时必须是合法 JSON。
	if r.Body != nil {
		var req revokeSessionRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
			if !errors.Is(err, io.EOF) {
				writeAPIError(w, badRequest("invalid JSON body"))
				return
			}
		}
	}

	if id == ac.session.ID {
		// 撤销当前设备：当前行已被本请求的租约 FOR UPDATE 锁定，
		// 必须在租约事务内撤销（另开事务会自锁到 lock_timeout）。
		// 首次撤销恒为 revoked=true；重复请求时 Cookie 已清、租约无法建立，
		// 得到一致的 401 authentication_failed。
		if err := ac.lease.RevokeSelf(r.Context(), reasonDeviceRevoke); err != nil {
			s.writeRevokeErr(w, err)
			return
		}
		s.clearSessionCookie(w)
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "revoked", "revoked": true, "current": true,
		})
		return
	}

	// 撤销其他设备：独立事务按 id 加行锁，与该设备上正在执行的受保护操作互斥。
	// 未知 UUID、其他成员、其他租户统一 not_found，无法枚举。
	res, err := s.store.RevokeMemberSession(r.Context(),
		ac.session.TenantID, ac.member.ID, id, reasonDeviceRevoke)
	if err != nil {
		s.writeRevokeErr(w, err)
		return
	}
	if !res.Exists {
		writeAPIError(w, notFound("session not found for this member"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "revoked",
		"revoked": res.Revoked, // 首次撤销 true；重复撤销 false（幂等）
		"current": false,
	})
}

type revokeAllRequest struct {
	// IncludeCurrent=true（默认）时撤销全部设备（含当前会话）并清除当前 Cookie；
	// false 时只撤销其他设备，当前会话保持登录（“下线其余设备”）。
	IncludeCurrent *bool `json:"include_current"`
}

// POST /t/{slug}/api/sessions/revoke-all  body: {"include_current": true}
//
// 全部撤销都发生在当前请求的租约事务里（当前会话行已锁，其余目标行按 id 排序加锁），
// 与中间件的提交构成同一个原子点：响应返回后没有任何该成员的活跃会话。
func (s *Server) revokeAllSessions(w http.ResponseWriter, r *http.Request) {
	ac := authed(r)
	includeCurrent := true
	if r.Body != nil {
		var req revokeAllRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
			if !errors.Is(err, io.EOF) {
				writeAPIError(w, badRequest("invalid JSON body"))
				return
			}
		}
		if req.IncludeCurrent != nil {
			includeCurrent = *req.IncludeCurrent
		}
	}

	// 撤销“其他设备”（排除当前会话，避免重复更新已锁的当前行）。
	n, err := ac.lease.RevokeOthers(r.Context(), reasonRevokeAll)
	if err != nil {
		s.writeRevokeErr(w, err)
		return
	}
	if includeCurrent {
		if err := ac.lease.RevokeSelf(r.Context(), reasonRevokeAll); err != nil {
			s.writeRevokeErr(w, err)
			return
		}
		n++
		s.clearSessionCookie(w)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "revoked",
		"revoked_count":   n,
		"current":         includeCurrent,
		"include_current": includeCurrent,
	})
}

func (s *Server) writeRevokeErr(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrLockBusy) {
		// 行锁竞争超时：撤销本身幂等，客户端原样重试即可。
		writeAPIError(w, busy("session is busy; retry the revocation"))
		return
	}
	s.logger.Printf("revoke session failed: %v", err)
	writeAPIError(w, newAPIError(http.StatusInternalServerError, "internal_error", "revoke session failed"))
}

// maxDeviceLabelLen 限制展示标签长度（User-Agent 可能很长）。
const maxDeviceLabelLen = 200

// deviceLabelFromRequest 从请求中派生不含任何凭据的展示标签。
// 仅取 User-Agent：剥掉控制字符（防止日志/列表注入换行伪造记录），并截断长度。
// sid、授权码、身份令牌永远不进入标签。
func deviceLabelFromRequest(r *http.Request) string {
	ua := r.UserAgent()
	var b strings.Builder
	b.Grow(len(ua))
	for _, rn := range ua {
		if rn < 0x20 || rn == 0x7f {
			continue // 丢弃 CR/LF/制表等控制字符
		}
		b.WriteRune(rn)
	}
	label := strings.TrimSpace(b.String())
	if len(label) > maxDeviceLabelLen {
		label = label[:maxDeviceLabelLen]
	}
	return label
}
