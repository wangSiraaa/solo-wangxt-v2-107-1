// Package store 封装所有 PostgreSQL 访问（pgx 原生驱动）。
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/example/oidctenant/internal/models"
)

var (
	// ErrNotFound 表示按主键/唯一键没有找到行。
	ErrNotFound = errors.New("store: not found")
	// ErrConsumed 表示 state 已被消费（回调重复到达）或根本不存在。
	// 对二者返回同样的错误，避免通过接口枚举有效 state。
	ErrConsumed = errors.New("store: auth request already consumed or unknown")
	// ErrConflict 表示唯一约束冲突（绑定冲突）。
	ErrConflict = errors.New("store: unique constraint violation")
	// ErrLockBusy 表示等待会话行锁超时（撤销与受保护请求竞争），调用方可安全重试。
	ErrLockBusy = errors.New("store: session lock busy")
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// DB 暴露底层连接池（迁移/测试查询用）。
func (s *Store) DB() *pgxpool.Pool { return s.pool }

func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return ErrConflict
		case "55P03": // lock_not_available（SET LOCAL lock_timeout 超时）
			return ErrLockBusy
		case "40P01": // deadlock_detected（多个批量撤销竞争，任一方安全重试即可）
			return ErrLockBusy
		}
	}
	return err
}

// ---------- tenant / provider ----------

func (s *Store) TenantBySlug(ctx context.Context, slug string) (*models.Tenant, error) {
	var t models.Tenant
	err := s.pool.QueryRow(ctx,
		`SELECT id, slug, name, created_at FROM tenants WHERE slug = $1`, slug,
	).Scan(&t.ID, &t.Slug, &t.Name, &t.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &t, nil
}

func (s *Store) TenantByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	var t models.Tenant
	err := s.pool.QueryRow(ctx,
		`SELECT id, slug, name, created_at FROM tenants WHERE id = $1`, id,
	).Scan(&t.ID, &t.Slug, &t.Name, &t.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &t, nil
}

// UpsertTenant 创建或更新租户。
func (s *Store) UpsertTenant(ctx context.Context, id uuid.UUID, slug, name string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO tenants(id, slug, name) VALUES ($1,$2,$3)
		 ON CONFLICT (id) DO UPDATE SET slug = EXCLUDED.slug, name = EXCLUDED.name`,
		id, slug, name)
	return err
}

func (s *Store) ProviderByIssuer(ctx context.Context, tenantID uuid.UUID, issuer string) (*models.Provider, error) {
	return s.provider(ctx,
		`SELECT id, tenant_id, issuer, client_id, client_secret, redirect_uris,
		        auth_time_max_age, enabled, created_at, updated_at
		 FROM identity_providers WHERE tenant_id = $1 AND issuer = $2`,
		tenantID, issuer)
}

func (s *Store) ProviderByID(ctx context.Context, tenantID, idpID uuid.UUID) (*models.Provider, error) {
	return s.provider(ctx,
		`SELECT id, tenant_id, issuer, client_id, client_secret, redirect_uris,
		        auth_time_max_age, enabled, created_at, updated_at
		 FROM identity_providers WHERE tenant_id = $1 AND id = $2`,
		tenantID, idpID)
}

func (s *Store) provider(ctx context.Context, q string, args ...any) (*models.Provider, error) {
	var p models.Provider
	err := s.pool.QueryRow(ctx, q, args...).Scan(
		&p.ID, &p.TenantID, &p.Issuer, &p.ClientID, &p.ClientSecret, &p.RedirectURIs,
		&p.AuthTimeMaxAge, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &p, nil
}

// UpsertProvider 创建或更新租户的一个 issuer 配置。
func (s *Store) UpsertProvider(ctx context.Context, p *models.Provider) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO identity_providers
		 (id, tenant_id, issuer, client_id, client_secret, redirect_uris, auth_time_max_age, enabled)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (tenant_id, issuer) DO UPDATE SET
		   client_id = EXCLUDED.client_id,
		   client_secret = EXCLUDED.client_secret,
		   redirect_uris = EXCLUDED.redirect_uris,
		   auth_time_max_age = EXCLUDED.auth_time_max_age,
		   enabled = EXCLUDED.enabled,
		   updated_at = now()`,
		p.ID, p.TenantID, p.Issuer, p.ClientID, p.ClientSecret, p.RedirectURIs,
		p.AuthTimeMaxAge, p.Enabled)
	return err
}

// ---------- auth requests ----------

func (s *Store) CreateAuthRequest(ctx context.Context, ar *models.AuthRequest) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth_requests
		 (state, kind, tenant_id, idp_id, nonce, pkce_verifier, return_to, link_token, session_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		ar.State, ar.Kind, ar.TenantID, ar.IDPID, ar.Nonce, ar.PKCEVerifier,
		ar.ReturnTo, nullableStr(ar.LinkToken), ar.SessionID)
	return mapErr(err)
}

// ConsumeAuthRequest 原子地取出并消费一个 state。
// 重复回调（已消费）或伪造 state 一律返回 ErrConsumed。
func (s *Store) ConsumeAuthRequest(ctx context.Context, state string) (*models.AuthRequest, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var ar models.AuthRequest
	err = tx.QueryRow(ctx,
		`SELECT state, kind, tenant_id, idp_id, nonce, pkce_verifier, return_to,
		        link_token, session_id, created_at
		 FROM auth_requests WHERE state = $1 AND consumed_at IS NULL
		 FOR UPDATE`,
		state,
	).Scan(&ar.State, &ar.Kind, &ar.TenantID, &ar.IDPID, &ar.Nonce,
		&ar.PKCEVerifier, &ar.ReturnTo, &ar.LinkToken, &ar.SessionID, &ar.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConsumed
		}
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE auth_requests SET consumed_at = now() WHERE state = $1`, state); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &ar, nil
}

// DeleteExpiredAuthRequests 清理过期未消费的 state 行。
func (s *Store) DeleteExpiredAuthRequests(ctx context.Context, before time.Time) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM auth_requests WHERE created_at < $1`, before)
	return err
}

// ---------- 登录：按已核实身份找到或创建成员（并发安全，回调重放安全） ----------

// LoginIdentity 是回调中已通过加密校验的身份信息。
type LoginIdentity struct {
	TenantID      uuid.UUID
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
}

// LoginMemberResult 返回成员信息以及该身份是否为首次登录。
type LoginMemberResult struct {
	Member  *models.Member
	Created bool
}

// LoginOrRegisterMember 以 (tenant_id, issuer, subject) 为锚点查找/创建成员。
//
// 事务内先取事务级咨询锁，保证两个并发的首次回调不会各自插入一个成员；
// 行上的 UNIQUE(tenant_id, issuer, subject) 是第二道防线。
func (s *Store) LoginOrRegisterMember(ctx context.Context, in LoginIdentity) (*LoginMemberResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	created := false

	// pg_advisory_xact_lock 以 issuer|subject 的哈希作为 key，事务结束自动释放。
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1 || '|' || $2, 0))`,
		in.Issuer, in.Subject); err != nil {
		return nil, err
	}

	var identityID, memberID uuid.UUID
	var email string
	var emailVerified bool
	err = tx.QueryRow(ctx,
		`SELECT id, member_id, email, email_verified FROM identities
		 WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`,
		in.TenantID, in.Issuer, in.Subject,
	).Scan(&identityID, &memberID, &email, &emailVerified)
	switch {
	case err == nil:
		// 已有身份：刷新展示字段，复用既有成员。绝不按邮箱合并账号。
		if _, err := tx.Exec(ctx,
			`UPDATE identities SET email = $1, email_verified = $2, updated_at = now()
			 WHERE id = $3`, in.Email, in.EmailVerified, identityID); err != nil {
			return nil, err
		}
		if in.DisplayName != "" {
			_, _ = tx.Exec(ctx,
				`UPDATE members SET display_name = $1 WHERE id = $2 AND display_name = ''`,
				in.DisplayName, memberID)
		}
	case errors.Is(err, pgx.ErrNoRows):
		// 全新身份：创建成员 + 身份，二者在同一事务里。
		created = true
		memberID = uuid.New()
		if _, err := tx.Exec(ctx,
			`INSERT INTO members(id, tenant_id, display_name) VALUES ($1,$2,$3)`,
			memberID, in.TenantID, in.DisplayName); err != nil {
			return nil, mapErr(err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO identities(id, tenant_id, member_id, issuer, subject, email, email_verified)
			 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			uuid.New(), in.TenantID, memberID, in.Issuer, in.Subject,
			in.Email, in.EmailVerified); err != nil {
			return nil, mapErr(err)
		}
	default:
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, mapErr(err)
	}

	m, err := s.Member(ctx, in.TenantID, memberID)
	if err != nil {
		return nil, err
	}
	return &LoginMemberResult{Member: m, Created: created}, nil
}

func (s *Store) Member(ctx context.Context, tenantID, memberID uuid.UUID) (*models.Member, error) {
	var m models.Member
	err := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, display_name, created_at FROM members
		 WHERE id = $1 AND tenant_id = $2`, memberID, tenantID,
	).Scan(&m.ID, &m.TenantID, &m.DisplayName, &m.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &m, nil
}

// IdentitiesOfMember 返回成员在本租户内已绑定的全部已核实身份。
func (s *Store) IdentitiesOfMember(ctx context.Context, tenantID, memberID uuid.UUID) ([]models.Identity, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, member_id, issuer, subject, email, email_verified
		 FROM identities WHERE tenant_id = $1 AND member_id = $2 ORDER BY created_at`,
		tenantID, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Identity
	for rows.Next() {
		var i models.Identity
		if err := rows.Scan(&i.ID, &i.TenantID, &i.MemberID, &i.Issuer,
			&i.Subject, &i.Email, &i.EmailVerified); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// IdentityByAnchor 按业务身份锚点查找（绝不按邮箱）。
func (s *Store) IdentityByAnchor(ctx context.Context, tenantID uuid.UUID, issuer, subject string) (*models.Identity, error) {
	var i models.Identity
	err := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, member_id, issuer, subject, email, email_verified
		 FROM identities WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`,
		tenantID, issuer, subject,
	).Scan(&i.ID, &i.TenantID, &i.MemberID, &i.Issuer, &i.Subject,
		&i.Email, &i.EmailVerified)
	if err != nil {
		return nil, mapErr(err)
	}
	return &i, nil
}

// ---------- sessions（设备会话） ----------
//
// 并发与撤销竞争的核心约定：
//
//   - 受保护请求在 AcquireSessionLease 中以 SELECT ... FOR UPDATE 锁住会话行，
//     并在整个请求期间（SessionLease.Finalize/Rollback 之前）持续持有该锁；
//     Finalize 在同事务刷新 last_seen_at，使“观察到活跃状态”与“刷新活动时间”原子化。
//   - 撤销（RevokeMemberSession 针对其他设备；RevokeSelf/RevokeOthers 针对当前请求
//     自己的设备或同成员其余设备）都对目标行 FOR UPDATE 后才写 revoked_at。
//     锁与写在同一个事务，因此：
//     要么撤销先拿到锁（请求随后拿锁即看到 revoked_at，401，绝不放行写入）；
//     要么请求先拿到锁（撤销必须等到请求结束，不存在“撤销后该请求仍成功写入”）。
//   - 批量撤销按会话 id 排序后逐行加锁，多个并发撤销之间形成全局一致的
//     加锁顺序，避免 AB-BA 死锁。

// CreateSessionParams 携带创建设备会话所需的全部非令牌信息。
type CreateSessionParams struct {
	TenantID    uuid.UUID
	MemberID    uuid.UUID
	TokenHash   []byte
	TTL         time.Duration
	DeviceLabel string
	LastIP      string
}

func (s *Store) CreateSession(ctx context.Context, p CreateSessionParams) (*models.Session, error) {
	id := uuid.New()
	now := time.Now()
	exp := now.Add(p.TTL)
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO sessions
		 (id, tenant_id, member_id, token_hash, device_label, last_ip,
		  created_at, last_seen_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8)`,
		id, p.TenantID, p.MemberID, p.TokenHash, p.DeviceLabel, p.LastIP, now, exp); err != nil {
		return nil, err
	}
	return &models.Session{
		ID: id, TenantID: p.TenantID, MemberID: p.MemberID, TokenHash: p.TokenHash,
		DeviceLabel: p.DeviceLabel, LastIP: p.LastIP,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: exp,
	}, nil
}

// sessionLockTimeout 是等待单条会话行锁的上限。
// 行锁只在单个 HTTP 请求期间持有，等待超过该值视为繁忙竞争（可安全重试）。
const sessionLockTimeout = 10 * time.Second

// SessionLease 是受保护请求期间对某条会话行持有的 FOR UPDATE 锁。
// 请求结束必须调用 Finalize（放行并刷新活动时间/提交自撤销）或 Rollback（错误路径）。
type SessionLease struct {
	tx      pgx.Tx
	Sess    *models.Session
	revoked bool // 当前请求在租约事务内撤销了自身（logout / 撤销当前设备 / 全部退出）
}

const sessionColumns = `id, tenant_id, member_id, token_hash, device_label,
	created_at, last_seen_at, last_ip, expires_at, revoked_at, revoked_reason`

func scanSession(row pgx.Row) (*models.Session, error) {
	var sess models.Session
	var revokedAt sql.NullTime
	var revokedReason sql.NullString
	err := row.Scan(&sess.ID, &sess.TenantID, &sess.MemberID, &sess.TokenHash,
		&sess.DeviceLabel, &sess.CreatedAt, &sess.LastSeenAt, &sess.LastIP,
		&sess.ExpiresAt, &revokedAt, &revokedReason)
	if err != nil {
		return nil, mapErr(err)
	}
	sess.RevokedAt = revokedAt
	sess.RevokedReason = revokedReason
	return &sess, nil
}

// AcquireSessionLease 按 sid 哈希取出会话、锁住行并在同一事务中校验状态。
//
// 返回的 SessionLease.Sess 保证在租约期间不会被撤销（撤销方阻塞在同一行锁上）。
// 未找到/已撤销/已过期统一返回 ErrNotFound —— 对调用方而言都是“认证失败”，
// 不区分会话是否存在，避免据此枚举有效 sid。
func (s *Store) AcquireSessionLease(ctx context.Context, tokenHash []byte) (*SessionLease, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		"SELECT set_config('lock_timeout', $1, true)",
		fmt.Sprintf("%dms", sessionLockTimeout.Milliseconds())); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	sess, err := scanSession(tx.QueryRow(ctx,
		`SELECT `+sessionColumns+`
		 FROM sessions WHERE token_hash = $1 FOR UPDATE`,
		tokenHash))
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	if sess.RevokedAt.Valid || !sess.ExpiresAt.After(time.Now()) {
		_ = tx.Rollback(ctx)
		return nil, ErrNotFound
	}
	return &SessionLease{tx: tx, Sess: sess}, nil
}

// RevokeSelf 在租约事务内撤销“当前会话自身”。
//
// 必须走租约事务而非新开事务：当前行已被本租约 FOR UPDATE 锁定，
// 另开事务会自锁到 lock_timeout。撤销随 Finalize 一起原子提交，
// 因此“本请求处理完成”与“当前会话已撤销”是同一个提交点。
func (l *SessionLease) RevokeSelf(ctx context.Context, reason string) error {
	if _, err := l.tx.Exec(ctx,
		`UPDATE sessions SET revoked_at = now(), revoked_reason = $2 WHERE id = $1`,
		l.Sess.ID, reason); err != nil {
		return mapErr(err)
	}
	l.revoked = true
	l.Sess.RevokedAt = sql.NullTime{Time: time.Now(), Valid: true}
	l.Sess.RevokedReason = sql.NullString{String: reason, Valid: true}
	return nil
}

// RevokeOthers 在租约事务内撤销同一成员同一租户下“除当前会话外”的全部活跃会话。
//
// 复用当前请求的事务（当前会话行已锁），其余目标行按 id 排序后逐行 FOR UPDATE
// 再更新：排序让并发的批量撤销/单个撤销之间形成一致加锁顺序，配合 lock_timeout
// 与死锁检测，竞争时返回 ErrLockBusy 由上层转 503，客户端可安全重试。
// 返回本次新撤销的会话数。
func (l *SessionLease) RevokeOthers(ctx context.Context, reason string) (int, error) {
	n, err := revokeActiveSessionsTx(ctx, l.tx,
		l.Sess.TenantID, l.Sess.MemberID, &l.Sess.ID, reason)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Revoked 报告本请求是否已在租约内撤销自身。
func (l *SessionLease) Revoked() bool { return l.revoked }

// Finalize 结束请求：正常路径刷新最近活动并提交；
// 若请求内已撤销自身，则直接提交（不再刷新活动，避免撤销行看起来仍活跃）。
func (l *SessionLease) Finalize(ctx context.Context, lastIP string) error {
	if l.revoked {
		return l.tx.Commit(ctx)
	}
	if _, err := l.tx.Exec(ctx,
		`UPDATE sessions SET last_seen_at = now(), last_ip = $2 WHERE id = $1`,
		l.Sess.ID, lastIP); err != nil {
		_ = l.tx.Rollback(ctx)
		return err
	}
	return l.tx.Commit(ctx)
}

// Rollback 放弃租约（错误/未授权路径），释放行锁。
func (l *SessionLease) Rollback(ctx context.Context) { _ = l.tx.Rollback(ctx) }

// RevokeResult 描述一次撤销的结果（供接口幂等地构造响应）。
type RevokeResult struct {
	// Revoked 为 true 表示本次调用实际写入了 revoked_at；
	// false 表示会话此前已撤销（幂等重放）。
	Revoked bool
	// Exists 为 false 表示当前租户/成员下没有这条会话。
	// 跨租户、跨成员与不存在返回完全一致的结果，杜绝枚举。
	Exists bool
	Reason string
}

// RevokeMemberSession 撤销指定成员在指定租户下的某台设备会话。
//
// 在独立事务里按 id 锁住行：与受保护请求的租约锁互斥，从而把
// “撤销某会话”与“该会话上的受保护操作”线性化，二者不会交叉成功。
func (s *Store) RevokeMemberSession(ctx context.Context,
	tenantID, memberID, sessionID uuid.UUID, reason string) (RevokeResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RevokeResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		"SELECT set_config('lock_timeout', $1, true)",
		fmt.Sprintf("%dms", sessionLockTimeout.Milliseconds())); err != nil {
		return RevokeResult{}, err
	}
	sess, err := scanSession(tx.QueryRow(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE id = $1 FOR UPDATE`, sessionID))
	if errors.Is(err, ErrNotFound) {
		// 未知 id / 跨租户 / 跨成员：不区分，统一“不存在”。
		return RevokeResult{Exists: false}, tx.Commit(ctx)
	}
	if err != nil {
		return RevokeResult{}, err
	}
	if sess.TenantID != tenantID || sess.MemberID != memberID {
		return RevokeResult{Exists: false}, nil
	}
	res := RevokeResult{Exists: true, Reason: reason}
	if sess.RevokedAt.Valid {
		// 已撤销：稳定幂等，回传既有撤销原因。
		res.Revoked = false
		if sess.RevokedReason.Valid {
			res.Reason = sess.RevokedReason.String
		}
		return res, tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE sessions SET revoked_at = now(), revoked_reason = $2 WHERE id = $1`,
		sessionID, reason); err != nil {
		return RevokeResult{}, err
	}
	res.Revoked = true
	return res, tx.Commit(ctx)
}

// revokeActiveSessionsTx 在给定事务内按 id 排序锁定并撤销全部活跃会话，
// except 非空时跳过该会话。加锁顺序固定（id ASC）以避免并发批量撤销死锁。
// 返回新撤销的行数。
func revokeActiveSessionsTx(ctx context.Context, tx pgx.Tx,
	tenantID, memberID uuid.UUID, except *uuid.UUID, reason string) (int, error) {
	rows, err := tx.Query(ctx,
		`SELECT id FROM sessions
		 WHERE tenant_id = $1 AND member_id = $2 AND revoked_at IS NULL AND expires_at > now()
		 ORDER BY id FOR UPDATE`,
		tenantID, memberID)
	if err != nil {
		return 0, mapErr(err)
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		if except != nil && id == *except {
			continue
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	rows.Close()
	for _, id := range ids {
		if _, err := tx.Exec(ctx,
			`UPDATE sessions SET revoked_at = now(), revoked_reason = $2 WHERE id = $1`,
			id, reason); err != nil {
			return 0, mapErr(err)
		}
	}
	return len(ids), nil
}

// MemberSessions 返回成员在当前租户下未过期的全部会话（含已撤销的），
// 最近活跃在前。不返回 token_hash —— 列表永远不暴露可用于登录的材料。
func (s *Store) MemberSessions(ctx context.Context,
	tenantID, memberID uuid.UUID) ([]models.Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+sessionColumns+`
		 FROM sessions
		 WHERE tenant_id = $1 AND member_id = $2 AND expires_at > now()
		 ORDER BY last_seen_at DESC, created_at DESC`,
		tenantID, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sess)
	}
	return out, rows.Err()
}

// DeleteExpiredSessions 物理删除过期会话行（定时清理由 cmd/server 调用）。
func (s *Store) DeleteExpiredSessions(ctx context.Context, before time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1`, before)
	return err
}

// ---------- link sessions ----------

// CreateLinkSession 建立待完成的关联会话。
func (s *Store) CreateLinkSession(ctx context.Context, ls *models.LinkSession, ttl time.Duration) error {
	ls.ExpiresAt = time.Now().Add(ttl)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO link_sessions
		 (token, tenant_id, anchor_member_id, session_id, target_idp_id,
		  a_issuer, a_subject, a_auth_time, status, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9)`,
		ls.Token, ls.TenantID, ls.AnchorMemberID, ls.SessionID, ls.TargetIDPID,
		ls.AIssuer, ls.ASubject, nullableTime(ls.AAuthTime), ls.ExpiresAt)
	return err
}

func (s *Store) LinkSession(ctx context.Context, token string) (*models.LinkSession, error) {
	var ls models.LinkSession
	var aAuth, bAuth sql.NullTime
	err := s.pool.QueryRow(ctx,
		`SELECT token, tenant_id, anchor_member_id, session_id, target_idp_id,
		        a_issuer, a_subject, a_auth_time,
		        b_issuer, b_subject, b_email, b_auth_time, b_idp_id, b_state,
		        status, expires_at
		 FROM link_sessions WHERE token = $1`, token,
	).Scan(&ls.Token, &ls.TenantID, &ls.AnchorMemberID, &ls.SessionID,
		&ls.TargetIDPID, &ls.AIssuer, &ls.ASubject, &aAuth,
		&ls.BIssuer, &ls.BSubject, &ls.BEmail, &bAuth, &ls.BIDPID, &ls.BState,
		&ls.Status, &ls.ExpiresAt)
	if err != nil {
		return nil, mapErr(err)
	}
	ls.AAuthTime = aAuth
	ls.BAuthTime = bAuth
	return &ls, nil
}

// AttachLinkLegB 在 leg B 回调通过校验后，原子地写入 B 的身份与本次重新认证时间。
// 只有 pending 会话、且当前 b_state 与回调 state 一致时才允许写入，重放返回 ErrConflict。
func (s *Store) AttachLinkLegB(ctx context.Context, token, state, issuer, subject, email string,
	authTime time.Time, idpID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE link_sessions
		 SET b_issuer = $1, b_subject = $2, b_email = $3, b_auth_time = $4, b_idp_id = $5,
		     b_state = ''
		 WHERE token = $6 AND status = 'pending' AND b_state = $7
		   AND b_subject = '' AND expires_at > now()`,
		issuer, subject, email, authTime, idpID, token, state)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// SetLinkLegBState 记录 leg B 待消费的 state（绑定在关联会话上，回调必须与之一致）。
func (s *Store) SetLinkLegBState(ctx context.Context, token, state string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE link_sessions SET b_state = $1
		 WHERE token = $2 AND status = 'pending' AND b_state = '' AND expires_at > now()`,
		state, token)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// CompleteLink 在单个事务里完成关联，全部冲突检查与写入原子发生。
//
// 检查项：
//  1. 会话仍 pending 且未过期（token 一次性）；
//  2. A、B 两条 leg 都已完成重新认证，且认证时间都在 maxAge 之内；
//  3. A 的 (issuer,subject) 仍然锚定在发起关联的成员上；
//  4. B 不能与 A 是同一个已核实身份；
//  5. B 若已存在：必须属于同一成员（重复提交幂等成功）；属于别人则绑定冲突。
func (s *Store) CompleteLink(ctx context.Context, token string, now time.Time, maxAge time.Duration) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		tenantID, anchorMemberID, sessionID, targetIDPID uuid.UUID
		bIDPID                                           uuid.UUID
		aIssuer, aSubject, bIssuer, bSubject, bEmail     string
		status                                           string
		expiresAt                                        time.Time
		aAuth, bAuth                                     sql.NullTime
	)
	err = tx.QueryRow(ctx,
		`SELECT tenant_id, anchor_member_id, session_id, target_idp_id,
		        a_issuer, a_subject, b_issuer, b_subject, b_email, status, expires_at,
		        a_auth_time, b_auth_time, b_idp_id
		 FROM link_sessions WHERE token = $1 FOR UPDATE`, token,
	).Scan(&tenantID, &anchorMemberID, &sessionID, &targetIDPID,
		&aIssuer, &aSubject, &bIssuer, &bSubject, &bEmail, &status, &expiresAt,
		&aAuth, &bAuth, &bIDPID)
	if err != nil {
		return mapErr(err)
	}
	if status != "pending" {
		return ErrConflict
	}
	if expiresAt.Before(now) {
		_, _ = tx.Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
		_ = tx.Commit(ctx)
		return ErrNotFound
	}
	if !aAuth.Valid || !bAuth.Valid {
		return reauthError("both identities must re-authenticate before linking")
	}
	if now.Sub(aAuth.Time) > maxAge || now.Sub(bAuth.Time) > maxAge {
		return reauthError("one or both identities did not re-authenticate recently")
	}
	if bIDPID != targetIDPID {
		return reauthError("second identity was authenticated at an unexpected provider")
	}

	var aOwner uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT member_id FROM identities
		 WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`,
		tenantID, aIssuer, aSubject,
	).Scan(&aOwner)
	if errors.Is(err, pgx.ErrNoRows) {
		_, _ = tx.Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
		_ = tx.Commit(ctx)
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if aOwner != anchorMemberID {
		_, _ = tx.Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
		_ = tx.Commit(ctx)
		return ErrConflict
	}

	if aIssuer == bIssuer && aSubject == bSubject {
		_, _ = tx.Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
		_ = tx.Commit(ctx)
		return ErrConflict
	}

	var bOwner uuid.UUID
	err = tx.QueryRow(ctx,
		`SELECT member_id FROM identities
		 WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`,
		tenantID, bIssuer, bSubject,
	).Scan(&bOwner)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if _, err := tx.Exec(ctx,
			`INSERT INTO identities(id, tenant_id, member_id, issuer, subject, email, email_verified)
			 VALUES ($1,$2,$3,$4,$5,$6,true)`,
			uuid.New(), tenantID, anchorMemberID, bIssuer, bSubject, bEmail); err != nil {
			return mapErr(err)
		}
	case err != nil:
		return err
	case bOwner != anchorMemberID:
		_, _ = tx.Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
		_ = tx.Commit(ctx)
		return ErrConflict
	default:
		// 已属于同一成员：幂等成功。
	}

	if _, err := tx.Exec(ctx,
		`UPDATE link_sessions SET status='completed', completed_at = now() WHERE token = $1`,
		token); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ConsumeCompletedLink 在成功回调一次性消费已完成的关联会话，随后拒绝重放。
func (s *Store) ConsumeCompletedLink(ctx context.Context, token string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE link_sessions SET status='consumed'
		 WHERE token = $1 AND status = 'completed'`, token)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

// ---------- helpers ----------

func nullableStr(ns models.NullString) any {
	if !ns.Valid {
		return nil
	}
	return ns.String
}

func nullableTime(nt models.NullTime) any {
	if !nt.Valid {
		return nil
	}
	return nt.Time
}

type reauthError string

func (e reauthError) Error() string { return string(e) }

// AsReauth 判断 store 返回的错误是否为“必须重新认证”类。
func AsReauth(err error) (string, bool) {
	var r reauthError
	if errors.As(err, &r) {
		return string(r), true
	}
	return "", false
}
