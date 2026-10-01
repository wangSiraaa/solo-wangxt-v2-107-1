// Package store 封装所有 PostgreSQL 访问（pgx 原生驱动）。
package store

import (
	"context"
	"database/sql"
	"errors"
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
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
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

// ---------- sessions ----------

func (s *Store) CreateSession(ctx context.Context, tenantID, memberID uuid.UUID, tokenHash []byte, ttl time.Duration) (*models.Session, error) {
	id := uuid.New()
	now := time.Now()
	exp := now.Add(ttl)
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO sessions(id, tenant_id, member_id, token_hash, created_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		id, tenantID, memberID, tokenHash, now, exp); err != nil {
		return nil, err
	}
	return &models.Session{ID: id, TenantID: tenantID, MemberID: memberID,
		TokenHash: tokenHash, ExpiresAt: exp}, nil
}

func (s *Store) SessionByHash(ctx context.Context, tokenHash []byte) (*models.Session, error) {
	var sess models.Session
	err := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, member_id, token_hash, expires_at FROM sessions
		 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()`,
		tokenHash,
	).Scan(&sess.ID, &sess.TenantID, &sess.MemberID, &sess.TokenHash, &sess.ExpiresAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &sess, nil
}

func (s *Store) RevokeSession(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
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
