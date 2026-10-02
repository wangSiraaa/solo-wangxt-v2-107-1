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
	// ErrAlreadyRevoked 表示目标会话此前已被撤销（撤销接口的幂等分支）。
	ErrAlreadyRevoked = errors.New("store: session already revoked")
)

// querier 是连接池与事务的公共查询面。
// 会话中间件把“整个请求期间持有的会话行锁”事务放进 context，
// 之后所有 store 调用都自动落在该事务内，从而让
// “撤销会话”与“受保护接口的写入”在数据库层面严格串行化。
type querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

type txCtxKey struct{}

// WithTx 在 fn 期间让 store 调用复用 ctx 中的事务；没有则新启一个。
// ctx 中已是 pgx.Tx 时，Begin 会建立 savepoint，故可安全嵌套。
func WithTx(ctx context.Context, pool querier, fn func(context.Context) error) error {
	if ctxTx, ok := ctx.Value(txCtxKey{}).(pgx.Tx); ok {
		// 已在请求事务内：必须在该事务（同一连接）上 Begin 以建立 savepoint，
		// 绝不能对传入的 pool 另起事务 —— 那会换到别的连接、脱离请求事务与行锁。
		// savepoint 的 Rollback 只撤销其内部改动，Commit 只释放 savepoint，
		// 请求事务的锁与提交点不受影响。
		sp, err := ctxTx.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = sp.Rollback(ctx) }()
		if err := fn(context.WithValue(ctx, txCtxKey{}, sp)); err != nil {
			return err
		}
		return sp.Commit(ctx)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(context.WithValue(ctx, txCtxKey{}, tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RequestTx 是鉴权中间件持有的“整个请求生命周期”事务。
// handler 内的全部 store 调用（q 从 ctx 取事务）都落在该事务里，
// 因而 TouchSession 取得的会话行排他锁一直保持到请求结束。
type RequestTx struct {
	tx pgx.Tx
}

// BeginRequestTx 在连接池上开启一个新的请求事务。
func BeginRequestTx(ctx context.Context, pool *pgxpool.Pool) (*RequestTx, context.Context, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, ctx, err
	}
	ctx = context.WithValue(ctx, txCtxKey{}, tx)
	return &RequestTx{tx: tx}, ctx, nil
}

// Commit 提交请求事务（释放会话行锁）。
func (r *RequestTx) Commit(ctx context.Context) error { return r.tx.Commit(ctx) }

// Rollback 回滚请求事务；已提交时回滚是无害 no-op。
func (r *RequestTx) Rollback(ctx context.Context) error { return r.tx.Rollback(ctx) }

func q(ctx context.Context, pool querier) querier {
	if tx, ok := ctx.Value(txCtxKey{}).(pgx.Tx); ok {
		return tx
	}
	return pool
}

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

// isSerializationFailure 判断是否为死锁/序列化失败等“安全重试”错误。
func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "40P01", // deadlock_detected
			"40001", // serialization_failure
			"55P03": // lock_not_available
			return true
		}
	}
	return false
}

// ---------- tenant / provider ----------

func (s *Store) TenantBySlug(ctx context.Context, slug string) (*models.Tenant, error) {
	var t models.Tenant
	err := q(ctx, s.pool).QueryRow(ctx,
		`SELECT id, slug, name, created_at FROM tenants WHERE slug = $1`, slug,
	).Scan(&t.ID, &t.Slug, &t.Name, &t.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &t, nil
}

func (s *Store) TenantByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	var t models.Tenant
	err := q(ctx, s.pool).QueryRow(ctx,
		`SELECT id, slug, name, created_at FROM tenants WHERE id = $1`, id,
	).Scan(&t.ID, &t.Slug, &t.Name, &t.CreatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &t, nil
}

// UpsertTenant 创建或更新租户。
func (s *Store) UpsertTenant(ctx context.Context, id uuid.UUID, slug, name string) error {
	_, err := q(ctx, s.pool).Exec(ctx,
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

func (s *Store) provider(ctx context.Context, query string, args ...any) (*models.Provider, error) {
	var p models.Provider
	err := q(ctx, s.pool).QueryRow(ctx, query, args...).Scan(
		&p.ID, &p.TenantID, &p.Issuer, &p.ClientID, &p.ClientSecret, &p.RedirectURIs,
		&p.AuthTimeMaxAge, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &p, nil
}

// UpsertProvider 创建或更新租户的一个 issuer 配置。
func (s *Store) UpsertProvider(ctx context.Context, p *models.Provider) error {
	_, err := q(ctx, s.pool).Exec(ctx,
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
	_, err := q(ctx, s.pool).Exec(ctx,
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
	var ar *models.AuthRequest
	err := WithTx(ctx, s.pool, func(ctx context.Context) error {
		var got models.AuthRequest
		err := q(ctx, s.pool).QueryRow(ctx,
			`SELECT state, kind, tenant_id, idp_id, nonce, pkce_verifier, return_to,
			        link_token, session_id, created_at
			 FROM auth_requests WHERE state = $1 AND consumed_at IS NULL
			 FOR UPDATE`,
			state,
		).Scan(&got.State, &got.Kind, &got.TenantID, &got.IDPID, &got.Nonce,
			&got.PKCEVerifier, &got.ReturnTo, &got.LinkToken, &got.SessionID, &got.CreatedAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConsumed
			}
			return err
		}
		if _, err := q(ctx, s.pool).Exec(ctx,
			`UPDATE auth_requests SET consumed_at = now() WHERE state = $1`, state); err != nil {
			return err
		}
		ar = &got
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ar, nil
}

// DeleteExpiredAuthRequests 清理过期未消费的 state 行。
func (s *Store) DeleteExpiredAuthRequests(ctx context.Context, before time.Time) error {
	_, err := q(ctx, s.pool).Exec(ctx,
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
	var result *LoginMemberResult
	err := WithTx(ctx, s.pool, func(ctx context.Context) error {
		// pg_advisory_xact_lock 以 issuer|subject 的哈希作为 key，事务结束自动释放。
		if _, err := q(ctx, s.pool).Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended($1 || '|' || $2, 0))`,
			in.Issuer, in.Subject); err != nil {
			return err
		}

		created := false
		var identityID, memberID uuid.UUID
		var email string
		var emailVerified bool
		err := q(ctx, s.pool).QueryRow(ctx,
			`SELECT id, member_id, email, email_verified FROM identities
			 WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`,
			in.TenantID, in.Issuer, in.Subject,
		).Scan(&identityID, &memberID, &email, &emailVerified)
		switch {
		case err == nil:
			// 已有身份：刷新展示字段，复用既有成员。绝不按邮箱合并账号。
			if _, err := q(ctx, s.pool).Exec(ctx,
				`UPDATE identities SET email = $1, email_verified = $2, updated_at = now()
				 WHERE id = $3`, in.Email, in.EmailVerified, identityID); err != nil {
				return err
			}
			if in.DisplayName != "" {
				_, _ = q(ctx, s.pool).Exec(ctx,
					`UPDATE members SET display_name = $1 WHERE id = $2 AND display_name = ''`,
					in.DisplayName, memberID)
			}
		case errors.Is(err, pgx.ErrNoRows):
			// 全新身份：创建成员 + 身份，二者在同一事务里。
			created = true
			memberID = uuid.New()
			if _, err := q(ctx, s.pool).Exec(ctx,
				`INSERT INTO members(id, tenant_id, display_name) VALUES ($1,$2,$3)`,
				memberID, in.TenantID, in.DisplayName); err != nil {
				return mapErr(err)
			}
			if _, err := q(ctx, s.pool).Exec(ctx,
				`INSERT INTO identities(id, tenant_id, member_id, issuer, subject, email, email_verified)
				 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				uuid.New(), in.TenantID, memberID, in.Issuer, in.Subject,
				in.Email, in.EmailVerified); err != nil {
				return mapErr(err)
			}
		default:
			return err
		}

		var m models.Member
		if err := q(ctx, s.pool).QueryRow(ctx,
			`SELECT id, tenant_id, display_name, created_at FROM members
			 WHERE id = $1 AND tenant_id = $2`, memberID, in.TenantID,
		).Scan(&m.ID, &m.TenantID, &m.DisplayName, &m.CreatedAt); err != nil {
			return err
		}
		result = &LoginMemberResult{Member: &m, Created: created}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) Member(ctx context.Context, tenantID, memberID uuid.UUID) (*models.Member, error) {
	var m models.Member
	err := q(ctx, s.pool).QueryRow(ctx,
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
	rows, err := q(ctx, s.pool).Query(ctx,
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
	err := q(ctx, s.pool).QueryRow(ctx,
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

// ---------- sessions（设备会话管理） ----------

const sessionColumns = `id, tenant_id, member_id, token_hash, display_label,
	created_at, last_activity_at, expires_at, revoked_at`

func scanSession(row pgx.Row) (*models.Session, error) {
	var sess models.Session
	err := row.Scan(&sess.ID, &sess.TenantID, &sess.MemberID, &sess.TokenHash,
		&sess.DisplayLabel, &sess.CreatedAt, &sess.LastActivityAt,
		&sess.ExpiresAt, &sess.RevokedAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &sess, nil
}

// CreateSession 建立新设备会话。displayLabel 必须是脱敏后的展示标签，
// 调用方使用 auth.DeviceLabel 生成，绝不允许写入令牌内容。
func (s *Store) CreateSession(ctx context.Context, tenantID, memberID uuid.UUID,
	tokenHash []byte, displayLabel string, ttl time.Duration) (*models.Session, error) {
	id := uuid.New()
	now := time.Now()
	exp := now.Add(ttl)
	sess, err := scanSession(q(ctx, s.pool).QueryRow(ctx,
		`INSERT INTO sessions
		 (id, tenant_id, member_id, token_hash, display_label, created_at, last_activity_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$6,$7)
		 RETURNING `+sessionColumns,
		id, tenantID, memberID, tokenHash, displayLabel, now, exp))
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// TouchSession 是鉴权中间件的核心：
//
//	在请求事务内对 sid 对应的会话行做条件 UPDATE ... RETURNING。
//	该语句会一直持有行排他锁直到请求事务提交：
//	  - 行不存在 / 已撤销 / 已过期 -> ErrNotFound（认证失败）；
//	  - 撤销语句是对同一行的 UPDATE，必须等待本事务结束，
//	    因而“撤销先于受保护写入提交”或反之，二者严格串行，
//	    被撤销会话不可能在撤销之后再成功写入任何受保护接口；
//	  - 最近活动时间在同一把锁内刷新，读数天然一致。
func (s *Store) TouchSession(ctx context.Context, tokenHash []byte) (*models.Session, error) {
	sess, err := scanSession(q(ctx, s.pool).QueryRow(ctx,
		`UPDATE sessions SET last_activity_at = now()
		 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
		 RETURNING `+sessionColumns,
		tokenHash))
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// SessionInfo 是设备列表/撤销接口使用的会话投影，刻意不含 token_hash。
type SessionInfo struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	MemberID       uuid.UUID
	DisplayLabel   string
	CreatedAt      time.Time
	LastActivityAt time.Time
	ExpiresAt      time.Time
	RevokedAt      sql.NullTime
}

const sessionInfoColumns = `id, tenant_id, member_id, display_label,
	created_at, last_activity_at, expires_at, revoked_at`

// ListMemberSessions 列出成员在指定租户的设备会话：
// 活跃（未撤销且未过期）在前，已撤销在后；过期且未撤销的行不展示。
// 结果只含展示字段，不含 sid 哈希。
func (s *Store) ListMemberSessions(ctx context.Context, tenantID, memberID uuid.UUID) ([]SessionInfo, error) {
	rows, err := q(ctx, s.pool).Query(ctx,
		`SELECT `+sessionInfoColumns+`
		 FROM sessions
		 WHERE tenant_id = $1 AND member_id = $2
		   AND (revoked_at IS NOT NULL OR expires_at > now())
		 ORDER BY (revoked_at IS NULL) DESC, last_activity_at DESC
		 LIMIT 200`,
		tenantID, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionInfo
	for rows.Next() {
		var si SessionInfo
		if err := rows.Scan(&si.ID, &si.TenantID, &si.MemberID, &si.DisplayLabel,
			&si.CreatedAt, &si.LastActivityAt, &si.ExpiresAt, &si.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, si)
	}
	return out, rows.Err()
}

// RevokeCurrentSession 在“请求自身的鉴权事务”内撤销当前会话。
// 与 TouchSession 持有的是同一行/同一事务，撤销随请求一起提交，
// logout 语义因此与受保护接口写入严格互斥。
func (s *Store) RevokeCurrentSession(ctx context.Context, id uuid.UUID) error {
	tag, err := q(ctx, s.pool).Exec(ctx,
		`UPDATE sessions SET revoked_at = now()
		 WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// 行已撤销或已过期：对 logout 来说都是幂等成功。
		return nil
	}
	return nil
}

// revokeTxRunner 在独立事务（不参与请求事务）内执行撤销，
// 并在死锁/序列化失败时做有限次退避重试 —— 撤销全部是幂等语句，重试安全。
//
// 退避而不是立即重试：两个互相撤销对方设备的并发请求之间，PostgreSQL 会挑选
// 一个死锁牺牲者；牺牲者短暂等待后重试，待对方请求事务提交即可完成，
// 避免把可恢复的锁竞争直接上抛为 500。
func (s *Store) revokeTxRunner(ctx context.Context, attempts int,
	fn func(context.Context, querier) (int64, error)) (int64, error) {
	var total int64
	for attempt := 0; attempt < attempts; attempt++ {
		total = 0
		err := func() error {
			tx, err := s.pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback(ctx) }()
			n, err := fn(ctx, tx)
			if err != nil {
				return err
			}
			total = n
			return tx.Commit(ctx)
		}()
		switch {
		case err == nil:
			return total, nil
		case isSerializationFailure(err) && attempt < attempts-1:
			select {
			case <-ctx.Done():
				return total, ctx.Err()
			case <-time.After(time.Duration(10*(attempt+1)) * time.Millisecond):
			}
			continue
		default:
			return total, err
		}
	}
	return total, nil
}

// RevokeMemberSession 撤销成员自己在指定租户的指定设备会话。
//
// 归属条件 (tenant_id, member_id) 直接写进查询，跨租户/跨成员的 id 命中 0 行
// -> ErrNotFound，响应无法区分“不存在/不属于我”。
//
// 结果语义（幂等）：
//   - 活跃未撤销：撤销成功（nil）；
//   - 已撤销（即使之后已过期）：ErrAlreadyRevoked —— 重复撤销必须稳定成功；
//   - 从未撤销但已过期（过期登录）或行不存在：ErrNotFound。
//
// 在独立事务里对该行 FOR UPDATE 后撤销；并发撤销之间按主键有序，避免死锁。
func (s *Store) RevokeMemberSession(ctx context.Context, tenantID, memberID, sessionID uuid.UUID) error {
	_, err := s.revokeTxRunner(ctx, 4, func(ctx context.Context, tx querier) (int64, error) {
		var revoked sql.NullTime
		var expiresAt time.Time
		err := tx.QueryRow(ctx,
			`SELECT revoked_at, expires_at FROM sessions
			 WHERE id = $1 AND tenant_id = $2 AND member_id = $3
			 FOR UPDATE`,
			sessionID, tenantID, memberID).Scan(&revoked, &expiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNotFound
		}
		if err != nil {
			return 0, err
		}
		if revoked.Valid {
			// 已撤销（含之后过期）：幂等结果，不区分“刚刚/早已”。
			return 0, ErrAlreadyRevoked
		}
		if !expiresAt.After(time.Now()) {
			// 从未撤销但已过期的登录：不可再撤销，按不存在处理。
			return 0, ErrNotFound
		}
		tag, err := tx.Exec(ctx,
			`UPDATE sessions SET revoked_at = now()
			 WHERE id = $1 AND revoked_at IS NULL`, sessionID)
		if err != nil {
			return 0, err
		}
		if tag.RowsAffected() == 0 {
			// 极端竞态：锁窗口内被别处抢先撤销 —— 同样是幂等成功。
			return 0, ErrAlreadyRevoked
		}
		return 1, nil
	})
	return err
}

// RevokeAllMemberSessions 撤销成员在该租户的全部其他设备会话。
//
// 行按 id 有序锁定（ORDER BY id），任意两个并发撤销之间加锁顺序一致，
// 从根本上消除互相等待导致的死锁。
// 排除当前请求正在持有的会话行（该行由外层请求事务管理）。
// 返回实际新撤销的行数（此前已撤销的不重复计数）。
func (s *Store) RevokeAllMemberSessions(ctx context.Context, tenantID, memberID,
	currentSessionID uuid.UUID) (int64, error) {
	return s.revokeTxRunner(ctx, 4, func(ctx context.Context, tx querier) (int64, error) {
		rows, err := tx.Query(ctx,
			`SELECT id FROM sessions
			 WHERE tenant_id = $1 AND member_id = $2
			   AND revoked_at IS NULL AND expires_at > now()
			   AND id <> $3
			 ORDER BY id
			 FOR UPDATE`,
			tenantID, memberID, currentSessionID)
		if err != nil {
			return 0, err
		}
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return 0, err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			return 0, err
		}
		rows.Close()
		if len(ids) == 0 {
			return 0, nil
		}
		tag, err := tx.Exec(ctx,
			`UPDATE sessions SET revoked_at = now()
			 WHERE tenant_id = $1 AND member_id = $2 AND revoked_at IS NULL
			   AND expires_at > now() AND id = ANY($3)`,
			tenantID, memberID, ids)
		if err != nil {
			return 0, err
		}
		return tag.RowsAffected(), nil
	})
}

// DeleteExpiredSessions 物理清理“从未撤销却已过期”的会话行，控制设备表增长。
//
// 已撤销行刻意保留：它们承载幂等的“已撤销”状态与设备列表的 revoked 展示，
// 删除会让重复撤销退化为 404。这类行的增长与登录次数同级，可由独立的
// 数据保留策略（如保留 N 天）另行处理，本服务不做隐式删除。
func (s *Store) DeleteExpiredSessions(ctx context.Context, before time.Time) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM sessions WHERE expires_at < $1 AND revoked_at IS NULL`, before)
	return err
}

// ---------- link sessions ----------

// CreateLinkSession 建立待完成的关联会话。
func (s *Store) CreateLinkSession(ctx context.Context, ls *models.LinkSession, ttl time.Duration) error {
	ls.ExpiresAt = time.Now().Add(ttl)
	_, err := q(ctx, s.pool).Exec(ctx,
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
	err := q(ctx, s.pool).QueryRow(ctx,
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
	tag, err := q(ctx, s.pool).Exec(ctx,
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
	tag, err := q(ctx, s.pool).Exec(ctx,
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
	return WithTx(ctx, s.pool, func(ctx context.Context) error {
		var (
			tenantID, anchorMemberID, sessionID, targetIDPID uuid.UUID
			bIDPID                                           uuid.UUID
			aIssuer, aSubject, bIssuer, bSubject, bEmail     string
			status                                           string
			expiresAt                                        time.Time
			aAuth, bAuth                                     sql.NullTime
		)
		err := q(ctx, s.pool).QueryRow(ctx,
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
			_, _ = q(ctx, s.pool).Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
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
		err = q(ctx, s.pool).QueryRow(ctx,
			`SELECT member_id FROM identities
			 WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`,
			tenantID, aIssuer, aSubject,
		).Scan(&aOwner)
		if errors.Is(err, pgx.ErrNoRows) {
			_, _ = q(ctx, s.pool).Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
			return ErrConflict
		}
		if err != nil {
			return err
		}
		if aOwner != anchorMemberID {
			_, _ = q(ctx, s.pool).Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
			return ErrConflict
		}

		if aIssuer == bIssuer && aSubject == bSubject {
			_, _ = q(ctx, s.pool).Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
			return ErrConflict
		}

		var bOwner uuid.UUID
		err = q(ctx, s.pool).QueryRow(ctx,
			`SELECT member_id FROM identities
			 WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`,
			tenantID, bIssuer, bSubject,
		).Scan(&bOwner)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if _, err := q(ctx, s.pool).Exec(ctx,
				`INSERT INTO identities(id, tenant_id, member_id, issuer, subject, email, email_verified)
				 VALUES ($1,$2,$3,$4,$5,$6,true)`,
				uuid.New(), tenantID, anchorMemberID, bIssuer, bSubject, bEmail); err != nil {
				return mapErr(err)
			}
		case err != nil:
			return err
		case bOwner != anchorMemberID:
			_, _ = q(ctx, s.pool).Exec(ctx, `UPDATE link_sessions SET status='consumed' WHERE token=$1`, token)
			return ErrConflict
		default:
			// 已属于同一成员：幂等成功。
		}

		if _, err := q(ctx, s.pool).Exec(ctx,
			`UPDATE link_sessions SET status='completed', completed_at = now() WHERE token = $1`,
			token); err != nil {
			return err
		}
		return nil
	})
}

// ConsumeCompletedLink 在成功回调一次性消费已完成的关联会话，随后拒绝重放。
func (s *Store) ConsumeCompletedLink(ctx context.Context, token string) error {
	tag, err := q(ctx, s.pool).Exec(ctx,
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
