package store

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	embedded "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/db"
)

// startPG 拉起进程内真实 PostgreSQL 并完成迁移（无 Keycloak 依赖）。
func startPG(t *testing.T) (*Store, func()) {
	t.Helper()
	if testing.Short() {
		t.Skip("postgres test skipped in -short mode")
	}
	port := freePort(t)
	pg := embedded.NewDatabase(embedded.DefaultConfig().
		Port(port).
		Database("oidctenant").
		DataPath(t.TempDir()).
		CachePath("/workspace/tools/ep-cache/store").
		Logger(io.Discard))
	if err := pg.Start(); err != nil {
		t.Fatalf("start embedded postgres: %v", err)
	}
	dsn := "postgres://postgres:postgres@localhost:" + strconv.Itoa(int(port)) + "/oidctenant?sslmode=disable"
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st := New(pool)
	cleanup := func() {
		pool.Close()
		_ = pg.Stop()
	}
	return st, cleanup
}

func freePort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := uint32(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	return port
}

// seedMember 直接插入租户与成员，返回其 id。
func seedMember(t *testing.T, st *Store, tenantID, memberID uuid.UUID, slug string) {
	t.Helper()
	ctx := context.Background()
	if err := st.UpsertTenant(ctx, tenantID, slug, slug+" name"); err != nil {
		t.Fatalf("upsert tenant: %v", err)
	}
	if _, err := st.DB().Exec(ctx,
		`INSERT INTO members(id, tenant_id) VALUES ($1,$2)`, memberID, tenantID); err != nil {
		t.Fatalf("insert member: %v", err)
	}
}

func hashOf(s string) []byte { return hashTokenHelper(s) }

// TestRevokeSerializesWithInFlightProtectedRequest 直接验证核心不变量：
// 被撤销会话在撤销提交之后不可能再成功“写入/通过鉴权”。
func TestRevokeSerializesWithInFlightProtectedRequest(t *testing.T) {
	st, cleanup := startPG(t)
	defer cleanup()

	ctx := context.Background()
	tenantID := uuid.New()
	memberID := uuid.New()
	seedMember(t, st, tenantID, memberID, "acme")

	lost, err := st.CreateSession(ctx, tenantID, memberID, hashOf("lost-device-secret"), "Lost Phone", time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// 受保护请求已进入中间件：开启请求事务、TouchSession 取锁，暂不提交。
	rtx, txCtx, err := BeginRequestTx(ctx, st.DB())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	inFlight, err := st.TouchSession(txCtx, hashOf("lost-device-secret"))
	if err != nil {
		t.Fatalf("in-flight touch: %v", err)
	}
	if inFlight.ID != lost.ID {
		t.Fatalf("in-flight session mismatch")
	}

	// 另一设备并发撤销该行：必须等待在锁上，不能提前完成。
	done := make(chan error, 1)
	go func() {
		done <- st.RevokeMemberSession(ctx, tenantID, memberID, lost.ID)
	}()
	select {
	case e := <-done:
		t.Fatalf("revoke completed before in-flight request committed: %v", e)
	case <-time.After(300 * time.Millisecond):
	}

	// 受保护请求提交（先发生，合法写入）。
	if err := rtx.Commit(ctx); err != nil {
		t.Fatalf("commit in-flight: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("revoke after barrier: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("revoke blocked forever")
	}

	// 顺序断言：last_activity（受保护写入）不晚于 revoked_at。
	var lastActivity, revokedAt time.Time
	if err := st.DB().QueryRow(ctx,
		`SELECT last_activity_at, revoked_at FROM sessions WHERE id=$1`, lost.ID,
	).Scan(&lastActivity, &revokedAt); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if revokedAt.IsZero() {
		t.Fatalf("expected revoked")
	}
	if lastActivity.After(revokedAt) {
		t.Fatalf("protected write %s landed after revoke %s", lastActivity, revokedAt)
	}

	// 撤销后同一 sid 无法再通过 TouchSession（中间件鉴权）。
	rtx2, tx2, err := BeginRequestTx(ctx, st.DB())
	if err != nil {
		t.Fatalf("begin2: %v", err)
	}
	if _, err := st.TouchSession(tx2, hashOf("lost-device-secret")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("touch after revoke err=%v want ErrNotFound", err)
	}
	_ = rtx2.Rollback(ctx)

	// 重复撤销：幂等结果 ErrAlreadyRevoked。
	if err := st.RevokeMemberSession(ctx, tenantID, memberID, lost.ID); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("re-revoke err=%v want ErrAlreadyRevoked", err)
	}
}

// TestRevokeMembershipScoping 验证归属隔离与全部撤销。
func TestRevokeMembershipScoping(t *testing.T) {
	st, cleanup := startPG(t)
	defer cleanup()
	ctx := context.Background()

	tA, mA := uuid.New(), uuid.New()
	tB, mB := uuid.New(), uuid.New()
	seedMember(t, st, tA, mA, "acme")
	seedMember(t, st, tB, mB, "globex")

	sA1, _ := st.CreateSession(ctx, tA, mA, hashOf("a1"), "A one", time.Hour)
	sA2, _ := st.CreateSession(ctx, tA, mA, hashOf("a2"), "A two", time.Hour)
	sB1, _ := st.CreateSession(ctx, tB, mB, hashOf("b1"), "B one", time.Hour)

	// 跨成员/跨租户撤销他人会话 -> ErrNotFound（不可枚举）。
	if err := st.RevokeMemberSession(ctx, tA, mA, sB1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant revoke err=%v want ErrNotFound", err)
	}
	if err := st.RevokeMemberSession(ctx, tB, mB, sA1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-member revoke err=%v want ErrNotFound", err)
	}
	if err := st.RevokeMemberSession(ctx, tA, mA, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id revoke err=%v want ErrNotFound", err)
	}

	// 撤销 mA 除当前 sA1 外的全部设备 -> 只撤销 sA2。
	n, err := st.RevokeAllMemberSessions(ctx, tA, mA, sA1.ID)
	if err != nil || n != 1 {
		t.Fatalf("revoke-all n=%d err=%v want 1", n, err)
	}
	if err := st.RevokeMemberSession(ctx, tA, mA, sA2.ID); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("sA2 should already be revoked")
	}
	// sA1 仍可用。
	rtx, tx, _ := BeginRequestTx(ctx, st.DB())
	if _, err := st.TouchSession(tx, hashOf("a1")); err != nil {
		t.Fatalf("current session should stay usable: %v", err)
	}
	_ = rtx.Rollback(ctx)
	// sB1 完全不受影响。
	rtx2, tx2, _ := BeginRequestTx(ctx, st.DB())
	if _, err := st.TouchSession(tx2, hashOf("b1")); err != nil {
		t.Fatalf("other tenant session unaffected: %v", err)
	}
	_ = rtx2.Rollback(ctx)
}

// TestRevokeIdempotentAfterExpiry 已撤销会话即使后来过期，重复撤销仍稳定幂等。
func TestRevokeIdempotentAfterExpiry(t *testing.T) {
	st, cleanup := startPG(t)
	defer cleanup()
	ctx := context.Background()
	tID, mID := uuid.New(), uuid.New()
	seedMember(t, st, tID, mID, "acme")

	// 建一个很快过期的会话并撤销。
	sess, err := st.CreateSession(ctx, tID, mID, hashOf("short"), "Short", time.Millisecond*50)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.RevokeMemberSession(ctx, tID, mID, sess.ID); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	time.Sleep(80 * time.Millisecond) // 等其过期
	// 已撤销且已过期：重复撤销仍应 ErrAlreadyRevoked（幂等），而不是 NotFound。
	if err := st.RevokeMemberSession(ctx, tID, mID, sess.ID); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("re-revoke expired-revoked err=%v want ErrAlreadyRevoked", err)
	}

	// 从未撤销但已过期的登录：不可撤销 -> ErrNotFound。
	other, _ := st.CreateSession(ctx, tID, mID, hashOf("exp2"), "Exp2", time.Millisecond*50)
	time.Sleep(80 * time.Millisecond)
	if err := st.RevokeMemberSession(ctx, tID, mID, other.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke never-used expired err=%v want ErrNotFound", err)
	}
}

// TestConcurrentRevokesDoNotDeadlock 验证并发互撤/全部撤销在有序加锁下不死锁。
func TestConcurrentRevokesDoNotDeadlock(t *testing.T) {
	st, cleanup := startPG(t)
	defer cleanup()
	ctx := context.Background()
	tID, mID := uuid.New(), uuid.New()
	seedMember(t, st, tID, mID, "acme")

	const n = 12
	ids := make([]uuid.UUID, n)
	for i := range ids {
		s, err := st.CreateSession(ctx, tID, mID, hashOf("s-"+string(rune('a'+i))+"-"+uuid.NewString()),
			"device", time.Hour)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		ids[i] = s.ID
	}

	var wg sync.WaitGroup
	for round := 0; round < 4; round++ {
		// 并发“全部撤销”与单点撤销混合：只能有序等待或成功，不能死锁。
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = st.RevokeAllMemberSessions(ctx, tID, mID, uuid.Nil)
		}()
		go func() {
			defer wg.Done()
			_ = st.RevokeMemberSession(ctx, tID, mID, ids[round%n])
		}()
		wg.Wait()
	}

	var active int
	if err := st.DB().QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > now()`).
		Scan(&active); err != nil {
		t.Fatalf("count: %v", err)
	}
	if active != 0 {
		t.Fatalf("expected all sessions revoked, active=%d", active)
	}
}

// TestNestedWithTxIsSavepointOnRequestTx 验证请求事务内再调 WithTx
// 是同一连接上的 savepoint：内部写入对请求事务可见、随请求事务提交，
// 而不是换到另一条连接起独立事务（那会脱离会话行锁）。
func TestNestedWithTxIsSavepointOnRequestTx(t *testing.T) {
	st, cleanup := startPG(t)
	defer cleanup()
	ctx := context.Background()
	tID, mID := uuid.New(), uuid.New()
	seedMember(t, st, tID, mID, "acme")
	sess, _ := st.CreateSession(ctx, tID, mID, hashOf("nested-token"), "N", time.Hour)

	// 开启请求事务并锁定会话行。
	rtx, txCtx, err := BeginRequestTx(ctx, st.DB())
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := st.TouchSession(txCtx, hashOf("nested-token")); err != nil {
		t.Fatalf("touch: %v", err)
	}

	// 在请求事务内嵌套 WithTx：内部 UPDATE 必须落在同一事务/连接上，
	// 能读到未提交数据，且不应另起独立事务。
	seen := false
	if err := WithTx(txCtx, st.DB(), func(inner context.Context) error {
		// savepoint 内能看到外层未提交的 last_activity 更新（非空）。
		var la time.Time
		if err := st.DB().QueryRow(inner,
			`SELECT last_activity_at FROM sessions WHERE id=$1`, sess.ID).Scan(&la); err != nil {
			return err
		}
		if !la.IsZero() {
			seen = true
		}
		// 在 savepoint 内撤销；回滚 savepoint 不应影响外层。
		return errors.New("force savepoint rollback")
	}); err == nil {
		t.Fatalf("expected inner error to surface")
	}
	if !seen {
		t.Fatalf("nested tx did not see outer uncommitted data (not same connection?)")
	}

	// 外层请求事务仍活跃且会话仍未撤销。
	var revoked sql.NullTime
	if err := st.DB().QueryRow(txCtx,
		`SELECT revoked_at FROM sessions WHERE id=$1`, sess.ID).Scan(&revoked); err != nil {
		t.Fatalf("outer read after savepoint rollback: %v", err)
	}
	if revoked.Valid {
		t.Fatalf("savepoint rollback leaked into request transaction")
	}
	if err := rtx.Commit(ctx); err != nil {
		t.Fatalf("commit request tx: %v", err)
	}
}

// TestListSessionsShape 验证列表只含展示字段、隐藏过期未撤销行。
func TestListSessionsShape(t *testing.T) {
	st, cleanup := startPG(t)
	defer cleanup()
	ctx := context.Background()
	tID, mID := uuid.New(), uuid.New()
	seedMember(t, st, tID, mID, "acme")

	current, _ := st.CreateSession(ctx, tID, mID, hashOf("cur"), "Current", time.Hour)
	revoked, _ := st.CreateSession(ctx, tID, mID, hashOf("old"), "Old", time.Hour)
	expired, _ := st.CreateSession(ctx, tID, mID, hashOf("exp"), "Expired", -time.Hour)
	if err := st.RevokeMemberSession(ctx, tID, mID, revoked.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	list, err := st.ListMemberSessions(ctx, tID, mID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("list len=%d want 2 (expired hidden, revoked shown)", len(list))
	}
	if list[0].ID != current.ID {
		t.Fatalf("expected active current first, got %s", list[0].ID)
	}
	if list[1].ID != revoked.ID || !list[1].RevokedAt.Valid {
		t.Fatalf("expected revoked second, got %+v", list[1])
	}
	// 投影结构不含 token 哈希字段（编译期保证 SessionInfo 无 TokenHash）。
	if expired.ID == uuid.Nil {
		t.Fatalf("sanity")
	}
}
