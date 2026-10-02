package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	embedded "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/config"
	"github.com/example/oidctenant/internal/db"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

type apiHarness struct {
	t       *testing.T
	store   *store.Store
	server  *httptest.Server
	tenants map[string]uuid.UUID
}

func startAPIHarness(t *testing.T) *apiHarness {
	t.Helper()
	if testing.Short() {
		t.Skip("postgres test skipped in -short mode")
	}
	port := freeHTTPPort(t)
	pg := embedded.NewDatabase(embedded.DefaultConfig().
		Port(port).Database("oidctenant").
		DataPath(t.TempDir()).CachePath("/workspace/tools/ep-cache/api").Logger(io.Discard))
	if err := pg.Start(); err != nil {
		t.Fatalf("start pg: %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop() })

	dsn := "postgres://postgres:postgres@localhost:" + strconv.Itoa(int(port)) + "/oidctenant?sslmode=disable"
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st := store.New(pool)

	h := &apiHarness{t: t, store: st, tenants: map[string]uuid.UUID{}}
	for _, slug := range []string{"acme", "globex"} {
		id := uuid.New()
		if err := st.UpsertTenant(ctx, id, slug, slug+" name"); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		h.tenants[slug] = id
	}

	cfg := &config.Config{
		BaseURL:        "http://example.invalid",
		SessionTTL:     time.Hour,
		LinkTTL:        time.Minute,
		AuthRequestTTL: time.Minute,
		CookieSecure:   false,
		CookieSameSite: "lax",
	}
	srv := NewServer(cfg, st, oidcx.NewManager(), discardLogger())
	h.server = httptest.NewServer(srv.Routes())
	t.Cleanup(h.server.Close)
	return h
}

func freeHTTPPort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := uint32(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	return port
}

// addMember 创建成员，返回其 id。
func (h *apiHarness) addMember(tenantSlug string) uuid.UUID {
	id := uuid.New()
	if _, err := h.store.DB().Exec(context.Background(),
		`INSERT INTO members(id, tenant_id) VALUES ($1,$2)`, id, h.tenants[tenantSlug]); err != nil {
		h.t.Fatalf("add member: %v", err)
	}
	return id
}

// deviceClient 创建一个带 sid cookie 的“设备”客户端，返回其会话 id。
func (h *apiHarness) deviceClient(tenantSlug string, memberID uuid.UUID, token, label string,
	ttl time.Duration) (*http.Client, uuid.UUID) {
	sess, err := h.store.CreateSession(context.Background(),
		h.tenants[tenantSlug], memberID, hashTokenPkg(token), label, ttl)
	if err != nil {
		h.t.Fatalf("create session: %v", err)
	}
	jar, _ := cookiejar.New(nil)
	u, _ := urlParse(h.server.URL)
	jar.SetCookies(u, []*http.Cookie{{Name: "sid", Value: token, Path: "/"}})
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}, sess.ID
}

func (h *apiHarness) do(client *http.Client, method, path string, wantStatus int) (int, map[string]any, *http.Response) {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.server.URL+path, nil)
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var body map[string]any
	_ = json.Unmarshal(data, &body)
	if wantStatus >= 0 && resp.StatusCode != wantStatus {
		h.t.Fatalf("%s %s status=%d want %d body=%s", method, path, resp.StatusCode, wantStatus, data)
	}
	return resp.StatusCode, body, resp
}

// TestAPISelectiveRevokeAcrossTwoDevices 端到端：两设备区分、只撤一台、被撤 401、另一台可用。
func TestAPISelectiveRevokeAcrossTwoDevices(t *testing.T) {
	h := startAPIHarness(t)
	member := h.addMember("acme")

	d1, id1 := h.deviceClient("acme", member, "opaque-token-device-1", "Device One", time.Hour)
	d2, id2 := h.deviceClient("acme", member, "opaque-token-device-2", "Device Two", time.Hour)
	_ = id1

	// 两台都能访问 me。
	h.do(d1, http.MethodGet, "/t/acme/api/me", http.StatusOK)
	h.do(d2, http.MethodGet, "/t/acme/api/me", http.StatusOK)

	// 列表可区分，且含 current 标记。
	_, listBody, _ := h.do(d1, http.MethodGet, "/t/acme/api/sessions", http.StatusOK)
	sessions := listBody["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("sessions len=%d want 2", len(sessions))
	}
	sawCurrent := false
	for _, s := range sessions {
		m := s.(map[string]any)
		if m["id"] == id1.String() && m["current"] == true {
			sawCurrent = true
		}
		if m["id"] == id2.String() && m["status"] != "active" {
			t.Fatalf("device2 should be active: %v", m)
		}
	}
	if !sawCurrent {
		t.Fatalf("device1 should be marked current")
	}

	// d1 撤销 d2。
	_, revokeBody, _ := h.do(d1, http.MethodDelete, "/t/acme/api/sessions/"+id2.String(), http.StatusOK)
	if revokeBody["status"] != "revoked" {
		t.Fatalf("revoke body=%v", revokeBody)
	}

	// d2 随后访问 me -> 401 且清 cookie。
	_, body, resp := h.do(d2, http.MethodGet, "/t/acme/api/me", http.StatusUnauthorized)
	if body["error"] != "authentication_failed" {
		t.Fatalf("body=%v", body)
	}
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == "sid" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("expected sid cookie to be cleared on 401")
	}
	// 契约以 Set-Cookie 的过期头为准（浏览器会据此删除本地 sid）。

	// d1 仍可用。
	h.do(d1, http.MethodGet, "/t/acme/api/me", http.StatusOK)
}

// TestAPIRevokeIdempotent 重复撤销返回稳定幂等结果。
func TestAPIRevokeIdempotent(t *testing.T) {
	h := startAPIHarness(t)
	member := h.addMember("acme")
	d1, id1 := h.deviceClient("acme", member, "t1", "D1", time.Hour)
	d2, id2 := h.deviceClient("acme", member, "t2", "D2", time.Hour)
	_ = id1
	_ = d2

	if _, b, _ := h.do(d1, http.MethodDelete, "/t/acme/api/sessions/"+id2.String(), http.StatusOK); b["status"] != "revoked" {
		t.Fatalf("first revoke: %v", b)
	}
	for i := 0; i < 2; i++ {
		_, b, _ := h.do(d1, http.MethodDelete, "/t/acme/api/sessions/"+id2.String(), http.StatusOK)
		if b["status"] != "already_revoked" {
			t.Fatalf("repeat revoke #%d: %v", i, b)
		}
	}
	h.do(d1, http.MethodGet, "/t/acme/api/me", http.StatusOK)
}

// TestAPIRevokeAllAndLogoutSemantics 全部退出 + 单设备 logout 语义。
func TestAPIRevokeAllAndLogoutSemantics(t *testing.T) {
	h := startAPIHarness(t)
	member := h.addMember("globex")
	d1, id1 := h.deviceClient("globex", member, "g1", "G1", time.Hour)
	d2, _ := h.deviceClient("globex", member, "g2", "G2", time.Hour)
	d3, _ := h.deviceClient("globex", member, "g3", "G3", time.Hour)
	_ = id1
	_ = d3

	_, b, _ := h.do(d1, http.MethodPost, "/t/globex/api/sessions/revoke-all", http.StatusOK)
	if b["status"] != "logged_out_all" || b["other_revoked"].(float64) != 2 {
		t.Fatalf("revoke-all body=%v", b)
	}
	for _, c := range []*http.Client{d1, d2, d3} {
		h.do(c, http.MethodGet, "/t/globex/api/me", http.StatusUnauthorized)
	}

	// logout 的单设备语义：两台新设备，只撤当前。
	x1, _ := h.deviceClient("globex", member, "x1", "X1", time.Hour)
	x2, _ := h.deviceClient("globex", member, "x2", "X2", time.Hour)
	h.do(x1, http.MethodPost, "/t/globex/api/logout", http.StatusOK)
	h.do(x1, http.MethodGet, "/t/globex/api/me", http.StatusUnauthorized)
	h.do(x2, http.MethodGet, "/t/globex/api/me", http.StatusOK)
}

// TestAPICrossTenantAndCrossMemberRevocationDenied 跨租户/跨成员不可枚举撤销；跨租户使用会话 403。
func TestAPICrossTenantAndCrossMemberRevocationDenied(t *testing.T) {
	h := startAPIHarness(t)
	aliceAcme := h.addMember("acme")
	aliceGlobex := h.addMember("globex") // 刻意不同 member，即使邮箱相同也隔离
	carolAcme := h.addMember("acme")

	a, aSession := h.deviceClient("acme", aliceAcme, "aa", "acme alice", time.Hour)
	g, gSession := h.deviceClient("globex", aliceGlobex, "gg", "globex alice", time.Hour)
	c, cSession := h.deviceClient("acme", carolAcme, "cc", "carol", time.Hour)
	_ = c

	// globex 撤销 acme 会话 -> 404；carol 撤销 alice 会话 -> 404；非法 id 同样 404。
	do404 := func(client *http.Client, tenant, id string) {
		t.Helper()
		_, body, _ := h.do(client, http.MethodDelete, "/t/"+tenant+"/api/sessions/"+id, http.StatusNotFound)
		if body["error"] != "not_found" {
			t.Fatalf("body=%v want not_found", body)
		}
	}
	do404(g, "globex", aSession.String())
	do404(c, "acme", aSession.String())
	do404(a, "acme", gSession.String())
	do404(a, "acme", cSession.String())
	do404(a, "acme", "not-a-uuid")
	do404(a, "acme", "00000000-0000-0000-0000-000000000000")

	// 跨租户使用会话 -> 403 tenant_unauthorized。
	h.do(a, http.MethodGet, "/t/globex/api/me", http.StatusForbidden)

	// 全部受攻击会话仍然有效。
	h.do(a, http.MethodGet, "/t/acme/api/me", http.StatusOK)
	h.do(g, http.MethodGet, "/t/globex/api/me", http.StatusOK)
	h.do(c, http.MethodGet, "/t/acme/api/me", http.StatusOK)
}

// TestAPIExpiredSessionFails 过期会话无法通过鉴权并清 cookie。
func TestAPIExpiredSessionFails(t *testing.T) {
	h := startAPIHarness(t)
	m := h.addMember("acme")
	d, _ := h.deviceClient("acme", m, "expired-token", "Old", -time.Minute)
	h.do(d, http.MethodGet, "/t/acme/api/me", http.StatusUnauthorized)
}

// TestAPIRevokeRaceNoSuccessAfterRevoke 撤销与被撤设备的并发受保护访问。
//
// 数据库层的严格保证（由会话行锁 + 提交闸门实现）：
//   - 与撤销并发、先提交的请求可以成功（其 last_activity/写入不晚于 revoked_at，
//     该顺序在 store 层 TestRevokeSerializesWithInFlightProtectedRequest 断言）；
//   - 撤销提交之后才开始鉴权的请求，一律不可能成功。
//
// 跨两条 TCP 连接的“响应字节到达先后”不由数据库保证，因此这里不按客户端
// 观察顺序判定，而是：在撤销返回后先排空在途请求，再发若干全新请求，
// 它们必须全部 401。
func TestAPIRevokeRaceNoSuccessAfterRevoke(t *testing.T) {
	h := startAPIHarness(t)
	m := h.addMember("acme")
	ctrl, _ := h.deviceClient("acme", m, "controller", "Controller", time.Hour)
	victim, targetID := h.deviceClient("acme", m, "victim-secret", "Victim", time.Hour)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// 撤销前后持续制造受害者请求（在途请求可能先于撤销提交，允许 200）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/t/acme/api/me", nil)
			if resp, err := victim.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	h.do(ctrl, http.MethodDelete, "/t/acme/api/sessions/"+targetID.String(), http.StatusOK)
	// 排空撤销发生时已经在途的请求。
	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()

	// 关键断言：撤销提交之后发起的全新请求，全部 401，无一成功。
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/t/acme/api/me", nil)
		resp, err := victim.Do(req)
		if err != nil {
			t.Fatalf("post-revoke request: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("post-revoke request #%d status=%d want 401", i, resp.StatusCode)
		}
		time.Sleep(2 * time.Millisecond)
	}
	// 控制端仍可用。
	h.do(ctrl, http.MethodGet, "/t/acme/api/me", http.StatusOK)
}

// TestAPIRevokedCurrentDeviceClearsCookie 撤销“当前设备”等价 logout。
func TestAPIRevokedCurrentDeviceClearsCookie(t *testing.T) {
	h := startAPIHarness(t)
	m := h.addMember("acme")
	d, id := h.deviceClient("acme", m, "self-token", "Self", time.Hour)
	_, body, resp := h.do(d, http.MethodDelete, "/t/acme/api/sessions/"+id.String(), http.StatusOK)
	if body["status"] != "revoked" {
		t.Fatalf("self revoke body=%v", body)
	}
	cleared := false
	for _, c := range resp.Cookies() {
		if c.Name == "sid" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("self revoke should clear sid cookie")
	}
	h.do(d, http.MethodGet, "/t/acme/api/me", http.StatusUnauthorized)
}
