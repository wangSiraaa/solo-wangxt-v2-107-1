package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	embedded "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/api"
	sec "github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/config"
	"github.com/example/oidctenant/internal/db"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

// 本文件覆盖“设备会话管理”的全部验收点。
//
// 这些用例不需要 Keycloak：直接在数据库中建立不透明 sid 会话，
// 把精力集中在“列出/区分/撤销/并发竞争/跨租户隔离/日志不泄漏 sid”本身。
// 需要真实 OIDC 登录端到端覆盖的路径由既有 browser_* 用例承担。

const (
	sessTenantAcme   = "acme"
	sessTenantGlobex = "globex"
)

// 固定 UUID，便于 seed 与断言引用（与 harness_test.go 中的租户常量一致）。
var (
	aliceAcmeMemberID = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	globexMemberID    = uuid.MustParse("11111111-1111-1111-1111-111111111112")
	carolMemberID     = uuid.MustParse("11111111-1111-1111-1111-111111111113")
)

type sessionHarness struct {
	t       *testing.T
	st      *store.Store
	baseURL string
	logBuf  *safeBuffer
	pg      *embedded.EmbeddedPostgres
	httpSrv *http.Server
}

// startSessionHarness 在真实 embedded Postgres + 真实 HTTP 服务上搭一个无 Keycloak 环境：
// 两个租户（acme/globex）；acme 有 alice/carol 两名成员，globex 有 alice，
// 两个 alice 刻意同邮箱 alice@example.com。
func startSessionHarness(t *testing.T) *sessionHarness {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}

	pgPort := freeTCPPort(t)
	appPort := freeTCPPort(t)

	pg := embedded.NewDatabase(embedded.DefaultConfig().
		Port(pgPort).
		Database("sessions").
		DataPath(t.TempDir()).
		CachePath("/workspace/tools/ep-cache").
		Logger(io.Discard))
	if err := pg.Start(); err != nil {
		t.Fatalf("start embedded postgres: %v", err)
	}

	dsn := formatDSN(pgPort, "sessions")
	ctx := context.Background()
	database, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st := store.New(database)

	seedSessTenant(t, st, tenantAcmeID, sessTenantAcme)
	seedSessTenant(t, st, tenantGlobexID, sessTenantGlobex)
	seedSessMember(t, st, tenantAcmeID, aliceAcmeMemberID,
		uuid.MustParse("21111111-1111-1111-1111-111111111111"),
		"http://idp.example/acme", "sub-acme-alice", "alice@example.com")
	seedSessMember(t, st, tenantAcmeID, carolMemberID,
		uuid.MustParse("21111111-1111-1111-1111-111111111113"),
		"http://idp.example/acme", "sub-acme-carol", "carol@example.com")
	seedSessMember(t, st, tenantGlobexID, globexMemberID,
		uuid.MustParse("21111111-1111-1111-1111-111111111112"),
		"http://idp.example/globex", "sub-globex-alice", "alice@example.com")

	baseURL := fmt.Sprintf("http://localhost:%d", appPort)
	cfg := &config.Config{
		DatabaseURL:    dsn,
		BaseURL:        baseURL,
		Addr:           fmt.Sprintf("127.0.0.1:%d", appPort),
		SessionTTL:     time.Hour,
		LinkTTL:        10 * time.Minute,
		AuthRequestTTL: 10 * time.Minute,
		CookieSecure:   false,
		CookieSameSite: "lax",
	}
	logBuf := &safeBuffer{}
	logger := log.New(io.MultiWriter(logBuf, os.Stdout), "[sess-api] ",
		log.LstdFlags|log.Lmicroseconds)
	httpSrv := &http.Server{
		Addr:    cfg.Addr,
		Handler: api.NewServer(cfg, st, oidcx.NewManager(), logger).Routes(),
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = httpSrv.Serve(ln) }()
	waitReady(t, baseURL+"/healthz")

	h := &sessionHarness{
		t: t, st: st, baseURL: baseURL, logBuf: logBuf, pg: pg, httpSrv: httpSrv,
	}
	t.Cleanup(func() {
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shCtx)
		database.Close()
		_ = pg.Stop()
	})
	return h
}

type safeBuffer struct {
	mu sync.Mutex
	sb bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

// device 表示一台“设备浏览器”：持有不透明 sid（不放进 cookiejar，
// 以便精确控制在撤销后是否仍携带旧 Cookie 发起请求）。
type device struct {
	name     string
	slug     string
	tenantID uuid.UUID
	memberID uuid.UUID
	sid      string
}

func (h *sessionHarness) createDevice(name, slug string, tenantID, memberID uuid.UUID,
	ua string) *device {
	h.t.Helper()
	token, err := sec.SessionToken()
	if err != nil {
		h.t.Fatalf("session token: %v", err)
	}
	if _, err := h.st.CreateSession(context.Background(), store.CreateSessionParams{
		TenantID:    tenantID,
		MemberID:    memberID,
		TokenHash:   sec.HashToken(token),
		TTL:         time.Hour,
		DeviceLabel: ua,
		LastIP:      "127.0.0.1",
	}); err != nil {
		h.t.Fatalf("create session: %v", err)
	}
	return &device{name: name, slug: slug, tenantID: tenantID, memberID: memberID, sid: token}
}

func (d *device) ua() string { return "test-" + d.name + "/1.0" }

func (h *sessionHarness) apiURL(slug, path string) string {
	return h.baseURL + "/t/" + slug + path
}

// doRaw 携带指定设备的 sid Cookie 发请求（显式 Cookie 头，不用 jar）。
func (h *sessionHarness) doRaw(method, raw string, d *device, body any) *http.Response {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, raw, reader)
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if d != nil {
		req.Header.Set("Cookie", "sid="+d.sid)
		req.Header.Set("User-Agent", d.ua())
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Helper()
		h.t.Fatalf("%s %s: %v", method, raw, err)
	}
	return resp
}

func (h *sessionHarness) mustStatus(resp *http.Response, want int) map[string]any {
	h.t.Helper()
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != want {
		h.t.Fatalf("status=%d want %d url=%s body=%s", resp.StatusCode, want,
			resp.Request.URL.Path, string(data))
	}
	if len(data) == 0 {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		h.t.Fatalf("decode %q: %v", string(data), err)
	}
	return out
}

func (h *sessionHarness) meOK(d *device) map[string]any {
	return h.mustStatus(h.doRaw(http.MethodGet, h.apiURL(d.slug, "/api/me"), d, nil), http.StatusOK)
}

func (h *sessionHarness) meStatus(d *device) int {
	resp := h.doRaw(http.MethodGet, h.apiURL(d.slug, "/api/me"), d, nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	code := resp.StatusCode
	_ = resp.Body.Close()
	return code
}

// listOrdered 返回该设备所见的会话视图列表（最近活跃在前）。
func (h *sessionHarness) listOrdered(d *device) []map[string]any {
	out := h.mustStatus(h.doRaw(http.MethodGet, h.apiURL(d.slug, "/api/sessions"), d, nil),
		http.StatusOK)
	var res []map[string]any
	for _, it := range out["sessions"].([]any) {
		res = append(res, it.(map[string]any))
	}
	return res
}

func (h *sessionHarness) findIDByLabel(viewer *device, label string) string {
	h.t.Helper()
	for _, v := range h.listOrdered(viewer) {
		if v["label"] == label {
			return v["id"].(string)
		}
	}
	h.t.Fatalf("session label %q not found for viewer in tenant %s", label, viewer.slug)
	return ""
}

// sessionIDBySid 直接从库中按 sid 哈希查 UUID（测试辅助，绝不经过 API 暴露）。
func (h *sessionHarness) sessionIDBySid(sid string) uuid.UUID {
	h.t.Helper()
	var id uuid.UUID
	if err := h.st.DB().QueryRow(context.Background(),
		`SELECT id FROM sessions WHERE token_hash=$1`, sec.HashToken(sid)).Scan(&id); err != nil {
		h.t.Fatalf("lookup session id by sid: %v", err)
	}
	return id
}

func (h *sessionHarness) revoke(viewer *device, targetID string, body any) (*http.Response, map[string]any) {
	resp := h.doRaw(http.MethodPost,
		h.apiURL(viewer.slug, "/api/sessions/"+targetID+"/revoke"), viewer, body)
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return resp, m
}

// ---------- 用例 ----------

// TestDeviceSessions_TwoDevicesDistinguishableAndRevokeOne
// 验收：同一成员两台设备登录后可区分，仅撤销其中一台；
// 被撤销设备随后访问 me 得到 401，另一台仍 200；
// 列表/任何响应不泄漏原始 sid。
func TestDeviceSessions_TwoDevicesDistinguishableAndRevokeOne(t *testing.T) {
	h := startSessionHarness(t)

	devA := h.createDevice("laptop", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "Chrome on Laptop")
	devB := h.createDevice("phone", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "Safari on Phone")

	if h.meOK(devA)["member_id"] != aliceAcmeMemberID.String() {
		t.Fatalf("devA member mismatch")
	}
	if h.meOK(devB)["member_id"] != aliceAcmeMemberID.String() {
		t.Fatalf("devB member mismatch")
	}

	// 列表可区分两台设备：标签不同、current 标记只命中本设备。
	viewsA := h.listOrdered(devA)
	if len(viewsA) != 2 {
		t.Fatalf("sessions listed=%d want 2", len(viewsA))
	}
	var bID string
	for _, v := range viewsA {
		switch v["label"] {
		case "Chrome on Laptop":
			if v["current"] != true {
				t.Fatalf("laptop view current=%v want true", v["current"])
			}
		case "Safari on Phone":
			bID = v["id"].(string)
			if v["current"] != false || v["status"] != "active" {
				t.Fatalf("phone view=%v want current=false status=active", v)
			}
		default:
			t.Fatalf("unexpected label %v", v["label"])
		}
	}
	if bID == "" {
		t.Fatalf("phone session not found in listing")
	}
	// 列表条目是 UUID，绝不能等于原始 sid。
	for _, v := range viewsA {
		if v["id"] == devA.sid || v["id"] == devB.sid {
			t.Fatalf("listing leaked raw sid: %v", v["id"])
		}
	}

	// 仅撤销设备 B（设备 A 发起，撤销“其他设备”）。
	resp, rev := h.revoke(devA, bID, nil)
	if resp.StatusCode != http.StatusOK || rev["revoked"] != true || rev["current"] != false {
		t.Fatalf("revoke B status=%d body=%v want 200 revoked=true current=false",
			resp.StatusCode, rev)
	}

	// B 随后访问受保护接口：认证失败（401），且响应要求清除失效 Cookie。
	respB := h.doRaw(http.MethodGet, h.apiURL(sessTenantAcme, "/api/me"), devB, nil)
	bbody := readBody(t, respB)
	if respB.StatusCode != http.StatusUnauthorized || bbody["error"] != "authentication_failed" {
		t.Fatalf("revoked B me status=%d body=%v want 401 authentication_failed",
			respB.StatusCode, bbody)
	}
	if !cookieCleared(respB) {
		t.Fatalf("revoked session response must clear sid cookie")
	}

	// A 仍可正常使用；列表中 B 已 revoked、A 仍 active。
	h.meOK(devA)
	views := h.listOrdered(devA)
	for _, v := range views {
		want := "active"
		if v["id"] == bID {
			want = "revoked"
		}
		if v["status"] != want {
			t.Fatalf("session %s status=%v want %s", v["id"], v["status"], want)
		}
	}

	// B 的旧 sid 不能“复活”：重试仍是一致的 401。
	if code := h.meStatus(devB); code != http.StatusUnauthorized {
		t.Fatalf("revoked B retry status=%d want 401", code)
	}

	// 日志中不得出现任何原始 sid（设备标签里也不可能含 sid）。
	logs := h.logBuf.String()
	if strings.Contains(logs, devA.sid) || strings.Contains(logs, devB.sid) {
		t.Fatalf("server logs leaked raw session token")
	}
}

// TestDeviceSessions_RevokeIdempotent 验收：重复撤销同一会话结果稳定幂等。
func TestDeviceSessions_RevokeIdempotent(t *testing.T) {
	h := startSessionHarness(t)
	devA := h.createDevice("laptop", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-laptop")
	devB := h.createDevice("phone", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-phone")
	bID := h.findIDByLabel(devA, "ua-phone")

	resp, first := h.revoke(devA, bID, nil)
	if resp.StatusCode != http.StatusOK || first["revoked"] != true {
		t.Fatalf("first revoke status=%d body=%v want 200 revoked=true", resp.StatusCode, first)
	}
	// 第二次：200 稳定，revoked=false 表示此前已撤销。
	resp, second := h.revoke(devA, bID, nil)
	if resp.StatusCode != http.StatusOK || second["revoked"] != false || second["current"] != false {
		t.Fatalf("second revoke status=%d body=%v want 200 revoked=false current=false",
			resp.StatusCode, second)
	}
	// 第三次：结果完全一致。
	resp, third := h.revoke(devA, bID, nil)
	if resp.StatusCode != http.StatusOK || third["revoked"] != false {
		t.Fatalf("third revoke status=%d body=%v want 200 revoked=false", resp.StatusCode, third)
	}

	if code := h.meStatus(devB); code != http.StatusUnauthorized {
		t.Fatalf("revoked B status=%d want 401", code)
	}
	h.meOK(devA)
}

// TestDeviceSessions_RevokeCurrentClearsCookie 验收：撤销当前会话（自己这台设备）
// 时清理 Cookie，随后访问一致地 401，其他设备不受影响。
func TestDeviceSessions_RevokeCurrentClearsCookie(t *testing.T) {
	h := startSessionHarness(t)
	devA := h.createDevice("laptop", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-laptop")
	devB := h.createDevice("phone", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-phone")
	aID := h.findIDByLabel(devA, "ua-laptop")

	resp := h.doRaw(http.MethodPost,
		h.apiURL(sessTenantAcme, "/api/sessions/"+aID+"/revoke"), devA, nil)
	body := h.mustStatus(resp, http.StatusOK)
	if body["current"] != true || body["revoked"] != true {
		t.Fatalf("revoke current body=%v", body)
	}
	if !cookieCleared(resp) {
		t.Fatalf("revoke-current must clear sid cookie")
	}
	if code := h.meStatus(devA); code != http.StatusUnauthorized {
		t.Fatalf("self-revoked A status=%d want 401", code)
	}
	h.meOK(devB) // 其他设备不受影响。
}

// TestDeviceSessions_RevokeAllAndExcludeCurrent 验收全部设备退出与“下线其他设备”。
func TestDeviceSessions_RevokeAllAndExcludeCurrent(t *testing.T) {
	h := startSessionHarness(t)
	devA := h.createDevice("laptop", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-laptop")
	devB := h.createDevice("phone", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-phone")
	devC := h.createDevice("tablet", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-tablet")

	// include_current=false：撤销其他设备，当前会话保持登录、不清理 Cookie。
	resp := h.doRaw(http.MethodPost, h.apiURL(sessTenantAcme, "/api/sessions/revoke-all"),
		devA, map[string]any{"include_current": false})
	out := h.mustStatus(resp, http.StatusOK)
	if out["revoked_count"].(float64) != 2 {
		t.Fatalf("revoked_count=%v want 2", out["revoked_count"])
	}
	for _, c := range resp.Cookies() {
		if c.Name == "sid" {
			t.Fatalf("revoke-others must not touch current sid cookie")
		}
	}
	h.meOK(devA)
	if code := h.meStatus(devB); code != http.StatusUnauthorized {
		t.Fatalf("B after revoke-others status=%d want 401", code)
	}
	if code := h.meStatus(devC); code != http.StatusUnauthorized {
		t.Fatalf("C after revoke-others status=%d want 401", code)
	}

	// 新设备 D 登录，随后 include_current=true：全部退出（此刻活跃的只有 A、D）。
	devD := h.createDevice("watch", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-watch")
	resp = h.doRaw(http.MethodPost, h.apiURL(sessTenantAcme, "/api/sessions/revoke-all"),
		devA, map[string]any{"include_current": true})
	all := h.mustStatus(resp, http.StatusOK)
	if all["revoked_count"].(float64) != 2 {
		t.Fatalf("revoke-all count=%v want 2", all["revoked_count"])
	}
	if !cookieCleared(resp) {
		t.Fatalf("revoke-all must clear current sid cookie")
	}
	for i, d := range []*device{devA, devB, devC, devD} {
		if code := h.meStatus(d); code != http.StatusUnauthorized {
			t.Fatalf("device %d after revoke-all status=%d want 401", i, code)
		}
	}

	// 全部已撤销后再来一次 revoke-all：幂等，计数 0，Cookie 仍被清理，结果结构稳定。
	// 注意 A 的 cookie 已失效，因此用一台新登录设备验证“无其他设备可撤销”。
	devE := h.createDevice("netbook", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-netbook")
	resp = h.doRaw(http.MethodPost, h.apiURL(sessTenantAcme, "/api/sessions/revoke-all"),
		devE, map[string]any{"include_current": false})
	again := h.mustStatus(resp, http.StatusOK)
	if again["revoked_count"].(float64) != 0 {
		t.Fatalf("idempotent revoke-others count=%v want 0", again["revoked_count"])
	}
	h.meOK(devE)
}

// TestDeviceSessions_CrossTenantAndCrossMemberCannotEnumerateOrRevoke
// 验收：跨租户同邮箱、另一成员的会话既不能被枚举也不能被撤销。
func TestDeviceSessions_CrossTenantAndCrossMemberCannotEnumerateOrRevoke(t *testing.T) {
	h := startSessionHarness(t)
	devAlice := h.createDevice("alice-laptop", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-alice")
	devCarol := h.createDevice("carol-laptop", sessTenantAcme, tenantAcmeID, carolMemberID, "ua-carol")
	devGlobex := h.createDevice("globex-laptop", sessTenantGlobex, tenantGlobexID, globexMemberID, "ua-globex")

	// alice 的列表只有自己（看不到 carol）。
	if views := h.listOrdered(devAlice); len(views) != 1 {
		t.Fatalf("alice listing=%d want 1 (must not see carol)", len(views))
	}
	if views := h.listOrdered(devGlobex); len(views) != 1 {
		t.Fatalf("globex listing=%d want 1", len(views))
	}

	carolSID := h.findIDByLabel(devCarol, "ua-carol")
	globexSID := h.findIDByLabel(devGlobex, "ua-globex")

	// alice 撤销 carol / globex 的会话：统一 404 not_found（与“不存在”不可区分）。
	for _, target := range []string{carolSID, globexSID, uuid.NewString()} {
		resp, body := h.revoke(devAlice, target, nil)
		if resp.StatusCode != http.StatusNotFound || body["error"] != "not_found" {
			t.Fatalf("cross revoke target=%s status=%d body=%v want 404 not_found",
				target, resp.StatusCode, body)
		}
	}
	// 非法 id 格式是 400（参数形状错误，而非资源存在性）。
	resp, _ := h.revoke(devAlice, "not-a-uuid", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad id status=%d want 400", resp.StatusCode)
	}

	// 被尝试撤销的会话实际仍活跃。
	h.meOK(devCarol)
	h.meOK(devGlobex)

	// globex 的会话 cookie 不能用于访问 acme 租户接口（跨租户 403，沿用既有语义）。
	cross := h.doRaw(http.MethodGet, h.apiURL(sessTenantAcme, "/api/me"), devGlobex, nil)
	if cross.StatusCode != http.StatusForbidden {
		t.Fatalf("globex cookie against acme status=%d want 403", cross.StatusCode)
	}
	_ = cross.Body.Close()
	h.meOK(devAlice)
}

// TestDeviceSessions_SingleDeviceLogoutUnchanged 验收原有单设备 logout 语义：
// 只退出当前设备，其他设备不受影响；Cookie 被清理；旧 cookie 再打 logout 为 401。
func TestDeviceSessions_SingleDeviceLogoutUnchanged(t *testing.T) {
	h := startSessionHarness(t)
	devA := h.createDevice("laptop", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-laptop")
	devB := h.createDevice("phone", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-phone")

	resp := h.doRaw(http.MethodPost, h.apiURL(sessTenantAcme, "/api/logout"), devA, nil)
	body := h.mustStatus(resp, http.StatusOK)
	if body["status"] != "logged_out" {
		t.Fatalf("logout body=%v", body)
	}
	if !cookieCleared(resp) {
		t.Fatalf("logout must clear sid cookie")
	}
	if code := h.meStatus(devA); code != http.StatusUnauthorized {
		t.Fatalf("A after logout status=%d want 401", code)
	}
	again := h.doRaw(http.MethodPost, h.apiURL(sessTenantAcme, "/api/logout"), devA, nil)
	if again.StatusCode != http.StatusUnauthorized {
		t.Fatalf("repeat logout status=%d want 401", again.StatusCode)
	}
	_ = again.Body.Close()
	h.meOK(devB) // 另一设备不受影响。
}

// TestDeviceSessions_RevokeRacesProtectedOperation 验收撤销与受保护操作并发：
// 不会出现“撤销后受保护操作仍成功”。
//
// 真实 Postgres 行锁下的交错：
//  1. 设备 B 的“受保护操作”用 store 获取 FOR UPDATE 租约并保持
//     （等价于请求已通过中间件、正在业务处理中）；
//  2. 设备 A 发起 HTTP 撤销 B；该事务阻塞在 B 的行锁上（pg_locks 可见 tuple 等待）；
//  3. B 在锁保护下完成“受保护写入”（刷新 last_seen_at），严格先于撤销提交；
//  4. B 释放锁 -> 撤销解除阻塞并完成；
//  5. 此后任何携带 B sid 的受保护请求一律 401，A 仍可用。
func TestDeviceSessions_RevokeRacesProtectedOperation(t *testing.T) {
	h := startSessionHarness(t)
	devA := h.createDevice("laptop", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-laptop")
	devB := h.createDevice("phone", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-phone")
	bID := h.findIDByLabel(devA, "ua-phone")

	h.meOK(devB) // 确认 B 活跃。

	// B 的受保护操作开始：获取并持有行锁租约（不提交）。
	lease, err := h.st.AcquireSessionLease(context.Background(), sec.HashToken(devB.sid))
	if err != nil {
		t.Fatalf("B acquire lease: %v", err)
	}

	revokeDone := make(chan int, 1)
	go func() {
		resp := h.doRaw(http.MethodPost,
			h.apiURL(sessTenantAcme, "/api/sessions/"+bID+"/revoke"), devA, nil)
		_, _ = io.Copy(io.Discard, resp.Body)
		code := resp.StatusCode
		_ = resp.Body.Close()
		revokeDone <- code
	}()

	// 撤销必须在等待 B 的行锁，而不是提前成功（这正是“不能撤销后写入”的关键）。
	waitFor(t, func() bool { return h.tupleLockWaiters("sessions") > 0 },
		3*time.Second, "revoke should block on the protected operation's row lock")

	// B 在租约保护下完成受保护写入：撤销此刻不可能已提交。
	if err := lease.Finalize(context.Background(), "10.0.0.9"); err != nil {
		t.Fatalf("B finalize protected op: %v", err)
	}
	select {
	case code := <-revokeDone:
		if code != http.StatusOK {
			t.Fatalf("racing revoke status=%d want 200", code)
		}
	case <-time.After(12 * time.Second):
		t.Fatalf("revoke did not complete after protected operation finished")
	}

	// 撤销完成后：B 立即无法再获取租约/访问受保护接口。
	if _, err := h.st.AcquireSessionLease(context.Background(), sec.HashToken(devB.sid)); err == nil {
		t.Fatalf("B lease acquired after revoke, want failure")
	}
	if code := h.meStatus(devB); code != http.StatusUnauthorized {
		t.Fatalf("B me after revoke status=%d want 401", code)
	}
	h.meOK(devA)

	var revoked, active int
	h.st.DB().QueryRow(context.Background(),
		`SELECT count(*) FROM sessions WHERE id=$1 AND revoked_at IS NOT NULL`,
		h.sessionIDBySid(devB.sid)).Scan(&revoked)
	h.st.DB().QueryRow(context.Background(),
		`SELECT count(*) FROM sessions
		 WHERE member_id=$1 AND revoked_at IS NULL AND expires_at > now()`,
		aliceAcmeMemberID).Scan(&active)
	if revoked != 1 || active != 1 {
		t.Fatalf("post-race state revoked=%d want 1; active=%d want 1", revoked, active)
	}
}

// TestDeviceSessions_ConcurrentRevokeThenProtectedFailsClosed
// 反复制造“在途受保护操作 + 并发撤销”，撤销提交后立刻高并发打受保护接口：
// 所有请求必须 401，无一漏网（fail-closed）。
func TestDeviceSessions_ConcurrentRevokeThenProtectedFailsClosed(t *testing.T) {
	h := startSessionHarness(t)
	devA := h.createDevice("laptop", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-laptop")
	devB := h.createDevice("phone", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-phone")

	const rounds = 30
	for round := 0; round < rounds; round++ {
		bID := h.sessionIDBySid(devB.sid)
		lease, err := h.st.AcquireSessionLease(context.Background(), sec.HashToken(devB.sid))
		if err != nil {
			t.Fatalf("round %d acquire: %v", round, err)
		}
		done := make(chan struct{})
		go func() {
			resp := h.doRaw(http.MethodPost,
				h.apiURL(sessTenantAcme, "/api/sessions/"+bID.String()+"/revoke"), devA, nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			close(done)
		}()
		waitFor(t, func() bool { return h.tupleLockWaiters("sessions") > 0 },
			3*time.Second, fmt.Sprintf("round %d: revoke should wait", round))
		if err := lease.Finalize(context.Background(), "10.0.0.9"); err != nil {
			t.Fatalf("round %d finalize: %v", round, err)
		}
		<-done

		const concurrency = 8
		var wg sync.WaitGroup
		codes := make(chan int, concurrency)
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); codes <- h.meStatus(devB) }()
		}
		wg.Wait()
		close(codes)
		for code := range codes {
			if code != http.StatusUnauthorized {
				t.Fatalf("round %d post-revoke concurrent me status=%d want 401", round, code)
			}
		}

		if round < rounds-1 {
			// 模拟 B 再次登录：新 sid、新行（标签带轮次避免重名歧义）。
			devB = h.createDevice(fmt.Sprintf("phone-%d", round),
				sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-phone")
		}
	}
	h.meOK(devA)
}

// TestDeviceSessions_ProtectedOperationBlocksDuringRevokeUntilDone
// 反向断言：当 B 的受保护操作先持锁时，撤销必须等到操作结束，
// 期间数据库里 B 仍未被撤销（不存在“响应已返回撤销成功但操作尚未完成”的窗口颠倒）。
func TestDeviceSessions_ProtectedOperationBlocksRevokeUntilDone(t *testing.T) {
	h := startSessionHarness(t)
	devA := h.createDevice("laptop", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-laptop")
	devB := h.createDevice("phone", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-phone")
	bID := h.sessionIDBySid(devB.sid)

	lease, err := h.st.AcquireSessionLease(context.Background(), sec.HashToken(devB.sid))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	revokeDone := make(chan struct{})
	go func() {
		resp := h.doRaw(http.MethodPost,
			h.apiURL(sessTenantAcme, "/api/sessions/"+bID.String()+"/revoke"), devA, nil)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		close(revokeDone)
	}()
	waitFor(t, func() bool { return h.tupleLockWaiters("sessions") > 0 },
		3*time.Second, "revoke should wait for in-flight operation")

	// 持锁期间 B 仍活跃；撤销尚未落库。
	if n := h.countRevoked(bID); n != 0 {
		t.Fatalf("revoked visible while protected op in flight: %d", n)
	}
	if err := lease.Finalize(context.Background(), "10.0.0.9"); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	select {
	case <-revokeDone:
	case <-time.After(12 * time.Second):
		t.Fatalf("revoke hung")
	}
	if n := h.countRevoked(bID); n != 1 {
		t.Fatalf("revoked after completion=%d want 1", n)
	}
}

// TestDeviceSessions_RevokedSessionRejectedOnWriteEndpoints
// 验收被撤销设备访问“关联/写入型”受保护接口同样认证失败，而不只是 GET me。
func TestDeviceSessions_RevokedSessionRejectedOnWriteEndpoints(t *testing.T) {
	h := startSessionHarness(t)
	devA := h.createDevice("laptop", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-laptop")
	devB := h.createDevice("phone", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-phone")
	bID := h.findIDByLabel(devA, "ua-phone")

	if resp, _ := h.revoke(devA, bID, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke setup failed: %d", resp.StatusCode)
	}

	// POST /api/links（写入型受保护接口）：401 authentication_failed。
	linkResp := h.doRaw(http.MethodPost, h.apiURL(sessTenantAcme, "/api/links"), devB,
		map[string]string{"issuer": "http://idp.example/globex"})
	lbody := readBody(t, linkResp)
	if linkResp.StatusCode != http.StatusUnauthorized || lbody["error"] != "authentication_failed" {
		t.Fatalf("revoked POST links status=%d body=%v want 401 authentication_failed",
			linkResp.StatusCode, lbody)
	}

	// POST logout / revoke-* 同样在中间件即被拒绝，不会执行任何写入。
	for _, p := range []string{"/api/logout", "/api/sessions/revoke-all",
		"/api/sessions/" + bID + "/revoke"} {
		resp := h.doRaw(http.MethodPost, h.apiURL(sessTenantAcme, p), devB, nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked POST %s status=%d want 401", p, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
	// A 仍正常。
	h.meOK(devA)
}

// TestDeviceSessions_LastSeenUpdates 验收最近活动时间随受保护请求刷新，
// 且展示信息（label/ip）正确落库、不含令牌内容。
func TestDeviceSessions_LastSeenUpdates(t *testing.T) {
	h := startSessionHarness(t)
	devA := h.createDevice("laptop", sessTenantAcme, tenantAcmeID, aliceAcmeMemberID, "ua-laptop")
	id := h.sessionIDBySid(devA.sid)

	var before time.Time
	h.st.DB().QueryRow(context.Background(), `SELECT last_seen_at FROM sessions WHERE id=$1`, id).Scan(&before)
	time.Sleep(20 * time.Millisecond)
	h.meOK(devA)
	var after time.Time
	h.st.DB().QueryRow(context.Background(), `SELECT last_seen_at FROM sessions WHERE id=$1`, id).Scan(&after)
	if !after.After(before) {
		t.Fatalf("last_seen_at not refreshed: before=%v after=%v", before, after)
	}

	var label, lastIP, hash []byte
	var tokenHash []byte
	_ = label
	h.st.DB().QueryRow(context.Background(),
		`SELECT device_label, last_ip, token_hash FROM sessions WHERE id=$1`, id,
	).Scan(&label, &lastIP, &tokenHash)
	if string(label) != "ua-laptop" || string(lastIP) == "" {
		t.Fatalf("label=%q last_ip=%q want label set and ip non-empty", label, lastIP)
	}
	if bytes.Contains(tokenHash, []byte(devA.sid)) {
		t.Fatalf("stored token material must be hash only")
	}
	hash = sec.HashToken(devA.sid)
	if !bytes.Equal(hash, tokenHash) {
		t.Fatalf("stored hash mismatch")
	}
}

// ---------- helpers ----------

func (h *sessionHarness) tupleLockWaiters(table string) int {
	// 等待中的锁在 pg_stat_activity 上表现为 wait_event_type='Lock'
	// （wait_event 为 tuple / transactionid）。等待语句本身就是
	// 针对 sessions 表的 SELECT ... FOR UPDATE / UPDATE，按 query 文本过滤
	// 可精确定位到“撤销事务被受保护操作的行锁挡住”。
	var n int
	err := h.st.DB().QueryRow(context.Background(),
		`SELECT count(*) FROM pg_stat_activity
		 WHERE datname = current_database()
		   AND wait_event_type = 'Lock'
		   AND query ILIKE '%'||$1||'%'`, table).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

func (h *sessionHarness) countRevoked(id uuid.UUID) int {
	var n int
	if err := h.st.DB().QueryRow(context.Background(),
		`SELECT count(*) FROM sessions WHERE id=$1 AND revoked_at IS NOT NULL`, id).Scan(&n); err != nil {
		h.t.Fatalf("count revoked: %v", err)
	}
	return n
}

func cookieCleared(resp *http.Response) bool {
	for _, c := range resp.Cookies() {
		if c.Name != "sid" {
			continue
		}
		if c.MaxAge < 0 {
			return true
		}
		if !c.Expires.IsZero() && c.Expires.Before(time.Now()) {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, cond func() bool, within time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s: %s", within, msg)
}

func seedSessTenant(t *testing.T, st *store.Store, id uuid.UUID, slug string) {
	t.Helper()
	name := strings.ToUpper(slug[:1]) + slug[1:] + " Corp"
	if err := st.UpsertTenant(context.Background(), id, slug, name); err != nil {
		t.Fatalf("upsert tenant: %v", err)
	}
}

func seedSessMember(t *testing.T, st *store.Store,
	tenantID, memberID, identityID uuid.UUID, issuer, subject, email string) {
	t.Helper()
	if _, err := st.DB().Exec(context.Background(),
		`INSERT INTO members(id, tenant_id, display_name) VALUES ($1,$2,$3)
		 ON CONFLICT (id) DO NOTHING`,
		memberID, tenantID, "Seed User"); err != nil {
		t.Fatalf("insert member: %v", err)
	}
	if _, err := st.DB().Exec(context.Background(),
		`INSERT INTO identities(id, tenant_id, member_id, issuer, subject, email, email_verified)
		 VALUES ($1,$2,$3,$4,$5,$6,true)
		 ON CONFLICT (tenant_id, issuer, subject) DO NOTHING`,
		identityID, tenantID, memberID, issuer, subject, email); err != nil {
		t.Fatalf("insert identity: %v", err)
	}
}
