package integration

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/example/oidctenant/internal/auth"
	"github.com/example/oidctenant/internal/store"
)

// loginDevice 以指定 User-Agent 在某租户完成一次真实登录，返回“一台设备”。
func loginDevice(t *testing.T, tenantSlug, ua string, user keycloakUser) *browserClient {
	t.Helper()
	b := newBrowserClient(t).withUA(ua)
	resp := b.login(tenantSlug, user)
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s login callback status=%d want 302: %s", ua, resp.StatusCode, body)
	}
	_ = resp.Body.Close()
	if c := b.sidCookie(); c == nil {
		t.Fatalf("%s: expected sid cookie after login", ua)
	}
	return b
}

func sessionList(t *testing.T, b *browserClient, slug string) (map[string]any, []map[string]any) {
	t.Helper()
	out := b.sessions(slug, http.StatusOK)
	raw, ok := out["sessions"].([]any)
	if !ok {
		t.Fatalf("sessions payload missing list: %v", out)
	}
	list := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		list = append(list, item.(map[string]any))
	}
	return out, list
}

func findSession(list []map[string]any, id string) map[string]any {
	for _, s := range list {
		if s["id"] == id {
			return s
		}
	}
	return nil
}

// assertNoCredentialLeak 确保任何会话相关响应都不携带原始 sid / 哈希 / 授权码。
func assertNoCredentialLeak(t *testing.T, blob string, sidTokens ...string) {
	t.Helper()
	for _, sid := range sidTokens {
		if sid != "" && strings.Contains(blob, sid) {
			t.Fatalf("response leaked raw sid value: %s", blob)
		}
	}
	for _, banned := range []string{"token_hash", "access_token", "id_token", "\"code\"", "pkce"} {
		if strings.Contains(blob, banned) {
			t.Fatalf("response leaked sensitive field %q: %s", banned, blob)
		}
	}
}

// expectAuthFailureAndClearedCookie 断言被撤销设备访问受保护接口得到
// 401 authentication_failed，且服务端清理了 sid Cookie（一致结果）。
func expectAuthFailureAndClearedCookie(t *testing.T, resp *http.Response) {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "authentication_failed") {
		t.Fatalf("body=%s want authentication_failed", body)
	}
	var cleared bool
	for _, sc := range resp.Cookies() {
		if sc.Name == "sid" && (sc.MaxAge < 0 || !sc.Expires.IsZero() && sc.Expires.Before(time.Now())) {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("revoked session response did not clear sid cookie: %v", resp.Cookies())
	}
}

// TestDeviceSessionsTwoDevicesAreDistinctAndSelectiveRevoke 验收点：
// 同一成员两台设备登录后可在列表中区分，并仅撤销其中一台；
// 被撤销设备随后访问 me / 关联接口认证失败，另一台仍可用。
func TestDeviceSessionsTwoDevicesAreDistinctAndSelectiveRevoke(t *testing.T) {
	env := startEnv(t)
	user := keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}

	d1 := loginDevice(t, "acme", "iPhone 15 Safari iOS", user)
	d2 := loginDevice(t, "acme", "Windows 11 Chrome/126", user)

	// 两台设备必须落到同一个成员（身份复用，不重复建号）。
	m1, m2 := d1.memberID("acme"), d2.memberID("acme")
	if m1 != m2 {
		t.Fatalf("expected same member across devices, got %s vs %s", m1, m2)
	}
	if d1.sidCookie().Value == d2.sidCookie().Value {
		t.Fatalf("two devices must not share the same opaque sid")
	}

	out, list := sessionList(t, d1, "acme")
	if len(list) != 2 {
		t.Fatalf("sessions=%d want 2: %v", len(list), list)
	}
	currentID := out["current_id"].(string)
	if currentID != d1.me("acme")["session_id"] {
		t.Fatalf("current_id mismatch: %v", out)
	}
	var v1, v2 map[string]any
	for _, v := range list {
		switch v["label"] {
		case "iPhone 15 Safari iOS":
			v1 = v
		case "Windows 11 Chrome/126":
			v2 = v
		}
	}
	if v1 == nil || v2 == nil {
		t.Fatalf("device labels not distinguishable: %v", list)
	}
	if v1["id"] == v2["id"] {
		t.Fatalf("device ids must differ")
	}
	if v1["status"] != "active" || v2["status"] != "active" {
		t.Fatalf("new devices must be active: %v %v", v1, v2)
	}
	if v1["current"] != true {
		t.Fatalf("d1's own session must be marked current: %v", v1)
	}
	if v2["current"] != false {
		t.Fatalf("d2 session seen from d1 must not be current: %v", v2)
	}
	// 列表使用内部 UUID，绝不能用原始 sid 命中任何条目。
	if findSession(list, d1.sidCookie().Value) != nil || findSession(list, d2.sidCookie().Value) != nil {
		t.Fatalf("session list must not be addressable by raw sid")
	}
	// 列表载荷绝不包含原始 sid 或任何令牌字段。
	assertNoCredentialLeak(t, marshalForTest(out), d1.sidCookie().Value, d2.sidCookie().Value)

	// 仅撤销 d2 这一台设备。
	code, body := d1.revokeDevice("acme", v2["id"].(string))
	if code != http.StatusOK || body["status"] != "revoked" {
		t.Fatalf("selective revoke code=%d body=%v want 200 revoked", code, body)
	}

	// 被撤销设备：me 与关联发起接口都必须 401，并清理 Cookie。
	expectAuthFailureAndClearedCookie(t, d2.meResp("acme"))
	linksResp := d2.appDo(http.MethodPost, appBaseURL+"/t/acme/api/links",
		strings.NewReader(`{"issuer":"`+issuer("acme")+`"}`),
		map[string]string{"Content-Type": "application/json"})
	expectAuthFailureAndClearedCookie(t, linksResp)
	// 再次访问仍稳定 401（Cookie 已被清，也不再有效）。
	expectAuthFailureAndClearedCookie(t, d2.meResp("acme"))

	// 另一台设备继续可用。
	if got := d1.me("acme")["member_id"]; got != m1 {
		t.Fatalf("other device should keep working, got member=%v", got)
	}

	// 列表现在显示一活跃一已撤销。
	_, list2 := sessionList(t, d1, "acme")
	r2 := findSession(list2, v2["id"].(string))
	if r2 == nil || r2["status"] != "revoked" || r2["revoked_at"] == "" {
		t.Fatalf("revoked device not shown revoked: %v", list2)
	}
	r1 := findSession(list2, v1["id"].(string))
	if r1 == nil || r1["status"] != "active" || r1["revoked_at"] != "" {
		t.Fatalf("other device must remain active: %v", list2)
	}

	// DB 层断言：只有 d2 被撤销，d1 未被撤销。
	if n := countRows(t, env,
		`SELECT count(*) FROM sessions WHERE revoked_at IS NOT NULL AND member_id = $1`,
		mustUUID(t, m2)); n != 1 {
		t.Fatalf("revoked sessions=%d want 1", n)
	}
}

// TestRevokeSessionIsIdempotent 验收点：重复撤销同一会话有稳定幂等结果。
func TestRevokeSessionIsIdempotent(t *testing.T) {
	startEnv(t)
	user := keycloakUser{realm: "acme", username: "carol", password: "carol-pass"}

	d1 := loginDevice(t, "acme", "MacBook Safari", user)
	d2 := loginDevice(t, "acme", "Linux Firefox", user)

	_, list := sessionList(t, d1, "acme")
	var target string
	for _, v := range list {
		if v["current"] == false {
			target = v["id"].(string)
		}
	}

	for i, want := range []string{"revoked", "already_revoked", "already_revoked"} {
		code, body := d1.revokeDevice("acme", target)
		if code != http.StatusOK || body["status"] != want {
			t.Fatalf("revoke #%d code=%d body=%v want 200 %s", i+1, code, body, want)
		}
	}
	// 当前设备始终不受影响。
	if d1.me("acme")["member_id"] == nil {
		t.Fatalf("current device should still work after idempotent remote revokes")
	}
	// d2 已撤销。
	expectAuthFailureAndClearedCookie(t, d2.meResp("acme"))
}

// TestRevokeRacesWithInFlightProtectedOperation 验收点：
// 撤销请求与该会话的受保护操作同时发生时，不会出现“撤销之后还成功写入”。
//
// 手法：用与鉴权中间件完全相同的方式（请求事务 + TouchSession 行锁）
// 模拟 d2 上一个“已开始、尚未提交”的受保护请求；此时通过真实 HTTP 发起的
// 撤销必须在锁上等待。待该请求提交后撤销才完成；此后 d2 任何受保护访问
// 都 401，不可能再有成功写入。
func TestRevokeRacesWithInFlightProtectedOperation(t *testing.T) {
	env := startEnv(t)
	user := keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}
	d1 := loginDevice(t, "acme", "Controller Desktop", user)
	d2 := loginDevice(t, "acme", "Lost Phone Mobile", user)

	_, list := sessionList(t, d1, "acme")
	d2ID := d2.me("acme")["session_id"].(string)
	target := findSession(list, d2ID)
	if target == nil {
		t.Fatalf("d2 session not listed")
	}

	// 1) 模拟 d2 的受保护请求已经进入中间件：开启请求事务并拿到行锁，
	//    但不提交（handler 正在处理中）。
	rtx, txCtx, err := store.BeginRequestTx(context.Background(), env.store.DB())
	if err != nil {
		t.Fatalf("begin request tx: %v", err)
	}
	inFlight, err := env.store.TouchSession(txCtx, auth.HashToken(d2.sidCookie().Value))
	if err != nil {
		t.Fatalf("in-flight touch: %v", err)
	}
	if inFlight.ID.String() != d2ID {
		t.Fatalf("in-flight session mismatch")
	}

	// 2) 另一台设备同时发起撤销：必须阻塞，不能在受保护请求提交前完成。
	revokeDone := make(chan struct {
		code int
		body map[string]any
	}, 1)
	go func() {
		c, b := d1.revokeDevice("acme", d2ID)
		revokeDone <- struct {
			code int
			body map[string]any
		}{c, b}
	}()
	select {
	case r := <-revokeDone:
		t.Fatalf("revoke completed before in-flight request committed: %v", r)
	case <-time.After(300 * time.Millisecond):
		// 预期：撤销正在行锁上等待。
	}

	// 3) 受保护请求提交成功（它先于撤销完成，写入合法）。
	if err := rtx.Commit(context.Background()); err != nil {
		t.Fatalf("commit in-flight: %v", err)
	}
	select {
	case r := <-revokeDone:
		if r.code != http.StatusOK || r.body["status"] != "revoked" {
			t.Fatalf("revoke after barrier code=%d body=%v", r.code, r.body)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("revoke did not complete after in-flight commit")
	}

	// 4) 严格顺序校验：d2 的最后活动写入（先）不晚于 revoked_at（后）。
	var lastActivity, revokedAt time.Time
	if err := env.store.DB().QueryRow(context.Background(),
		`SELECT last_activity_at, revoked_at FROM sessions WHERE id=$1`,
		mustUUID(t, d2ID)).Scan(&lastActivity, &revokedAt); err != nil {
		t.Fatalf("load timestamps: %v", err)
	}
	if revokedAt.IsZero() {
		t.Fatalf("session should be revoked")
	}
	if lastActivity.After(revokedAt) {
		t.Fatalf("in-flight write (last_activity=%s) committed AFTER revoke (%s)",
			lastActivity, revokedAt)
	}

	// 5) 撤销之后，d2 不可能再发起任何成功的受保护“写入”：me/links 全部 401。
	expectAuthFailureAndClearedCookie(t, d2.meResp("acme"))

	// 反向顺序：先撤销，再尝试以 d2 凭据开启“受保护请求”，TouchSession 立即失败，
	// 中间件不会执行任何 handler 写入。
	if _, txCtx2, err := store.BeginRequestTx(context.Background(), env.store.DB()); err != nil {
		t.Fatalf("begin: %v", err)
	} else if _, err := env.store.TouchSession(txCtx2, auth.HashToken(d2.sidCookie().Value)); err == nil {
		t.Fatalf("touch after revoke must fail")
	}

	// d1 不受影响。
	if d1.me("acme")["member_id"] == nil {
		t.Fatalf("revoking device should stay signed in")
	}
}

// TestRevokeCrossTenantAndCrossMemberIsDenied 验收点：
// 跨租户同邮箱、同租户另一成员的会话都不能被枚举或撤销。
func TestRevokeCrossTenantAndCrossMemberIsDenied(t *testing.T) {
	startEnv(t)
	aliceAcme := keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}
	aliceGlobex := keycloakUser{realm: "globex", username: "alice.globex", password: "aliceg-pass"}
	carol := keycloakUser{realm: "acme", username: "carol", password: "carol-pass"}

	// 两个同邮箱、跨租户的 alice；以及同租户另一成员 carol。
	acmeAlice := loginDevice(t, "acme", "Acme Alice Laptop", aliceAcme)
	globexAlice := loginDevice(t, "globex", "Globex Alice Phone", aliceGlobex)
	acmeCarol := loginDevice(t, "acme", "Carol Tablet", carol)

	acmeAliceSession := acmeAlice.me("acme")["session_id"].(string)
	globexSession := globexAlice.me("globex")["session_id"].(string)
	carolSession := acmeCarol.me("acme")["session_id"].(string)

	// globex 的同邮箱 alice 看不到也撤销不了 acme 的会话：统一 404 not_found。
	if code, body := globexAlice.revokeDevice("globex", acmeAliceSession); code != http.StatusNotFound ||
		body["error"] != "not_found" {
		t.Fatalf("cross-tenant revoke code=%d body=%v want 404 not_found", code, body)
	}
	// carol 撤销不了同租户 alice 的会话。
	if code, body := acmeCarol.revokeDevice("acme", acmeAliceSession); code != http.StatusNotFound ||
		body["error"] != "not_found" {
		t.Fatalf("cross-member revoke code=%d body=%v want 404 not_found", code, body)
	}
	// acme alice 也枚举不到 globex / carol 的会话 id。
	if code, body := acmeAlice.revokeDevice("acme", globexSession); code != http.StatusNotFound {
		t.Fatalf("acme enumerating globex session code=%d body=%v", code, body)
	}
	if code, _ := acmeAlice.revokeDevice("acme", carolSession); code != http.StatusNotFound {
		t.Fatalf("alice enumerating carol session code=%d want 404", code)
	}
	// 非法 / 随机 UUID 同样 404，且响应体不可区分“不存在”与“不属于我”。
	for _, bad := range []string{"not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
		if code, body := acmeAlice.revokeDevice("acme", bad); code != http.StatusNotFound ||
			body["error"] != "not_found" {
			t.Fatalf("revoke %q code=%d body=%v want 404 not_found", bad, code, body)
		}
	}

	// 列表彼此不泄漏对方会话 id。
	_, ga := sessionList(t, globexAlice, "globex")
	for _, s := range ga {
		if s["id"] == acmeAliceSession {
			t.Fatalf("globex listing leaked acme session id")
		}
	}

	// 被尝试攻击的会话全部仍然有效。
	if acmeAlice.me("acme")["session_id"] != acmeAliceSession {
		t.Fatalf("acme alice session must survive cross-tenant/cross-member revoke attempts")
	}
	if globexAlice.me("globex")["session_id"] != globexSession {
		t.Fatalf("globex alice session must survive")
	}
	if acmeCarol.me("acme")["session_id"] != carolSession {
		t.Fatalf("carol session must survive")
	}
}

// TestLogoutKeepsSingleDeviceSemantics 验收点：原有单设备 logout 语义保持正确。
func TestLogoutKeepsSingleDeviceSemantics(t *testing.T) {
	env := startEnv(t)
	user := keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"}
	d1 := loginDevice(t, "globex", "Bob Desktop", user)
	d2 := loginDevice(t, "globex", "Bob Phone", user)

	d1.logout("globex")

	// 当前浏览器：sid 已清理，再次访问 401。
	if c := d1.sidCookie(); c != nil {
		t.Fatalf("logout should drop sid cookie, got %v", c)
	}
	expectAuthFailureAndClearedCookie(t, d1.meResp("globex"))

	// 另一台设备完全不受影响。
	if d2.me("globex")["member_id"] == nil {
		t.Fatalf("single-device logout must not revoke other devices")
	}

	if n := countRows(t, env,
		`SELECT count(*) FROM sessions WHERE revoked_at IS NOT NULL`); n != 1 {
		t.Fatalf("exactly one session should be revoked, got %d", n)
	}
}

// TestRevokeAllDevicesLogsOutEverySession 验收点补充：全部设备退出。
func TestRevokeAllDevicesLogsOutEverySession(t *testing.T) {
	env := startEnv(t)
	user := keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}
	d1 := loginDevice(t, "acme", "Alice Desktop", user)
	d2 := loginDevice(t, "acme", "Alice Laptop", user)
	d3 := loginDevice(t, "acme", "Alice Phone", user)

	out := d1.revokeAllDevices("acme", http.StatusOK)
	if out["status"] != "logged_out_all" {
		t.Fatalf("revoke-all body=%v", out)
	}
	if n, _ := out["other_revoked"].(float64); n != 2 {
		t.Fatalf("other_revoked=%v want 2", out["other_revoked"])
	}
	if c := d1.sidCookie(); c != nil {
		t.Fatalf("revoke-all should clear current sid cookie")
	}

	for _, b := range []*browserClient{d1, d2, d3} {
		expectAuthFailureAndClearedCookie(t, b.meResp("acme"))
	}
	if n := countRows(t, env, `SELECT count(*) FROM sessions WHERE revoked_at IS NOT NULL`); n != 3 {
		t.Fatalf("revoked sessions=%d want 3", n)
	}
}

// TestSessionLabelNeverContainsTokenMaterial 验收点补充：
// 标签是 User-Agent 的脱敏摘要，任何列表/响应都不带 sid 等令牌。
func TestSessionLabelNeverContainsTokenMaterial(t *testing.T) {
	startEnv(t)
	// 含控制字符的 UA 也只能成为安全的单行标签。
	ua := "CrazyBrowser/1.0\r\nX-Injected: yes\n"
	d := loginDevice(t, "acme", ua, keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	_, list := sessionList(t, d, "acme")
	if len(list) != 1 {
		t.Fatalf("sessions=%d want 1", len(list))
	}
	label := list[0]["label"].(string)
	if strings.ContainsAny(label, "\r\n") {
		t.Fatalf("label contains control characters: %q", label)
	}
	if strings.Contains(label, "X-Injected") {
		t.Fatalf("header injection survived in label: %q", label)
	}
	sid := d.sidCookie().Value
	assertNoCredentialLeak(t, marshalForTest(list), sid)
}
