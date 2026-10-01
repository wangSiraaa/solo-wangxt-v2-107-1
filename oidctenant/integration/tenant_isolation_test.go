package integration

import (
	"context"
	"io"
	"net/http"
	"testing"
)

// TestCrossTenantSameEmailIsolation 验证核心安全属性：
// 两个企业（租户）的员工邮箱完全相同，也绝不会落到同一个租户账号，
// 因为业务身份锚点是已核实的 (tenant_id, issuer, subject)，而不是 email 字段。
func TestCrossTenantSameEmailIsolation(t *testing.T) {
	env := startEnv(t)

	aliceAcme := keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}
	aliceGlobex := keycloakUser{realm: "globex", username: "alice.globex", password: "aliceg-pass"}

	// 浏览器 A：acme 租户的 alice@example.com
	browserA := newBrowserClient(t)
	loginRespA := browserA.login("acme", aliceAcme)
	if loginRespA.StatusCode != http.StatusFound {
		t.Fatalf("acme login callback status=%d, want 302", loginRespA.StatusCode)
	}
	_ = loginRespA.Body.Close()
	meA := browserA.me("acme")
	idsA := meA["identities"].([]any)
	if len(idsA) != 1 {
		t.Fatalf("acme alice identities=%d, want 1", len(idsA))
	}
	idA := idsA[0].(map[string]any)
	if idA["email"] != "alice@example.com" {
		t.Fatalf("acme email=%v", idA["email"])
	}
	if idA["issuer"] != issuer("acme") {
		t.Fatalf("acme issuer=%v", idA["issuer"])
	}

	// 浏览器 B：globex 租户的 alice@example.com（同一邮箱字符串）
	browserB := newBrowserClient(t)
	loginRespB := browserB.login("globex", aliceGlobex)
	if loginRespB.StatusCode != http.StatusFound {
		t.Fatalf("globex login callback status=%d, want 302", loginRespB.StatusCode)
	}
	_ = loginRespB.Body.Close()
	meB := browserB.me("globex")
	idsB := meB["identities"].([]any)
	if len(idsB) != 1 {
		t.Fatalf("globex alice identities=%d, want 1", len(idsB))
	}
	idB := idsB[0].(map[string]any)
	if idB["email"] != "alice@example.com" {
		t.Fatalf("globex email=%v", idB["email"])
	}
	if idB["issuer"] != issuer("globex") {
		t.Fatalf("globex issuer=%v", idB["issuer"])
	}

	// 关键断言：member_id 必须不同（不能因为同邮箱而合并/串号）。
	if meA["member_id"] == meB["member_id"] {
		t.Fatalf("same member_id across tenants: %v", meA["member_id"])
	}
	// subject 也应当不同（不同 realm 的不同用户）。
	if idA["subject"] == idB["subject"] {
		t.Fatalf("subjects unexpectedly equal across tenants")
	}

	// acme 的会话不能用来访问 globex 租户接口（跨租户使用会话 -> 403 tenant_unauthorized）。
	resp, err := browserA.app.Get(appBaseURL + "/t/globex/api/me")
	if err != nil {
		t.Fatalf("cross-tenant me: %v", err)
	}
	cross := readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden || cross["error"] != "tenant_unauthorized" {
		t.Fatalf("cross-tenant session status=%d error=%v, want 403 tenant_unauthorized",
			resp.StatusCode, cross["error"])
	}

	// 数据库层面只有两个成员、两条身份，邮箱相同但锚点不同。
	if n := countRows(t, env, "SELECT count(*) FROM members"); n != 2 {
		t.Fatalf("members=%d, want 2", n)
	}
	if n := countRows(t, env,
		"SELECT count(*) FROM identities WHERE email='alice@example.com'"); n != 2 {
		t.Fatalf("identities with shared email=%d, want 2", n)
	}
	if n := countRows(t, env, `
		SELECT count(DISTINCT member_id) FROM identities WHERE email='alice@example.com'`); n != 2 {
		t.Fatalf("distinct members sharing email=%d, want 2", n)
	}
}

// TestLoginCallbackReplayDoesNotDuplicateMember 验证登录回调重复到达：
// state 一次性消费，第二次回调必然失败；即使重复，也只创建一个成员/一条身份。
func TestLoginCallbackReplayDoesNotDuplicateMember(t *testing.T) {
	env := startEnv(t)
	browser := newBrowserClient(t)
	user := keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}

	startURL := appBaseURL + "/t/acme/login?issuer=" + issuer("acme")
	kcURL := browser.appStartRedirectsToKeycloak(startURL)
	callbackURL := browser.kc.passwordLogin(kcURL, user)

	// 第一次回调：成功，302 + 会话 cookie。
	first := browser.callAppCallback(callbackURL)
	if first.Response.StatusCode != http.StatusFound {
		t.Fatalf("first callback status=%d, want 302", first.Response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, first.Response.Body)
	_ = first.Response.Body.Close()

	// 第二次回调（完全相同的 state+code 再次到达）：必须被拒绝，且不建第二个成员。
	second := browser.replayCallback(callbackURL)
	body := readBody(t, second)
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed callback status=%d, want 400; body=%v", second.StatusCode, body)
	}
	if body["error"] != "invalid_request" {
		t.Fatalf("replayed callback error=%v, want invalid_request", body["error"])
	}

	if n := countRows(t, env,
		"SELECT count(*) FROM identities WHERE issuer=$1 AND subject=$2",
		issuer("acme"), subjectOf(t, env, "acme", "alice@example.com")); n != 1 {
		t.Fatalf("identities after replay=%d, want 1", n)
	}
	if n := countRows(t, env, "SELECT count(*) FROM members"); n != 1 {
		t.Fatalf("members after replay=%d, want 1", n)
	}
}

// TestConcurrentFirstLoginsDoNotDuplicateMember 模拟两个相同身份的“首次登录”
// 并发落库（双击/网络重试），验证咨询锁 + UNIQUE(tenant_id,issuer,subject)
// 共同保证只有一个成员。
func TestConcurrentFirstLoginsDoNotDuplicateMember(t *testing.T) {
	env := startEnv(t)
	user := keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"}

	type result struct{ status int }
	resCh := make(chan result, 2)
	for i := 0; i < 2; i++ {
		b := newBrowserClient(t)
		go func(b *browserClient) {
			defer func() {
				if r := recover(); r != nil {
					resCh <- result{status: -1}
				}
			}()
			startURL := appBaseURL + "/t/globex/login?issuer=" + issuer("globex")
			kcURL := b.appStartRedirectsToKeycloak(startURL)
			callbackURL := b.kc.passwordLogin(kcURL, user)
			cb := b.callAppCallback(callbackURL)
			_, _ = io.Copy(io.Discard, cb.Response.Body)
			cb.Response.Body.Close()
			resCh <- result{status: cb.Response.StatusCode}
		}(b)
	}
	for i := 0; i < 2; i++ {
		r := <-resCh
		if r.status != http.StatusFound && r.status != -1 {
			t.Fatalf("concurrent login unexpected status=%d", r.status)
		}
	}

	if n := countRows(t, env,
		`SELECT count(*) FROM members m
		 JOIN identities i ON i.member_id=m.id
		 JOIN tenants t ON t.id=i.tenant_id
		 WHERE t.slug='globex' AND i.email=$1`, "bob@example.com"); n != 1 {
		t.Fatalf("concurrent first-login members=%d, want 1", n)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM identities i JOIN tenants t ON t.id=i.tenant_id
		 WHERE t.slug='globex' AND i.email=$1`, "bob@example.com"); n != 1 {
		t.Fatalf("concurrent first-login identities=%d, want 1", n)
	}
}

func subjectOf(t *testing.T, env *testEnv, tenantSlug, email string) string {
	t.Helper()
	var sub string
	err := env.store.DB().QueryRow(context.Background(),
		`SELECT i.subject FROM identities i JOIN tenants t ON t.id=i.tenant_id
		 WHERE t.slug=$1 AND i.email=$2`, tenantSlug, email).Scan(&sub)
	if err != nil {
		t.Fatalf("lookup subject: %v", err)
	}
	return sub
}
