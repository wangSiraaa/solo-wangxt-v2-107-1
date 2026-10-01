package integration

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestAccountLinkingHappyPath 验证两个身份各自重新认证后成功关联：
//   - A 身份（acme alice）已登录；
//   - POST /api/links 发起，B 身份（globex bob）通过 prompt=login 重新认证；
//   - 完成后 acme 成员同时拥有 (acme,alice) 与 (globex,bob) 两条已核实身份；
//   - 两条身份邮箱不同，也绝不按邮箱合并。
func TestAccountLinkingHappyPath(t *testing.T) {
	env := startEnv(t)
	browser := newBrowserClient(t)

	// A 身份登录。
	respA := browser.login("acme",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	_, _ = io.Copy(io.Discard, respA.Body)
	_ = respA.Body.Close()
	memberID := browser.memberID("acme")
	if len(browser.identities("acme")) != 1 {
		t.Fatalf("pre-link identities should be 1")
	}

	// 发起关联，B 身份强制重新认证。
	token, linkURL := browser.startLink("acme", issuer("globex"))
	if token == "" || linkURL == "" {
		t.Fatalf("empty link token/url")
	}
	cb := browser.finishLink(linkURL,
		keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	if cb.StatusCode != http.StatusOK {
		body := readBody(t, cb)
		t.Fatalf("link callback status=%d body=%v, want 200", cb.StatusCode, body)
	}
	_ = cb.Body.Close()

	// 完成后 A 成员拥有两条身份，分属两个不同 issuer；邮箱不参与判定。
	ids := browser.identities("acme")
	if len(ids) != 2 {
		t.Fatalf("post-link identities=%d, want 2", len(ids))
	}
	issuers := map[string]bool{}
	for _, raw := range ids {
		issuers[raw.(map[string]any)["issuer"].(string)] = true
	}
	if !issuers[issuer("acme")] || !issuers[issuer("globex")] {
		t.Fatalf("post-link issuers=%v", issuers)
	}

	// 数据库：acme 租户内该成员名下有两条身份（acme-alice 与 globex-bob），
	// globex 租户没有产生新成员；同邮箱不会被用来匹配账号。
	if n := countRows(t, env,
		`SELECT count(*) FROM identities WHERE tenant_id=$1 AND member_id=$2`,
		tenantAcmeID, memberID); n != 2 {
		t.Fatalf("db identities on linked member in acme=%d, want 2", n)
	}
	if n := countRows(t, env,
		`SELECT count(*) FROM members WHERE tenant_id=$1`, tenantGlobexID); n != 0 {
		t.Fatalf("globex members=%d, want 0; linking attaches identity without creating a member", n)
	}

	// link token 一次性：状态查询已变为 consumed。
	st := browser.linkStatus("acme", token, http.StatusOK)
	if st["status"] != "consumed" {
		t.Fatalf("link status=%v, want consumed", st["status"])
	}
}

// TestLinkConflictWhenTargetAlreadyBound 验证绑定冲突：
// 当外部身份 (acme 租户视角, issuer=globex, subject=bob) 已经被关联到某成员名下后，
// 另一个成员再想把同一身份关联到自己，必须返回 409 binding_conflict，不能抢走别人的身份。
//
// 身份锚点为 (tenant_id=acme, issuer=globex, subject=bob)：冲突完全在 acme 租户内判定。
//
// 浏览器 SSO 说明（Keycloak 的安全约束）：prompt=login 不允许在同一 SSO 会话内
// 切换成另一个用户，因此两名成员必须来自不同 realm，使 B 身份（globex/bob）的
// 重新认证对两个浏览器都发生在“干净的 globex SSO 上下文”里：
//   - 成员 A：acme/alice（SSO 在 acme realm）→ 重认证 globex/bob（跨 realm，干净）
//   - 成员 C：acme 租户的 carol（SSO 也在 acme realm，但是另一个浏览器）→ 同样跨 realm
func TestLinkConflictWhenTargetAlreadyBound(t *testing.T) {
	env := startEnv(t)

	// 成员 A：acme 租户的 alice，先把外部身份 (globex,bob) 关联到自己名下。
	memberABrowser := newBrowserClient(t)
	respA := memberABrowser.login("acme",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	_, _ = io.Copy(io.Discard, respA.Body)
	_ = respA.Body.Close()
	memberAID := memberABrowser.memberID("acme")

	_, linkURLA := memberABrowser.startLink("acme", issuer("globex"))
	cbA := memberABrowser.finishLink(linkURLA,
		keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	if cbA.StatusCode != http.StatusOK {
		t.Fatalf("first link should succeed, status=%d body=%s",
			cbA.StatusCode, mustBody(t, cbA))
	}
	_ = cbA.Body.Close()
	if ids := memberABrowser.identities("acme"); len(ids) != 2 {
		t.Fatalf("member A identities=%d, want 2", len(ids))
	}

	// 成员 C：acme 租户的另一名员工 carol（acme realm，不同 subject）。
	memberCBrowser := newBrowserClient(t)
	respC := memberCBrowser.login("acme",
		keycloakUser{realm: "acme", username: "carol", password: "carol-pass"})
	_, _ = io.Copy(io.Discard, respC.Body)
	_ = respC.Body.Close()
	memberCID := memberCBrowser.memberID("acme")
	if memberCID == memberAID {
		t.Fatalf("member C collapsed into member A (identity anchoring broken)")
	}

	// C 也想关联外部身份 (globex,bob)，但它已属于 A -> 409 binding_conflict。
	_, linkURLC := memberCBrowser.startLink("acme", issuer("globex"))
	cbC := memberCBrowser.finishLink(linkURLC,
		keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	body := readBody(t, cbC)
	if cbC.StatusCode != http.StatusConflict || body["error"] != "binding_conflict" {
		t.Fatalf("link to already-bound identity status=%d body=%v, want 409 binding_conflict",
			cbC.StatusCode, body)
	}

	// 冲突后 (acme,globex,bob) 仍归成员 A，成员 C 仍只有自己一条身份。
	var owner string
	err := env.store.DB().QueryRow(context.Background(),
		`SELECT member_id::text FROM identities
		 WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		tenantAcmeID, issuer("globex"),
		subjectOf(t, env, "acme", "bob@example.com")).Scan(&owner)
	if err != nil {
		t.Fatalf("lookup bound identity owner: %v", err)
	}
	if owner != memberAID {
		t.Fatalf("bound identity owner changed: want %s got %s", memberAID, owner)
	}
	if ids := memberCBrowser.identities("acme"); len(ids) != 1 {
		t.Fatalf("member C identities after failed link=%d, want 1", len(ids))
	}
}

func mustBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// TestLinkSameEmailAcrossTenants 验证“跨租户同邮箱”账号关联：
// acme 的 alice(alice@example.com) 关联 globex 的 alice.globex（同样 alice@example.com）。
// 两条身份邮箱相同，但来自不同 issuer、不同 subject；关联后仍是同一成员的两条身份。
// 关联不依赖邮箱，因此即便邮箱相同也不会与“自然登录的另一个 alice”混淆。
func TestLinkSameEmailAcrossTenants(t *testing.T) {
	env := startEnv(t)
	browser := newBrowserClient(t)

	respA := browser.login("acme",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	_, _ = io.Copy(io.Discard, respA.Body)
	_ = respA.Body.Close()

	_, linkURL := browser.startLink("acme", issuer("globex"))
	cb := browser.finishLink(linkURL,
		keycloakUser{realm: "globex", username: "alice.globex", password: "aliceg-pass"})
	if cb.StatusCode != http.StatusOK {
		body := readBody(t, cb)
		t.Fatalf("same-email link status=%d body=%v, want 200", cb.StatusCode, body)
	}
	_ = cb.Body.Close()

	ids := browser.identities("acme")
	if len(ids) != 2 {
		t.Fatalf("identities after same-email link=%d, want 2", len(ids))
	}
	emails := map[string]int{}
	subs := map[string]int{}
	for _, raw := range ids {
		m := raw.(map[string]any)
		emails[m["email"].(string)]++
		subs[m["subject"].(string)]++
	}
	if emails["alice@example.com"] != 2 {
		t.Fatalf("expected two identities with shared email, got %v", emails)
	}
	if len(subs) != 2 {
		t.Fatalf("expected two distinct subjects, got %v", subs)
	}

	// 该成员只存在于 acme 租户视角；globex 侧不会因为关联凭空多出一个成员。
	if n := countRows(t, env, `SELECT count(*) FROM members WHERE tenant_id=$1`, tenantGlobexID); n != 0 {
		t.Fatalf("globex members=%d, want 0 (linking does not create cross-tenant members)", n)
	}
}

// TestLinkRequiresReauthentication 验证关联会话的新鲜度：
// 手动把 a_auth_time 调老，超过 provider 的 maxAge，完成时应被拒绝为
// 401 reauthentication_required，而不是静默关联。
func TestLinkRequiresReauthentication(t *testing.T) {
	env := startEnv(t)
	browser := newBrowserClient(t)
	respA := browser.login("acme",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	_, _ = io.Copy(io.Discard, respA.Body)
	_ = respA.Body.Close()

	token, linkURL := browser.startLink("acme", issuer("globex"))

	// 在 B 完成登录之前，把 A 的认证时间改到很久以前（模拟发起后搁置超时）。
	res, err := env.store.DB().Exec(context.Background(),
		`UPDATE link_sessions SET a_auth_time=$1 WHERE token=$2`,
		time.Now().Add(-2*time.Hour), token)
	if err != nil {
		t.Fatalf("age a_auth_time: %v", err)
	}
	if res.RowsAffected() != 1 {
		t.Fatalf("aged rows=%d, want 1", res.RowsAffected())
	}

	cb := browser.finishLink(linkURL,
		keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	body := readBody(t, cb)
	if cb.StatusCode != http.StatusUnauthorized || body["error"] != "reauthentication_required" {
		t.Fatalf("stale link status=%d body=%v, want 401 reauthentication_required",
			cb.StatusCode, body)
	}
}

// TestLinkCannotBeReplayed 验证 link state 与 link token 都一次性：
// 成功关联后，用同一回调 URL 再打一次必须被拒绝，且不会产生第三条身份。
func TestLinkCannotBeReplayed(t *testing.T) {
	env := startEnv(t)
	browser := newBrowserClient(t)
	respA := browser.login("acme",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	_, _ = io.Copy(io.Discard, respA.Body)
	_ = respA.Body.Close()

	_, linkURL := browser.startLink("acme", issuer("globex"))

	// 手动驱动一次以拿到回调 URL，再连续打两次。
	kcPage := browser.kc
	_ = kcPage
	callbackURL := browser.kc.passwordLogin(linkURL,
		keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	first := browser.callAppCallback(callbackURL)
	body1 := readBody(t, first.Response)
	if first.Response.StatusCode != http.StatusOK || body1["status"] != "linked" {
		t.Fatalf("first link status=%d body=%v, want 200 linked",
			first.Response.StatusCode, body1)
	}

	second := browser.replayCallback(callbackURL)
	body2 := readBody(t, second)
	if second.StatusCode != http.StatusBadRequest || body2["error"] != "invalid_request" {
		t.Fatalf("replayed link status=%d body=%v, want 400 invalid_request",
			second.StatusCode, body2)
	}

	if n := countRows(t, env,
		`SELECT count(*) FROM identities i JOIN tenants t ON t.id=i.tenant_id
		 WHERE t.slug='acme'`); n != 2 {
		t.Fatalf("identities after link replay=%d, want 2 (no duplication)", n)
	}
}

// TestLinkRejectsOtherIssuerIdentity 是 issuer 锚定的负向用例：
// link 目标 provider 必须仍为该租户授权；关联前禁用目标 provider 应失败，
// 且错误为 tenant_unauthorized。
func TestLinkRejectsDisabledProvider(t *testing.T) {
	env := startEnv(t)
	browser := newBrowserClient(t)
	respA := browser.login("acme",
		keycloakUser{realm: "acme", username: "alice", password: "alice-pass"})
	_, _ = io.Copy(io.Discard, respA.Body)
	_ = respA.Body.Close()

	if _, err := env.store.DB().Exec(context.Background(),
		`UPDATE identity_providers SET enabled=false WHERE id=$1`, idpAcmeGlobexID); err != nil {
		t.Fatalf("disable acme's globex provider authorization: %v", err)
	}

	status, body := browser.postLinkRaw("acme", map[string]string{"issuer": issuer("globex")})
	if status != http.StatusForbidden || body["error"] != "tenant_unauthorized" {
		t.Fatalf("link to disabled provider status=%d body=%v, want 403 tenant_unauthorized",
			status, body)
	}
}
