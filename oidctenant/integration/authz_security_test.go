package integration

import (
	"context"
	"io"
	"net/http"
	"testing"
)

// TestAuthorizationCodeReplay 验证授权码只能使用一次：
// 第一次回调消费 code 并成功；第二次（即使 state 未被消费的情形由另一用例覆盖）
// 在 Keycloak 侧也会以 invalid_grant 拒绝，接口统一归类为 authentication_failed。
//
// 本用例构造的是“state 已消费 + code 已用过”的完整重放（最常见的双击/浏览器后退）。
func TestAuthorizationCodeReplay(t *testing.T) {
	startEnv(t)
	browser := newBrowserClient(t)
	user := keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}

	startURL := appBaseURL + "/t/acme/login?issuer=" + issuer("acme")
	kcURL := browser.appStartRedirectsToKeycloak(startURL)
	callbackURL := browser.kc.passwordLogin(kcURL, user)

	first := browser.callAppCallback(callbackURL)
	if first.Response.StatusCode != http.StatusFound {
		t.Fatalf("first callback status=%d, want 302", first.Response.StatusCode)
	}
	_, _ = io.Copy(io.Discard, first.Response.Body)
	_ = first.Response.Body.Close()

	// 再次提交同一个回调：state 已被服务端原子消费，归类 invalid_request。
	second := browser.callAppCallback(callbackURL)
	body := readBody(t, second.Response)
	if second.Response.StatusCode != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("replay status=%d body=%v, want 400 invalid_request",
			second.Response.StatusCode, body)
	}
}

// TestAuthorizationCodeCannotBeReplayedAtTokenEndpoint 从侧面验证：
// 服务端不会“吞掉”重放 —— 用一个全新的 state 行 + 同一个旧 code 直接打回调，
// Keycloak token 端点以 invalid_grant 拒绝（code 已用过），
// 应用返回 401 authentication_failed，而不是创建会话。
func TestStaleCodeWithFreshStateIsAuthnFailure(t *testing.T) {
	startEnv(t)

	// 第一次正常登录拿到一个已消费的 code。
	good := newBrowserClient(t)
	user := keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}
	startURL := appBaseURL + "/t/acme/login?issuer=" + issuer("acme")
	callbackURL := good.kc.passwordLogin(good.appStartRedirectsToKeycloak(startURL), user)
	usedCode := queryParam(callbackURL, "code")

	first := good.callAppCallback(callbackURL)
	_, _ = io.Copy(io.Discard, first.Response.Body)
	first.Response.Body.Close()

	// 第二次发起授权会生成新 state，但我们不真正登录，
	// 而是用“新 state（未消费）+ 旧 code”打回调。
	attacker := newBrowserClient(t)
	startURL2 := appBaseURL + "/t/acme/login?issuer=" + issuer("acme")
	// 跟随到 KC 即可拿到新 state（在应用启动 302 的 Location 查询串里），
	// 不需要再走密码表单。
	resp, err := attacker.app.Get(startURL2)
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	loc2 := resp.Header.Get("Location")
	_ = resp.Body.Close()
	newState := queryParam(loc2, "state")

	forged := appBaseURL + "/oauth/callback?state=" + newState + "&code=" + usedCode
	resp2, err := attacker.app.Get(forged)
	if err != nil {
		t.Fatalf("forged callback: %v", err)
	}
	body := readBody(t, resp2)
	if resp2.StatusCode != http.StatusUnauthorized || body["error"] != "authentication_failed" {
		t.Fatalf("stale code status=%d body=%v, want 401 authentication_failed",
			resp2.StatusCode, body)
	}
}

// TestUnknownAndReplayedState 验证伪造 state 与已消费 state 行为一致，
// 无法借此枚举有效 state。
func TestUnknownAndReplayedState(t *testing.T) {
	startEnv(t)
	browser := newBrowserClient(t)

	for _, state := range []string{"does-not-exist", "0123456789abcdef0123456789abcdef"} {
		resp, err := browser.app.Get(appBaseURL + "/oauth/callback?state=" + state +
			"&code=anything")
		if err != nil {
			t.Fatalf("callback: %v", err)
		}
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_request" {
			t.Fatalf("state=%s status=%d body=%v, want 400 invalid_request",
				state, resp.StatusCode, body)
		}
	}
}

// TestUnauthorizedIssuerForTenant 验证租户未授权某 issuer 时返回
// 403 tenant_unauthorized（与认证失败 401 明确区分）。
func TestUnauthorizedIssuerForTenant(t *testing.T) {
	startEnv(t)
	browser := newBrowserClient(t)

	// acme 租户尝试用一个从未授权的 issuer（不属于其 provider 列表）：启动阶段即被拒绝。
	// 注意 globex issuer 已被 acme 授权用于跨企业账号关联，因此这里用第三个未授权 issuer。
	unauthorized := kcBaseURL() + "/realms/unauthorized-partner"
	u := appBaseURL + "/t/acme/login?issuer=" + unauthorized
	resp, err := browser.app.Get(u)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden || body["error"] != "tenant_unauthorized" {
		t.Fatalf("unauthorized issuer status=%d body=%v, want 403 tenant_unauthorized",
			resp.StatusCode, body)
	}

	// 未知租户同样是 403（不泄露租户是否存在之外的信息）。
	resp2, err := browser.app.Get(appBaseURL + "/t/ghost/login?issuer=" + issuer("acme"))
	if err != nil {
		t.Fatalf("login ghost: %v", err)
	}
	body2 := readBody(t, resp2)
	if resp2.StatusCode != http.StatusForbidden || body2["error"] != "tenant_unauthorized" {
		t.Fatalf("unknown tenant status=%d body=%v, want 403 tenant_unauthorized",
			resp2.StatusCode, body2)
	}
}

// TestRedirectURIMustBeWhitelisted 验证只允许已配置的回调地址。
// 临时把 provider 的 redirect_uris 改成不含应用回调地址的值，再发起登录应被拒绝。
func TestRedirectURIMustBeWhitelisted(t *testing.T) {
	env := startEnv(t)
	browser := newBrowserClient(t)

	// 通过 store 将 acme 的回调白名单改成别的地址（模拟误配置/未登记）。
	if _, err := env.store.DB().Exec(context.Background(),
		`UPDATE identity_providers SET redirect_uris=$1 WHERE id=$2`,
		[]string{"https://elsewhere.example.invalid/cb"}, idpAcmeID); err != nil {
		t.Fatalf("update redirect uris: %v", err)
	}

	u := appBaseURL + "/t/acme/login?issuer=" + issuer("acme")
	resp, err := browser.app.Get(u)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("non-whitelisted redirect status=%d body=%v, want 400 invalid_request",
			resp.StatusCode, body)
	}
}

// TestWrongPasswordIsAuthnFailure 验证 IdP 侧凭证错误不会登录成功：
// Keycloak 留在登录页；此处直接验证错误参数路径与凭证错误不会产生成员。
func TestWrongPasswordIsAuthnFailure(t *testing.T) {
	env := startEnv(t)
	browser := newBrowserClient(t)

	startURL := appBaseURL + "/t/acme/login?issuer=" + issuer("acme")
	kcURL := browser.appStartRedirectsToKeycloak(startURL)

	// 提交错误密码：passwordLogin 在仍停留登录页时 panic。改为手动断言。
	page, pageBody, _ := browser.kc.fetchLoginPage(kcURL)
	action, fields := parseLoginForm(pageBody)
	if action == "" {
		t.Fatalf("login page url=%s had no form", page)
	}
	fields["username"] = "alice"
	fields["password"] = "definitely-wrong-password"
	resp := postForm(t, browser.kc.client, absKeycloak(action), fields)
	bb, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !containsFold(string(bb), "invalid") {
		t.Fatalf("wrong password expected KC login error page (200 with 'invalid'), got status=%d",
			resp.StatusCode)
	}

	if n := countRows(t, env, "SELECT count(*) FROM members"); n != 0 {
		t.Fatalf("members after failed login=%d, want 0", n)
	}
}
