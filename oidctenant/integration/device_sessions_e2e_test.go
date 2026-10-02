package integration

import (
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func parseUUID(s string) (uuid.UUID, error) { return uuid.Parse(s) }

// skipIfKeycloakUnavailable 让依赖真实 IdP 的端到端用例在没有 Keycloak 时跳过
// （其余 browser_* 用例通过 startEnv 内部的 admin 检查暴露同样的前置条件）。
func skipIfKeycloakUnavailable(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(kcBaseURL() + "/realms/master/.well-known/openid-configuration")
	if err != nil {
		t.Skipf("keycloak not reachable at %s, skipping end-to-end device test: %v",
			kcBaseURL(), err)
		return
	}
	_ = resp.Body.Close()
}

// appSidCookies 返回浏览器 jar 中当前对应用生效的 sid cookie 数量（应为 0 或 1）。
func appSidCookies(b *browserClient) []*http.Cookie {
	u, err := url.Parse(appBaseURL)
	if err != nil {
		b.t.Fatalf("parse base url: %v", err)
	}
	var out []*http.Cookie
	for _, c := range b.app.Jar.Cookies(u) {
		if c.Name == "sid" {
			out = append(out, c)
		}
	}
	return out
}

// TestDeviceSessions_EndToEndLoginRevokeOtherDevice
//
// 真实 OIDC 登录端到端：同一成员在两台“设备”（两个独立浏览器，各自持有 sid）
// 登录后，设备 A 列出会话、识别当前会话、撤销设备 B；
// 随后 B 访问 me 得到 401（并清理 Cookie），A 仍可用；再次撤销 B 幂等。
//
// 该用例需要 Keycloak（与其它 browser_* 用例一致），KC 不可用时由 startEnv 跳过/失败前置。
func TestDeviceSessions_EndToEndLoginRevokeOtherDevice(t *testing.T) {
	skipIfKeycloakUnavailable(t)
	startEnv(t)
	user := keycloakUser{realm: "acme", username: "alice", password: "alice-pass"}

	devA := newBrowserClient(t)
	if cb := devA.login("acme", user); cb.StatusCode != http.StatusFound {
		t.Fatalf("device A login status=%d want 302", cb.StatusCode)
	} else {
		_ = cb.Body.Close()
	}
	devB := newBrowserClient(t)
	if cb := devB.login("acme", user); cb.StatusCode != http.StatusFound {
		t.Fatalf("device B login status=%d want 302", cb.StatusCode)
	} else {
		_ = cb.Body.Close()
	}

	meA := devA.me("acme")
	meB := devB.me("acme")
	if meA["member_id"] != meB["member_id"] {
		t.Fatalf("two devices landed on different members: %v vs %v",
			meA["member_id"], meB["member_id"])
	}

	// A 列出会话：恰好两台设备，且只有一条 current。
	list := getJSON(t, devA.app, appBaseURL+"/t/acme/api/sessions", http.StatusOK)
	sessions := list["sessions"].([]any)
	if len(sessions) != 2 {
		t.Fatalf("listed sessions=%d want 2", len(sessions))
	}
	var currentID, otherID string
	for _, raw := range sessions {
		v := raw.(map[string]any)
		// 列表 id 必须是 UUID 形态而不是 sid（Go cookie 值是 base64url）。
		if _, err := parseUUID(v["id"].(string)); err != nil {
			t.Fatalf("listing exposed non-uuid session handle: %v", v["id"])
		}
		if v["current"] == true {
			currentID = v["id"].(string)
		} else {
			otherID = v["id"].(string)
		}
		for _, secret := range []string{"token_hash", "sid", "code", "id_token"} {
			if _, present := v[secret]; present {
				t.Fatalf("session view leaked sensitive field %q", secret)
			}
		}
	}
	if currentID == "" || otherID == "" || currentID == otherID {
		t.Fatalf("expected exactly one current and one other session, got %v", sessions)
	}

	// A 撤销 B（other）。
	rev := postJSON(t, devA.app,
		appBaseURL+"/t/acme/api/sessions/"+otherID+"/revoke", nil, http.StatusOK)
	if rev["revoked"] != true || rev["current"] != false {
		t.Fatalf("revoke other=%v want revoked=true current=false", rev)
	}

	// B 立即被拒：me -> 401 authentication_failed，且 sid Cookie 被清理。
	respB, err := devB.app.Get(appBaseURL + "/t/acme/api/me")
	if err != nil {
		t.Fatalf("B me: %v", err)
	}
	bodyB := readBody(t, respB)
	if respB.StatusCode != http.StatusUnauthorized || bodyB["error"] != "authentication_failed" {
		t.Fatalf("revoked B status=%d body=%v want 401 authentication_failed",
			respB.StatusCode, bodyB)
	}
	if n := len(appSidCookies(devB)); n != 0 {
		t.Fatalf("revoked B sid cookies remaining=%d want 0", n)
	}

	// B 再打任何受保护写入接口都 401。
	for _, p := range []string{"/api/logout", "/api/sessions/revoke-all"} {
		req, _ := http.NewRequest(http.MethodPost, appBaseURL+"/t/acme"+p, nil)
		r, err := devB.app.Do(req)
		if err != nil {
			t.Fatalf("B post %s: %v", p, err)
		}
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked B %s status=%d want 401", p, r.StatusCode)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}

	// A 完全不受影响。
	devA.me("acme")

	// 重复撤销 B：幂等，200 且 revoked=false。
	again := postJSON(t, devA.app,
		appBaseURL+"/t/acme/api/sessions/"+otherID+"/revoke", nil, http.StatusOK)
	if again["revoked"] != false || again["current"] != false {
		t.Fatalf("idempotent revoke=%v want revoked=false current=false", again)
	}
}

// TestDeviceSessions_EndToEndRevokeAllLogsOutEveryDevice
// 三台真实登录设备，全部退出后所有 sid 立即失效。
func TestDeviceSessions_EndToEndRevokeAllLogsOutEveryDevice(t *testing.T) {
	skipIfKeycloakUnavailable(t)
	startEnv(t)
	user := keycloakUser{realm: "acme", username: "carol", password: "carol-pass"}

	var devices []*browserClient
	for i := 0; i < 3; i++ {
		b := newBrowserClient(t)
		if cb := b.login("acme", user); cb.StatusCode != http.StatusFound {
			t.Fatalf("device %d login status=%d want 302", i, cb.StatusCode)
		} else {
			_ = cb.Body.Close()
		}
		devices = append(devices, b)
		b.me("acme")
	}
	active := devices[0]
	out := postJSON(t, active.app,
		appBaseURL+"/t/acme/api/sessions/revoke-all", nil, http.StatusOK)
	if cnt, _ := out["revoked_count"].(float64); cnt != 3 {
		t.Fatalf("revoked_count=%v want 3", out["revoked_count"])
	}
	for i, b := range devices {
		if n := len(appSidCookies(b)); n != 0 {
			t.Fatalf("device %d sid cookies after revoke-all=%d want 0", i, n)
		}
		resp, err := b.app.Get(appBaseURL + "/t/acme/api/me")
		if err != nil {
			t.Fatalf("device %d me: %v", i, err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("device %d me after revoke-all status=%d want 401", i, resp.StatusCode)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}
