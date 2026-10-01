package integration

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSigningKeyRotation 验证 IdP 轮换签名密钥后应用仍能验证新 ID token：
//   - go-oidc 的远程 KeySet 在遇到未知 kid 时会自动重新拉取 JWKS；
//   - 旧 kid 仍在 JWKS 中，因此轮换前已签发的令牌在过期前仍可验。
//
// 步骤：
//  1. 用初始 key 登录成功（应用缓存了初始 JWKS）；
//  2. 通过 admin API 增加一个高优先级 RSA provider，新令牌改用新 kid；
//  3. 不重启应用，再次登录，必须成功，且新 token header.kid 确实变化。
func TestSigningKeyRotation(t *testing.T) {
	env := startEnv(t)

	// 轮换前的活动 kid 与 JWKS。
	kidBefore := env.kc.ActiveKeyID("globex")
	jwksBefore := PublicJWKSKids(t, "globex")
	if !jwksBefore[kidBefore] {
		t.Fatalf("active kid %s not present in public JWKS before rotation", kidBefore)
	}

	// 第一次登录：填充应用对 globex issuer 的 provider/JWKS 缓存。
	b1 := newBrowserClient(t)
	resp1 := b1.login("globex",
		keycloakUser{realm: "globex", username: "bob", password: "bobg-pass"})
	_, _ = io.Copy(io.Discard, resp1.Body)
	_ = resp1.Body.Close()
	me1 := b1.me("globex")
	memberBefore := me1["member_id"]

	// 轮换：加入优先级更高的 RSA provider。名与优先级均唯一，避免历史残留并列。
	rotName := "rsa-rotation-" + strings.ReplaceAll(
		time.Now().Format("150405.000000"), ".", "")
	rotPriority := 100000 + int(time.Now().UnixNano()%100000)
	rotID := env.kc.RotateSigningKey("globex", rotName, rotPriority)
	t.Cleanup(func() { env.kc.DeleteKeyProvider("globex", rotID) })

	// 等待 Keycloak 发布新 JWKS（通常立即生效，轮询确认）。
	deadline := time.Now().Add(15 * time.Second)
	kidAfter := ""
	for time.Now().Before(deadline) {
		kidAfter = env.kc.ActiveKeyID("globex")
		jwks := PublicJWKSKids(t, "globex")
		if kidAfter != kidBefore && jwks[kidAfter] && jwks[kidBefore] {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if kidAfter == "" || kidAfter == kidBefore {
		t.Fatalf("signing key did not rotate: before=%s after=%s", kidBefore, kidAfter)
	}

	// 取一个由新 key 签发的 ID token，直接核对 header.kid。
	// globex-rp 默认仅允许标准流；这里通过 admin 临时打开 directGrants 仅用于观察 kid。
	env.kc.EnableDirectGrants("globex", "globex-rp", true)
	t.Cleanup(func() { env.kc.EnableDirectGrants("globex", "globex-rp", false) })
	newTokenKid := kidOfFreshToken(t, "globex", "globex-rp", "globex-rp-secret",
		"bob", "bobg-pass")
	if newTokenKid != kidAfter {
		t.Fatalf("fresh token kid=%s, want rotated kid=%s", newTokenKid, kidAfter)
	}

	// 不重启应用，用全新浏览器（全新 state/nonce/PKCE）再走一次完整授权码登录，
	// 应用必须自动发现并信任新 kid。
	b2 := newBrowserClient(t)
	resp2 := b2.login("globex",
		keycloakUser{realm: "globex", username: "alice.globex", password: "aliceg-pass"})
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("login after key rotation status=%d, want 302", resp2.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp2.Body)
	_ = resp2.Body.Close()
	me2 := b2.me("globex")

	// bob 与 alice 仍是不同成员（同租户不同 subject）。
	if me2["member_id"] == memberBefore {
		t.Fatalf("different users collapsed into one member after rotation")
	}

	// 轮换前的 kid 必须仍在公开 JWKS 中（旧令牌在其有效期内仍可验）。
	jwksAfter := PublicJWKSKids(t, "globex")
	if !jwksAfter[kidBefore] {
		t.Fatalf("previous signing kid %s disappeared from JWKS after rotation", kidBefore)
	}
	if !jwksAfter[kidAfter] {
		t.Fatalf("new signing kid %s missing from JWKS", kidAfter)
	}
}

// kidOfFreshToken 用直接授权换取一枚新 ID token 并解码其未验签的 header.kid。
// 仅用于读取 kid；业务侧的令牌校验在应用授权码流程内单独验证。
func kidOfFreshToken(t *testing.T, realm, clientID, secret, username, password string) string {
	t.Helper()
	form := urlValues()
	form.Set("client_id", clientID)
	form.Set("client_secret", secret)
	form.Set("grant_type", "password")
	form.Set("scope", "openid")
	form.Set("username", username)
	form.Set("password", password)

	req, _ := http.NewRequest(http.MethodPost,
		kcBaseURL()+"/realms/"+realm+"/protocol/openid-connect/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("password grant: %v", err)
	}
	defer resp.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatalf("decode token resp: %v", err)
	}
	if resp.StatusCode != http.StatusOK || tok.IDToken == "" {
		t.Fatalf("password grant failed status=%d error=%s", resp.StatusCode, tok.Error)
	}
	kid, alg := jwtHeaderKid(t, tok.IDToken)
	if alg != "RS256" {
		t.Fatalf("unexpected alg=%s, want RS256", alg)
	}
	return kid
}

// jwtHeaderKid 不做签名校验地读取 JWT header（仅用于测试观察 kid）。
func jwtHeaderKid(t *testing.T, jwt string) (kid, alg string) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed jwt")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode jwt header: %v", err)
	}
	var h struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("unmarshal jwt header: %v", err)
	}
	return h.Kid, h.Alg
}
