package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// keycloakAdmin 封装 master realm 管理 API：获取/缓存 token、创建用户、轮换签名密钥。
type keycloakAdmin struct {
	t        *testing.T
	base     string
	http     *http.Client
	tokenMu  sync.Mutex
	token    string
	tokenExp time.Time
}

func newKeycloakAdmin(t *testing.T) *keycloakAdmin {
	a := &keycloakAdmin{
		t:    t,
		base: kcBaseURL(),
		http: &http.Client{Timeout: 20 * time.Second},
	}
	// 启动时验证一次可达性。
	if _, err := a.adminToken(); err != nil {
		t.Fatalf("keycloak admin api unreachable at %s: %v", a.base, err)
	}
	return a
}

func (a *keycloakAdmin) adminToken() (string, error) {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()
	if a.token != "" && time.Now().Before(a.tokenExp.Add(-10*time.Second)) {
		return a.token, nil
	}
	form := url.Values{}
	form.Set("client_id", "admin-cli")
	form.Set("grant_type", "password")
	form.Set("username", "admin")
	form.Set("password", "admin")
	resp, err := a.http.Post(a.base+"/realms/master/protocol/openid-connect/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("admin token status=%d body=%s", resp.StatusCode, string(data))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &tok); err != nil {
		return "", err
	}
	a.token = tok.AccessToken
	a.tokenExp = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return a.token, nil
}

func (a *keycloakAdmin) do(method, path string, body any, wantStatus ...int) []byte {
	a.t.Helper()
	var reader io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, a.base+path, reader)
	if err != nil {
		a.t.Fatalf("new admin request: %v", err)
	}
	tok, err := a.adminToken()
	if err != nil {
		a.t.Fatalf("admin token: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		a.t.Fatalf("admin %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if len(wantStatus) > 0 {
		ok := false
		for _, s := range wantStatus {
			if resp.StatusCode == s {
				ok = true
				break
			}
		}
		if !ok {
			a.t.Fatalf("admin %s %s status=%d want=%v body=%s",
				method, path, resp.StatusCode, wantStatus, truncate(string(data)))
		}
	}
	return data
}

// CreateUser 在指定 realm 创建带密码的用户（幂等：已存在则更新密码）。
func (a *keycloakAdmin) CreateUser(realm, username, email, password string) {
	a.t.Helper()
	payload := map[string]any{
		"username":        username,
		"email":           email,
		"emailVerified":   true,
		"enabled":         true,
		"requiredActions": []string{},
		"credentials": []map[string]any{
			{"type": "password", "value": password, "temporary": false},
		},
	}
	data := a.do(http.MethodPost, "/admin/realms/"+realm+"/users", payload,
		http.StatusCreated, http.StatusConflict)

	if len(data) == 0 {
		// 201 Created
		return
	}
	// 409 分支：find existing and reset password / email.
	var users []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(a.do(http.MethodGet,
		"/admin/realms/"+realm+"/users?username="+url.QueryEscape(username)+"&exact=true",
		nil), &users)
	if len(users) == 0 {
		a.t.Fatalf("user %s reported conflict but not found", username)
		return
	}
	id := users[0].ID
	a.do(http.MethodPut, "/admin/realms/"+realm+"/users/"+id, map[string]any{
		"email": email, "emailVerified": true, "enabled": true,
	}, http.StatusNoContent)
	a.setPassword(realm, id, password)
}

func (a *keycloakAdmin) setPassword(realm, id, password string) {
	a.do(http.MethodPut,
		"/admin/realms/"+realm+"/users/"+id+"/reset-password",
		map[string]any{"type": "password", "value": password, "temporary": false},
		http.StatusNoContent)
}

// EnableDirectGrants 切换客户端的 directAccessGrantsEnabled（测试观察 kid 用）。
func (a *keycloakAdmin) EnableDirectGrants(realm, clientID string, enabled bool) {
	a.t.Helper()
	var clients []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(a.do(http.MethodGet,
		"/admin/realms/"+realm+"/clients?clientId="+clientID+"&search=true",
		nil), &clients)
	if len(clients) == 0 {
		a.t.Fatalf("client %s not found in realm %s", clientID, realm)
	}
	a.do(http.MethodPut,
		"/admin/realms/"+realm+"/clients/"+clients[0].ID,
		map[string]any{"directAccessGrantsEnabled": enabled},
		http.StatusNoContent)
}

// RotateSigningKey 添加一个给定优先级的 RSA key provider。
// Keycloak 会立即用最高优先级 provider 的 active key 签发新令牌；
// 旧 key 仍在 JWKS 中可用于验旧令牌。返回新 component 的 ID。
// 组件名与优先级都由调用方保证唯一，避免多个并列最高优先级导致选键不确定。
func (a *keycloakAdmin) RotateSigningKey(realm, name string, priority int) string {
	a.t.Helper()
	payload := map[string]any{
		"name":         name,
		"providerId":   "rsa-generated",
		"providerType": "org.keycloak.keys.KeyProvider",
		"parentId":     realm, // Keycloak 创建 realm component 时要求在 body 中携带 parentId
		"config": map[string][]string{
			"priority": {strconv.Itoa(priority)},
			"keySize":  {"2048"},
			"active":   {"true"},
			"enabled":  {"true"},
		},
	}
	a.do(http.MethodPost,
		"/admin/realms/"+realm+"/components",
		payload, http.StatusCreated)

	// POST 创建没有 body 返回 ID；列出 components 找到该 name。
	var comps []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	_ = json.Unmarshal(a.do(http.MethodGet,
		"/admin/realms/"+realm+"/components?type=org.keycloak.keys.KeyProvider",
		nil), &comps)
	for _, c := range comps {
		if c.Name == name {
			return c.ID
		}
	}
	a.t.Fatalf("rotated key component %q not found after creation", name)
	return ""
}

// DeleteKeyProvider 删除一个签名密钥 component（测试清理用）。
func (a *keycloakAdmin) DeleteKeyProvider(realm, componentID string) {
	a.t.Helper()
	a.do(http.MethodDelete,
		"/admin/realms/"+realm+"/components/"+componentID, nil,
		http.StatusNoContent, http.StatusNotFound)
}

// ActiveKeyID 返回 realm 当前用于签名的 kid（从新签发令牌的 header 取）。
func (a *keycloakAdmin) ActiveKeyID(realm string) string {
	a.t.Helper()
	// 用一个直接授权拿令牌会污染语义；改为读取 JWKS 第一个 RSA kid 不够准确。
	// 更可靠：发起一次 client credentials（acme-rp 未开启），因此这里读取
	// realm keys 接口并返回 providerPriority 最高的 active RSA kid 由调用方对比。
	type keyEntry struct {
		ProviderID       string `json:"providerId"`
		ProviderPriority int    `json:"providerPriority"`
		Kid              string `json:"kid"`
		Status           string `json:"status"`
		Algorithm        string `json:"algorithm"`
	}
	var keys struct {
		Keys []keyEntry `json:"keys"`
	}
	_ = json.Unmarshal(a.do(http.MethodGet,
		"/admin/realms/"+realm+"/keys", nil), &keys)
	bestKid := ""
	bestPri := -1 << 30
	for _, k := range keys.Keys {
		if k.Status == "ACTIVE" && strings.HasPrefix(k.Algorithm, "RS") && k.ProviderPriority > bestPri {
			bestPri = k.ProviderPriority
			bestKid = k.Kid
		}
	}
	if bestKid == "" {
		a.t.Fatalf("no active RSA signing key found in realm %s", realm)
	}
	return bestKid
}

// PublicJWKSKids 返回该 realm 对外 JWKS 中的全部 kid（公开端点，无需 admin）。
func PublicJWKSKids(t *testing.T, realm string) map[string]bool {
	t.Helper()
	resp, err := http.Get(kcBaseURL() + "/realms/" + realm + "/protocol/openid-connect/certs")
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer resp.Body.Close()
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	out := map[string]bool{}
	for _, k := range doc.Keys {
		out[k.Kid] = true
	}
	return out
}

func truncate(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}
