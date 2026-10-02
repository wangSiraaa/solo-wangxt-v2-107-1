package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	xhtml "golang.org/x/net/html"
)

// browserClient 模拟真实浏览器：
//   - app jar：持有应用会话 cookie（sid），只向 appBaseURL 发送；
//   - kc jar：持有 Keycloak SSO cookie，只向 Keycloak 发送。
type browserClient struct {
	t   *testing.T
	kc  *keycloakHTTP
	app *http.Client
	// ua 是发给应用的 User-Agent，用于区分设备标签。
	ua string
}

func newBrowserClient(t *testing.T) *browserClient {
	appJar, _ := cookiejar.New(nil)
	kcJar, _ := cookiejar.New(nil)
	noFollow := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browserClient{
		t: t,
		kc: &keycloakHTTP{
			base:   kcBaseURL(),
			client: &http.Client{Jar: kcJar, Timeout: 20 * time.Second, CheckRedirect: noFollow},
		},
		app: &http.Client{Jar: appJar, Timeout: 20 * time.Second, CheckRedirect: noFollow},
	}
}

// withUA 设置该“设备”的 User-Agent（设备标签来源）。
func (b *browserClient) withUA(ua string) *browserClient {
	b.ua = ua
	return b
}

// appCallback 是 /oauth/callback 或 /oauth/link/callback 的落点结果。
type appCallback struct {
	// RequestURL 是应用回调的完整 URL（含 state/code）。
	RequestURL string
	// Response 是应用对该回调的响应（未关闭 Body，调用方负责）。
	Response *http.Response
}

// login 完整执行 应用登录启动 -> Keycloak 密码登录 -> 应用回调。
// 返回回调响应；成功时调用方应看到 302 + Set-Cookie: sid。
func (b *browserClient) login(tenantSlug string, user keycloakUser) *http.Response {
	b.t.Helper()
	startURL := appBaseURL + "/t/" + tenantSlug + "/login?issuer=" +
		url.QueryEscape(issuer(user.realm))
	cb := b.runAuthorizationFlow(startURL, user)
	return cb.Response
}

// me 携带会话 cookie 请求业务接口。
func (b *browserClient) me(tenantSlug string) map[string]any {
	b.t.Helper()
	return getJSON(b.t, b.app, appBaseURL+"/t/"+tenantSlug+"/api/me", http.StatusOK)
}

func (b *browserClient) memberID(tenantSlug string) string {
	return b.me(tenantSlug)["member_id"].(string)
}

func (b *browserClient) identities(tenantSlug string) []any {
	return b.me(tenantSlug)["identities"].([]any)
}

func (b *browserClient) logout(tenantSlug string) {
	postJSON(b.t, b.app, appBaseURL+"/t/"+tenantSlug+"/api/logout", nil, http.StatusOK)
}

// startLink 发起关联，返回 link_token 与 Keycloak 授权 URL。
func (b *browserClient) startLink(tenantSlug, targetIssuer string, extra ...map[string]string) (string, string) {
	b.t.Helper()
	body := map[string]string{"issuer": targetIssuer}
	if len(extra) > 0 {
		for k, v := range extra[0] {
			body[k] = v
		}
	}
	out := postJSON(b.t, b.app, appBaseURL+"/t/"+tenantSlug+"/api/links",
		body, http.StatusCreated)
	return out["link_token"].(string), out["link_url"].(string)
}

// linkStatus 查询关联会话状态。
func (b *browserClient) linkStatus(tenantSlug, token string, wantStatus int) map[string]any {
	return getJSON(b.t, b.app, appBaseURL+"/t/"+tenantSlug+"/api/links/"+token, wantStatus)
}

// finishLink 完成 B 身份登录并打应用关联回调，返回响应（Body 未关闭）。
func (b *browserClient) finishLink(linkURL string, user keycloakUser) *http.Response {
	b.t.Helper()
	cb := b.runAuthorizationFlow(linkURL, user)
	return cb.Response
}

// runAuthorizationFlow 从“应用生成的、指向 Keycloak 的 URL”开始：
//
//	app start(302) -> KC 登录页(200) -> 提交密码(302) -> app callback(应用响应)
func (b *browserClient) runAuthorizationFlow(appStartOrKCURL string, user keycloakUser) appCallback {
	b.t.Helper()
	var kcAuthURL string
	if strings.HasPrefix(appStartOrKCURL, appBaseURL) {
		kcAuthURL = b.appStartRedirectsToKeycloak(appStartOrKCURL)
	} else {
		kcAuthURL = appStartOrKCURL
	}
	callbackURL := b.kc.passwordLogin(kcAuthURL, user)
	if !strings.HasPrefix(callbackURL, appBaseURL) {
		b.t.Fatalf("after login expected redirect to app, got %s", callbackURL)
	}
	return b.callAppCallback(callbackURL)
}

// appStartRedirectsToKeycloak 请求应用启动端点，返回 Keycloak 授权地址。
func (b *browserClient) appStartRedirectsToKeycloak(startURL string) string {
	resp := b.appDo(http.MethodGet, startURL, nil, nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		b.t.Fatalf("app start status=%d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, kcBaseURL()) {
		b.t.Fatalf("app start did not redirect to keycloak: %s", loc)
	}
	return loc
}

// appDo 发起携带设备 User-Agent 的应用请求（不跟随重定向）。
func (b *browserClient) appDo(method, raw string, body io.Reader, hdr map[string]string) *http.Response {
	b.t.Helper()
	req, err := http.NewRequest(method, raw, body)
	if err != nil {
		b.t.Fatalf("new request %s %s: %v", method, raw, err)
	}
	if b.ua != "" {
		req.Header.Set("User-Agent", b.ua)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := b.app.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, raw, err)
	}
	return resp
}

// callAppCallback 用应用 cookie jar 请求回调地址（授权码在此被服务端消费）。
func (b *browserClient) callAppCallback(raw string) appCallback {
	resp := b.appDo(http.MethodGet, raw, nil, nil)
	// 不关闭：调用方读取 Body；测试结束进程销毁连接无妨。
	return appCallback{RequestURL: raw, Response: resp}
}

// replayCallback 用同样的应用 jar 再次请求同一回调 URL（授权码/state 重放）。
func (b *browserClient) replayCallback(raw string) *http.Response {
	return b.appDo(http.MethodGet, raw, nil, nil)
}

// ---------- 设备会话管理辅助 ----------

// sessions 列出当前成员在该租户的设备会话。
func (b *browserClient) sessions(tenantSlug string, wantStatus int) map[string]any {
	b.t.Helper()
	resp := b.appDo(http.MethodGet, appBaseURL+"/t/"+tenantSlug+"/api/sessions", nil, nil)
	return decodeExpect(b.t, resp, wantStatus)
}

// revokeDevice 撤销指定设备会话，返回 (状态码, 响应体)。
func (b *browserClient) revokeDevice(tenantSlug, sessionID string) (int, map[string]any) {
	b.t.Helper()
	resp := b.appDo(http.MethodDelete,
		appBaseURL+"/t/"+tenantSlug+"/api/sessions/"+sessionID, nil, nil)
	data := readBody(b.t, resp)
	return resp.StatusCode, data
}

// revokeAllDevices 执行“退出全部设备”。
func (b *browserClient) revokeAllDevices(tenantSlug string, wantStatus int) map[string]any {
	b.t.Helper()
	resp := b.appDo(http.MethodPost,
		appBaseURL+"/t/"+tenantSlug+"/api/sessions/revoke-all",
		strings.NewReader(""), map[string]string{"Content-Type": "application/json"})
	return decodeExpect(b.t, resp, wantStatus)
}

// meResp 与 me 相同但返回原始响应（供 401/Cookie 断言）。
func (b *browserClient) meResp(tenantSlug string) *http.Response {
	b.t.Helper()
	return b.appDo(http.MethodGet, appBaseURL+"/t/"+tenantSlug+"/api/me", nil, nil)
}

// sidCookie 返回浏览器当前持有的 sid Cookie（无则 nil）。
func (b *browserClient) sidCookie() *http.Cookie {
	u, _ := url.Parse(appBaseURL)
	for _, c := range b.app.Jar.Cookies(u) {
		if c.Name == "sid" {
			return c
		}
	}
	return nil
}

// postLink 直接 POST /api/links 并返回原始响应（供负面用例自定义期望状态）。
func (b *browserClient) postLinkRaw(tenantSlug string, body any) (int, map[string]any) {
	b.t.Helper()
	buf, _ := json.Marshal(body)
	resp, err := b.app.Post(appBaseURL+"/t/"+tenantSlug+"/api/links",
		"application/json", bytes.NewReader(buf))
	if err != nil {
		b.t.Fatalf("post link: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

// ---------- Keycloak 浏览器端 ----------

type keycloakUser struct {
	realm    string
	username string
	password string
}

type keycloakHTTP struct {
	base   string
	client *http.Client
}

// passwordLogin 请求授权页并提交用户名/密码，
// 返回 Keycloak 最终 302 的 Location（应用回调地址）。
func (k *keycloakHTTP) passwordLogin(authURL string, user keycloakUser) string {
	loginPage, pageBody, finalRedirect := k.fetchLoginPage(authURL)
	if finalRedirect != "" {
		// Keycloak 已有 SSO 会话（如 prompt 缺失时）：直接就是应用回调地址。
		return finalRedirect
	}
	_ = loginPage // 页面 URL 已用于 GET；解析表单只需要 action
	action, fields := parseLoginForm(pageBody)
	if action == "" {
		panic("keycloak login page contained no form action")
	}
	if strings.HasPrefix(action, "/") {
		action = k.base + action
	}
	form := url.Values{}
	for key, val := range fields {
		form.Set(key, val)
	}
	form.Set("username", user.username)
	form.Set("password", user.password)

	req, _ := http.NewRequest(http.MethodPost, action, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.client.Do(req)
	if err != nil {
		panic("post login form: " + err.Error())
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	switch {
	case loc != "":
		// 可能还有一次 KC 域内 302（如处理会话状态），收敛到最终地址。
		return k.finalizeRedirect(loc)
	case bytes.Contains(bytes.ToLower(body), []byte("invalid")):
		panic("keycloak rejected credentials: " + snippet(body))
	default:
		panic("login post returned no redirect: " + snippet(body))
	}
}

// finalizeRedirect 跟随 KC 域内 302，直到跳到非 KC 域（应用回调）。
func (k *keycloakHTTP) finalizeRedirect(loc string) string {
	if strings.HasPrefix(loc, "/") {
		loc = k.base + loc
	}
	if !strings.HasPrefix(loc, k.base) {
		return loc
	}
	resp, err := k.client.Get(loc)
	if err != nil {
		panic("follow keycloak redirect: " + err.Error())
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	next := resp.Header.Get("Location")
	if next == "" {
		return loc
	}
	return k.finalizeRedirect(next)
}

// fetchLoginPage 返回：
//   - 登录页 URL + 页面 HTML（需要提交密码），或
//   - 已存在 SSO 会话时的最终跳转地址 finalRedirect。
func (k *keycloakHTTP) fetchLoginPage(authURL string) (loginPage string, body []byte, finalRedirect string) {
	resp, err := k.client.Get(authURL)
	if err != nil {
		panic("get auth url: " + err.Error())
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return authURL, page, ""
	}
	if resp.StatusCode == http.StatusFound {
		loc := resp.Header.Get("Location")
		if strings.HasPrefix(loc, "/") {
			loc = k.base + loc
		}
		if strings.HasPrefix(loc, k.base) {
			return k.fetchLoginPage(loc)
		}
		return "", nil, loc
	}
	panic("unexpected auth page status")
}

// parseLoginForm 提取第一个 form 的 action 与其中所有具名表单字段。
//
// Keycloak 登录页结构（容易踩坑）：
//
//	<input type="hidden" name="credentialId" id="id-hidden-input"/>  ← 无 value，提交空串
//	<input type="submit" name="login" value="Sign In"/>             ← 提交按钮必须原样带上
//
// 因此必须：按属性名精确取值（不能被同节点其它属性污染）、只收集表单控件、
// hidden 的 credentialId 提交空字符串，submit 按钮提交其 value。
func parseLoginForm(body []byte) (string, map[string]string) {
	doc, err := xhtml.Parse(bytes.NewReader(body))
	if err != nil {
		return "", nil
	}
	action := ""
	fields := map[string]string{}
	inForm := false

	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n == nil {
			return
		}
		if n.Type == xhtml.ElementNode && n.Data == "form" {
			if action == "" {
				inForm = true
				for _, a := range n.Attr {
					if a.Key == "action" {
						action = decodeHTMLAttr(a.Val)
					}
				}
			}
		}

		if inForm && n.Type == xhtml.ElementNode && isFormControl(n.Data) {
			attrs := map[string]string{}
			for _, a := range n.Attr {
				attrs[a.Key] = a.Val
			}
			name := attrs["name"]
			if name != "" {
				// text/password/hidden 取 value（缺失即空串）；
				// submit/button 取其显示 value；select/textarea 在本页不出现。
				if _, exists := fields[name]; !exists {
					fields[name] = decodeHTMLAttr(attrs["value"])
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return action, fields
}

func isFormControl(tag string) bool {
	switch tag {
	case "input", "button", "select", "textarea":
		return true
	}
	return false
}

func decodeHTMLAttr(s string) string {
	return strings.NewReplacer("&amp;", "&", "&#34;", `"`, "&#39;", "'").Replace(s)
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
