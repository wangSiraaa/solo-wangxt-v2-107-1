// Package integration 是针对真实 Keycloak 与真实 PostgreSQL 的端到端集成测试。
//
// 运行前提：
//   - 本地 Keycloak 已按 deploy/keycloak/import/*.json 导入 acme / globex 两个 realm；
//   - 地址可用环境变量 KC_BASE_URL 覆盖（默认 http://localhost:8180）。
//
// 运行：
//
//	go test ./integration/... -v
//
// PostgreSQL 由 embedded-postgres 在测试进程内拉起（无需系统安装）。
package integration

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	embedded "github.com/fergusstrange/embedded-postgres"
	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/api"
	"github.com/example/oidctenant/internal/config"
	"github.com/example/oidctenant/internal/db"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

const (
	kcBaseURLDefault = "http://localhost:8180"
	appPort          = "18080" // 避开开发机常见端口
	appBaseURL       = "http://localhost:" + appPort
	loginCallback    = appBaseURL + "/oauth/callback"
	linkCallback     = appBaseURL + "/oauth/link/callback"
)

// 固定 UUID，便于 seed 与断言引用。
var (
	tenantAcmeID   = uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
	tenantGlobexID = uuid.MustParse("00000000-0000-0000-0000-0000000000b1")

	// acme 租户授权的 IdP：自有 acme issuer + 外部 globex issuer（用于跨企业关联）。
	idpAcmeSelfID   = uuid.MustParse("00000000-0000-0000-0000-0000000000a2")
	idpAcmeGlobexID = uuid.MustParse("00000000-0000-0000-0000-0000000000a3")
	// globex 租户授权的 IdP：自有 globex issuer + 外部 acme issuer。
	idpGlobexSelfID = uuid.MustParse("00000000-0000-0000-0000-0000000000b2")
	idpGlobexAcmeID = uuid.MustParse("00000000-0000-0000-0000-0000000000b3")
)

// 兼容旧引用（测试中按“自有 issuer”语义使用）。
var (
	idpAcmeID   = idpAcmeSelfID
	idpGlobexID = idpGlobexSelfID
)

type testEnv struct {
	t       *testing.T
	pg      *embedded.EmbeddedPostgres
	store   *store.Store
	kc      *keycloakAdmin
	baseURL string
}

func kcBaseURL() string {
	if v := os.Getenv("KC_BASE_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return kcBaseURLDefault
}

func issuer(realm string) string {
	return kcBaseURL() + "/realms/" + realm
}

// startEnv 启动嵌入式 PG、迁移、seed 租户/IdP，并在真实端口启动应用。
func startEnv(t *testing.T) *testEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in -short mode")
	}
	pgPort := freeTCPPort(t)
	pg := embedded.NewDatabase(embedded.DefaultConfig().
		Port(pgPort).
		Database("oidctenant").
		DataPath(t.TempDir()).
		CachePath("/workspace/tools/ep-cache").
		Logger(io.Discard))
	if err := pg.Start(); err != nil {
		t.Fatalf("start embedded postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Stop() })

	dsn := formatDSN(pgPort, "oidctenant")
	ctx := context.Background()
	database, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st := store.New(database)

	seedTenant(t, st, tenantAcmeID, "acme", "Acme Corp", models.Provider{
		ID: idpAcmeSelfID, TenantID: tenantAcmeID,
		Issuer: issuer("acme"), ClientID: "acme-rp", ClientSecret: "acme-rp-secret",
		RedirectURIs:   []string{loginCallback, linkCallback},
		AuthTimeMaxAge: 300, Enabled: true,
	})
	// acme 额外授权外部 globex issuer：凭证是 globex realm 的客户端（关联用）。
	seedTenant(t, st, tenantAcmeID, "acme", "Acme Corp", models.Provider{
		ID: idpAcmeGlobexID, TenantID: tenantAcmeID,
		Issuer: issuer("globex"), ClientID: "globex-rp", ClientSecret: "globex-rp-secret",
		RedirectURIs:   []string{loginCallback, linkCallback},
		AuthTimeMaxAge: 300, Enabled: true,
	})
	seedTenant(t, st, tenantGlobexID, "globex", "Globex Inc", models.Provider{
		ID: idpGlobexSelfID, TenantID: tenantGlobexID,
		Issuer: issuer("globex"), ClientID: "globex-rp", ClientSecret: "globex-rp-secret",
		RedirectURIs:   []string{loginCallback, linkCallback},
		AuthTimeMaxAge: 300, Enabled: true,
	})
	// globex 额外授权外部 acme issuer。
	seedTenant(t, st, tenantGlobexID, "globex", "Globex Inc", models.Provider{
		ID: idpGlobexAcmeID, TenantID: tenantGlobexID,
		Issuer: issuer("acme"), ClientID: "acme-rp", ClientSecret: "acme-rp-secret",
		RedirectURIs:   []string{loginCallback, linkCallback},
		AuthTimeMaxAge: 300, Enabled: true,
	})

	cfg := &config.Config{
		DatabaseURL:    dsn,
		BaseURL:        appBaseURL,
		Addr:           ":" + appPort,
		SessionTTL:     time.Hour,
		LinkTTL:        10 * time.Minute,
		AuthRequestTTL: 10 * time.Minute,
		CookieSecure:   false,
		CookieSameSite: "lax",
	}
	httpSrv := &http.Server{
		Addr: ":" + appPort,
		Handler: api.NewServer(cfg, st, oidcx.NewManager(),
			log.New(os.Stdout, "[test-api] ", log.LstdFlags|log.Lmicroseconds)).Routes(),
	}
	go func() { _ = httpSrv.ListenAndServe() }()
	waitReady(t, appBaseURL+"/healthz")
	t.Cleanup(func() {
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shCtx)
		database.Close()
	})

	env := &testEnv{
		t: t, pg: pg, store: st, baseURL: appBaseURL,
		kc: newKeycloakAdmin(t),
	}
	return env
}

func waitReady(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	client := &http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		if c, err := client.Get(url); err == nil {
			_ = c.Body.Close()
			if c.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server did not become ready at %s", url)
}

func seedTenant(t *testing.T, st *store.Store, id uuid.UUID, slug, name string, p models.Provider) {
	t.Helper()
	if err := st.UpsertTenant(context.Background(), id, slug, name); err != nil {
		t.Fatalf("upsert tenant: %v", err)
	}
	p.TenantID = id
	if err := st.UpsertProvider(context.Background(), &p); err != nil {
		t.Fatalf("upsert provider: %v", err)
	}
}

// ---------- 应用侧 HTTP 辅助 ----------

func getJSON(t *testing.T, client *http.Client, raw string, wantStatus int) map[string]any {
	t.Helper()
	resp, err := client.Get(raw)
	if err != nil {
		t.Fatalf("GET %s: %v", raw, err)
	}
	defer resp.Body.Close()
	return decodeExpect(t, resp, wantStatus)
}

func postJSON(t *testing.T, client *http.Client, raw string, body any, wantStatus int) map[string]any {
	t.Helper()
	var reader io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		reader = strings.NewReader(string(buf))
	}
	resp, err := client.Post(raw, "application/json", reader)
	if err != nil {
		t.Fatalf("POST %s: %v", raw, err)
	}
	defer resp.Body.Close()
	return decodeExpect(t, resp, wantStatus)
}

func decodeExpect(t *testing.T, resp *http.Response, wantStatus int) map[string]any {
	t.Helper()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d; body=%s", resp.StatusCode, wantStatus, string(data))
	}
	if len(data) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode %q: %v", string(data), err)
	}
	return out
}

// readBody 读取任意响应体为 map（不强制状态码）。
func readBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out
}
