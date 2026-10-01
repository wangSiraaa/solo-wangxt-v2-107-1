// Command seed 根据 JSON 规格幂等创建租户与其已授权的 OIDC issuer 配置。
//
// 规格示例见 deploy/seed.json。运行：
//
//	DATABASE_URL=postgres://... go run ./cmd/seed -file deploy/seed.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/example/oidctenant/internal/db"
	"github.com/example/oidctenant/internal/models"
	"github.com/example/oidctenant/internal/store"
)

type seedSpec struct {
	Tenants []seedTenant `json:"tenants"`
}

type seedTenant struct {
	ID        string         `json:"id"`
	Slug      string         `json:"slug"`
	Name      string         `json:"name"`
	Providers []seedProvider `json:"providers"`
}

type seedProvider struct {
	ID             string   `json:"id"`
	Issuer         string   `json:"issuer"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret"`
	RedirectURIs   []string `json:"redirect_uris"`
	AuthTimeMaxAge int      `json:"auth_time_max_age"`
	Enabled        *bool    `json:"enabled"`
}

func mustUUID(s, what string) uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		log.Fatalf("invalid %s uuid %q: %v", what, s, err)
	}
	return id
}

func main() {
	file := flag.String("file", "deploy/seed.json", "seed spec JSON file")
	flag.Parse()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		log.Fatalf("read seed file: %v", err)
	}
	var spec seedSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		log.Fatalf("parse seed file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	database, err := db.Connect(ctx, dsn)
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(ctx, database); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	st := store.New(database)

	for _, t := range spec.Tenants {
		tenantID := mustUUID(t.ID, "tenant")
		if err := st.UpsertTenant(ctx, tenantID, t.Slug, t.Name); err != nil {
			log.Fatalf("upsert tenant %s: %v", t.Slug, err)
		}
		for _, p := range t.Providers {
			enabled := true
			if p.Enabled != nil {
				enabled = *p.Enabled
			}
			maxAge := p.AuthTimeMaxAge
			if maxAge <= 0 {
				maxAge = 300
			}
			prov := &models.Provider{
				ID:             mustUUID(p.ID, "provider"),
				TenantID:       tenantID,
				Issuer:         p.Issuer,
				ClientID:       p.ClientID,
				ClientSecret:   p.ClientSecret,
				RedirectURIs:   p.RedirectURIs,
				AuthTimeMaxAge: maxAge,
				Enabled:        enabled,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}
			if err := st.UpsertProvider(ctx, prov); err != nil {
				log.Fatalf("upsert provider %s/%s: %v", t.Slug, p.Issuer, err)
			}
			log.Printf("seeded tenant=%s issuer=%s redirects=%v", t.Slug, p.Issuer, p.RedirectURIs)
		}
	}
	log.Printf("seed complete")
}
