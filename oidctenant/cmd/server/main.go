// Command oidctenant 启动多租户 OIDC 登录/账号关联 API。
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/oidctenant/internal/api"
	"github.com/example/oidctenant/internal/config"
	"github.com/example/oidctenant/internal/db"
	"github.com/example/oidctenant/internal/oidcx"
	"github.com/example/oidctenant/internal/store"
)

func main() {
	logger := log.New(os.Stdout, "oidctenant ", log.LstdFlags|log.LUTC)

	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	database, err := db.Connect(ctx, cfg.DatabaseURL)
	cancel()
	if err != nil {
		logger.Fatalf("db connect: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database); err != nil {
		logger.Fatalf("migrate: %v", err)
	}

	st := store.New(database)
	om := oidcx.NewManager()
	srv := api.NewServer(cfg, st, om, logger)

	stop := make(chan struct{})
	go cleanupLoop(context.Background(), st, cfg.CleanupInterval, cfg.AuthRequestTTL, logger, stop)

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Printf("listening on %s (base url %s)", cfg.Addr, cfg.BaseURL)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Printf("shutting down")
	close(stop)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Printf("shutdown: %v", err)
	}
}

// cleanupLoop 周期性删除过期的 auth_request 行，防止 state 表无限增长。
func cleanupLoop(ctx context.Context, st *store.Store, interval, ttl time.Duration,
	logger *log.Logger, stop chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			if err := st.DeleteExpiredAuthRequests(ctx, time.Now().Add(-ttl)); err != nil {
				logger.Printf("cleanup auth_requests: %v", err)
			}
		}
	}
}
