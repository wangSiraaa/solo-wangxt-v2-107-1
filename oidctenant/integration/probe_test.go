package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"

	embedded "github.com/fergusstrange/embedded-postgres"

	"github.com/example/oidctenant/internal/db"
)

func formatDSN(port uint32, database string) string {
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/%s?sslmode=disable", port, database)
}

func freeTCPPort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := l.Addr().(*net.TCPAddr)
	_ = l.Close()
	return uint32(addr.Port)
}

func TestProbeEmbeddedPostgres(t *testing.T) {
	port := freeTCPPort(t)
	ep := embedded.NewDatabase(embedded.DefaultConfig().
		Port(port).
		Database("probe").
		DataPath(t.TempDir()).
		CachePath("/workspace/tools/ep-cache").
		Logger(io.Discard))
	if err := ep.Start(); err != nil {
		t.Fatalf("start embedded postgres: %v", err)
	}
	t.Cleanup(func() { _ = ep.Stop() })

	dsn := formatDSN(port, "probe")
	d, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var v int
	if err := d.QueryRow(context.Background(), "SELECT 1").Scan(&v); err != nil || v != 1 {
		t.Fatalf("select 1: %v v=%d", err, v)
	}
}
