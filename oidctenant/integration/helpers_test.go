package integration

import (
	"context"
	"io"
	"testing"
)

func countRows(t *testing.T, env *testEnv, query string, args ...any) int {
	t.Helper()
	var n int
	if err := env.store.DB().QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("countRows: %v (query=%s)", err, query)
	}
	return n
}

func ioReadAll(r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	return io.ReadAll(r)
}
