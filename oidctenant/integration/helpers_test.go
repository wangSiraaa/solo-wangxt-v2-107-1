package integration

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/uuid"
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

// marshalForTest 把任意值序列化为 JSON 字符串，供泄漏断言使用。
func marshalForTest(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// mustUUID 解析 UUID 字符串，测试断言用。
func mustUUID(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parse uuid %q: %v", s, err)
	}
	return id
}
