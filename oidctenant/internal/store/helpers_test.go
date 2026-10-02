package store

import "github.com/example/oidctenant/internal/auth"

// hashTokenHelper 让测试复用生产的 SHA-256 令牌摘要，而不是另造哈希。
func hashTokenHelper(token string) []byte {
	return auth.HashToken(token)
}
