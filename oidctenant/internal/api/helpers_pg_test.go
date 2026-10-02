package api

import (
	"io"
	"log"
	"net/url"

	"github.com/example/oidctenant/internal/auth"
)

// hashTokenPkg 让测试直接复用生产的 sid 哈希算法。
func hashTokenPkg(token string) []byte { return auth.HashToken(token) }

func urlParse(raw string) (*url.URL, error) { return url.Parse(raw) }

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }
