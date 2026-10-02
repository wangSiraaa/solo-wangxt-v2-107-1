// Package auth 提供与传输/协议无关的安全原语：
// state/nonce/PKCE 随机值、会话令牌及其哈希、redirect_uri 白名单校验。
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
	"unicode"
)

// RandomToken 返回 nBytes 字节熵的 URL 安全随机字符串。
func RandomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// State 生成 OAuth state（≥128 bit 熵）。
func State() (string, error) { return RandomToken(32) }

// Nonce 生成 OIDC nonce（≥128 bit 熵）。
func Nonce() (string, error) { return RandomToken(32) }

// PKCEVerifier 生成 RFC 7636 code_verifier（43–128 字符的随机串，32 字节 base64url 为 43 字符）。
func PKCEVerifier() (string, error) { return RandomToken(32) }

// SessionToken 返回不透明会话令牌（256 bit 熵）。
func SessionToken() (string, error) { return RandomToken(32) }

// LinkToken 返回账号关联会话的不透明令牌（256 bit 熵）。
func LinkToken() (string, error) { return RandomToken(32) }

// HashToken 返回令牌的 SHA-256 摘要用于数据库存储/恒定时间比较。
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// EqualToken 以恒定时间方式比较令牌摘要。
func EqualToken(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// RedirectURIAllowed 对候选回调地址做精确白名单匹配。
// 故意不做前缀/后缀/通配匹配，避免 open redirect 与回调注入。
func RedirectURIAllowed(allowed []string, candidate string) bool {
	for _, a := range allowed {
		if a == candidate {
			return true
		}
	}
	return false
}

// maxDeviceLabelRunes 限制设备标签长度；标签只是展示摘要，不需要任意长输入。
const maxDeviceLabelRunes = 120

// DeviceLabel 从 User-Agent 生成“不含令牌内容”的设备展示标签。
//
// 处理原则：
//   - 只做脱敏/截断（去掉控制字符、折叠空白），不做 HTML 转义（输出是 JSON）；
//   - 不接受调用方传入任意标签，标签永远派生自请求头这一受限来源；
//   - sid / 授权码 / ID token 从不进入该函数，因此标签不可能携带凭据；
//   - 空 UA 给稳定的占位名，避免列表出现空白设备。
func DeviceLabel(userAgent string) string {
	var b strings.Builder
	lastSpace := false
	for _, r := range userAgent {
		switch {
		case unicode.IsControl(r):
			// 控制字符（含 \r\n）折叠为空格，杜绝日志/列表注入与换行伪造。
			r = ' '
			fallthrough
		case unicode.IsSpace(r):
			if !lastSpace && b.Len() > 0 {
				b.WriteRune(' ')
				lastSpace = true
			}
		default:
			b.WriteRune(r)
			lastSpace = false
		}
	}
	label := strings.TrimSpace(b.String())
	if label == "" {
		return "Unknown device"
	}
	if runes := []rune(label); len(runes) > maxDeviceLabelRunes {
		label = strings.TrimSpace(string(runes[:maxDeviceLabelRunes]))
	}
	return label
}
