package oidcx

import (
	"errors"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// VerifyKind 细分认证失败的原因（仅用于服务端日志/指标，不向客户端暴露细节）。
type VerifyKind string

const (
	KindSignature VerifyKind = "signature"
	KindIssuer    VerifyKind = "issuer"
	KindAudience  VerifyKind = "audience"
	KindExpired   VerifyKind = "expired"
	KindNonce     VerifyKind = "nonce"
	KindClaims    VerifyKind = "claims"
	KindNoIDToken VerifyKind = "no_id_token"
	KindExchange  VerifyKind = "token_exchange"
	KindDiscovery VerifyKind = "discovery"
	KindPKCE      VerifyKind = "pkce"
	KindMalformed VerifyKind = "malformed"
)

// VerifyError 是不包含任何敏感材料的认证失败错误。
type VerifyError struct {
	Kind VerifyKind
	Msg  string
}

func (e *VerifyError) Error() string { return string(e.Kind) + ": " + e.Msg }

// NewVerifyError 构造一个认证失败错误。
func NewVerifyError(kind VerifyKind, msg string) *VerifyError {
	return &VerifyError{Kind: kind, Msg: msg}
}

// AsVerifyError 提取 VerifyError。
func AsVerifyError(err error) (*VerifyError, bool) {
	var ve *VerifyError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}

// gooidc 的验证错误是固定的哨兵错误（errors.Is 可匹配），
// 同时部分库版本返回带文本的 error，这里两种方式都覆盖。
func classifyVerifyError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()

	var expiredErr *gooidc.TokenExpiredError
	if errors.As(err, &expiredErr) {
		return NewVerifyError(KindExpired, "id token is expired")
	}
	switch {
	case strings.Contains(msg, "oidc: id token signed with unsupported alg") ||
		strings.Contains(msg, "verify failed") ||
		strings.Contains(msg, "signature"):
		return NewVerifyError(KindSignature, "id token signature verification failed")
	case strings.Contains(msg, "issuer"):
		return NewVerifyError(KindIssuer, "id token issuer does not match discovery")
	case strings.Contains(msg, "audience") || strings.Contains(msg, "client"):
		return NewVerifyError(KindAudience, "id token audience does not match this client")
	case strings.Contains(msg, "expired") || strings.Contains(msg, "issued in the future") ||
		strings.Contains(msg, "before issued"):
		return NewVerifyError(KindExpired, "id token failed time validity checks")
	case strings.Contains(msg, "malformed") || strings.Contains(msg, "Unmarshal"):
		return NewVerifyError(KindMalformed, "id token is malformed")
	default:
		return NewVerifyError(KindClaims, "id token verification failed")
	}
}

func classifyExchangeError(err error) error {
	if err == nil {
		return nil
	}
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		// Keycloak / OAuth2 服务端对重放授权码返回 invalid_grant。
		body := strings.ToLower(string(retrieveErr.Body))
		if strings.Contains(body, "invalid_grant") ||
			strings.Contains(body, "code_verifier") || strings.Contains(body, "pkce") {
			return NewVerifyError(KindPKCE,
				"authorization code rejected (replayed or PKCE verification mismatch)")
		}
		return NewVerifyError(KindExchange, "token endpoint rejected the authorization code")
	}
	return NewVerifyError(KindExchange, "token exchange failed")
}
