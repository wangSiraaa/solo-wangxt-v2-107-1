// Package api 实现 OIDC 登录、会话与账号关联的 HTTP 接口。
package api

import (
	"errors"
	"net/http"
)

// ErrorType 是对客户端暴露的稳定错误类别。
type ErrorType string

const (
	// ErrAuthn 认证失败：state/nonce/PKCE/签名/受众/令牌交换等任何环节未通过。
	ErrAuthn ErrorType = "authentication_failed"
	// ErrTenantForbidden 租户未授权：租户未启用该 issuer，或身份不属于目标租户。
	ErrTenantForbidden ErrorType = "tenant_unauthorized"
	// ErrBindingConflict 绑定冲突：身份已关联到其他成员，或关联会话状态不允许。
	ErrBindingConflict ErrorType = "binding_conflict"
	// ErrInvalidRequest 请求参数非法或回调地址不在白名单。
	ErrInvalidRequest ErrorType = "invalid_request"
	// ErrReauthRequired 关联账号时身份未在规定时间内重新认证。
	ErrReauthRequired ErrorType = "reauthentication_required"
	// ErrNotFound 目标资源不存在或不属于调用者（设备会话枚举防护：统一为 404）。
	ErrNotFound ErrorType = "not_found"
)

// APIError 携带 HTTP 状态、稳定错误码与可展示的简短描述。
// 描述中绝不包含 ID token、access token、code 等敏感材料。
type APIError struct {
	Status  int       `json:"-"`
	Type    ErrorType `json:"error"`
	Message string    `json:"message"`
}

func (e *APIError) Error() string { return string(e.Type) + ": " + e.Message }

func newAPIError(status int, t ErrorType, msg string) *APIError {
	return &APIError{Status: status, Type: t, Message: msg}
}

func authn(msg string) *APIError {
	return newAPIError(http.StatusUnauthorized, ErrAuthn, msg)
}

func tenantForbidden(msg string) *APIError {
	return newAPIError(http.StatusForbidden, ErrTenantForbidden, msg)
}

func conflict(msg string) *APIError {
	return newAPIError(http.StatusConflict, ErrBindingConflict, msg)
}

func badRequest(msg string) *APIError {
	return newAPIError(http.StatusBadRequest, ErrInvalidRequest, msg)
}

func reauthRequired(msg string) *APIError {
	return newAPIError(http.StatusUnauthorized, ErrReauthRequired, msg)
}

func notFound(msg string) *APIError {
	return newAPIError(http.StatusNotFound, ErrNotFound, msg)
}

func asAPIError(err error) (*APIError, bool) {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}
