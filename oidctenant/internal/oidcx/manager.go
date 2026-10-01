// Package oidcx 基于 coreos/go-oidc v3 与 golang.org/x/oauth2 封装 OIDC 操作：
// 发现文档拉取、ID token 校验（签名、issuer、受众、过期、nonce、azp）、
// 授权码交换。Provider 按 issuer 缓存；go-oidc 内部的 JWKS keyring 会在遇到
// 未知 kid 时自动重新拉取，因此 IdP 轮换签名密钥对调用方透明。
package oidcx

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/example/oidctenant/internal/models"
)

const httpTimeout = 15 * time.Second

// Claims 是业务依赖的已核实声明子集。
type Claims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	// AuthTime 是 IdP 报告的最终用户认证时间（OIDC auth_time），无声明时为零值。
	AuthTime time.Time
	// Name 仅用作展示名候选，不参与身份判定。
	Name string
}

type providerEntry struct {
	provider    *gooidc.Provider
	fingerprint time.Time // 以 provider.updated_at 生成，配置变更后缓存自动失效
}

// Manager 按 issuer 缓存 *oidc.Provider，支持多租户、多 issuer。
type Manager struct {
	mu      sync.Mutex
	entries map[string]providerEntry
}

func NewManager() *Manager {
	return &Manager{entries: make(map[string]providerEntry)}
}

func (m *Manager) get(ctx context.Context, issuer string, fingerprint time.Time) (*gooidc.Provider, error) {
	m.mu.Lock()
	if e, ok := m.entries[issuer]; ok && e.fingerprint.Equal(fingerprint) {
		m.mu.Unlock()
		return e.provider, nil
	}
	m.mu.Unlock()

	discCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	p, err := gooidc.NewProvider(discCtx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", issuer, err)
	}

	m.mu.Lock()
	m.entries[issuer] = providerEntry{provider: p, fingerprint: fingerprint}
	m.mu.Unlock()
	return p, nil
}

// OAuth2Config 返回某 IdP 的 oauth2 配置。redirectURI 必须与 IdP 端注册值逐字符一致。
func (m *Manager) OAuth2Config(ctx context.Context, p *models.Provider, redirectURI string) (*oauth2.Config, error) {
	prov, err := m.get(ctx, p.Issuer, p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     prov.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       []string{gooidc.ScopeOpenID, "profile", "email"},
	}, nil
}

// Verifier 构造 ID token 校验器：
//   - 签名通过 IdP JWKS 验证，未知 kid 自动重新发现（支持密钥轮换）；
//   - issuer 必须与配置一致；
//   - audience 必须包含本客户端 client_id；
//   - 过期/生效时间由 gooidc 校验；
//   - nonce 与服务端 auth_request 中保存的值逐字节比较。
func (m *Manager) Verifier(ctx context.Context, p *models.Provider, nonce string) (*Verifier, error) {
	prov, err := m.get(ctx, p.Issuer, p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	v := prov.Verifier(&gooidc.Config{
		ClientID:                   p.ClientID,
		SkipClientIDCheck:          false,
		SkipIssuerCheck:            false,
		SkipExpiryCheck:            false,
		InsecureSkipSignatureCheck: false,
	})
	return &Verifier{v: v, nonce: nonce, clientID: p.ClientID}, nil
}

// Verifier 对单次授权定制 nonce / azp 校验。
type Verifier struct {
	v        *gooidc.IDTokenVerifier
	nonce    string
	clientID string
}

// Verify 执行完整校验。返回错误的信息不含令牌内容。
func (ver *Verifier) Verify(ctx context.Context, rawIDToken string) (*Claims, error) {
	tok, err := ver.v.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, classifyVerifyError(err)
	}
	if tok.Nonce != ver.nonce {
		return nil, NewVerifyError(KindNonce, "id token nonce does not match the authorization request")
	}

	var c struct {
		Email         string    `json:"email"`
		EmailVerified boolOrStr `json:"email_verified"`
		AuthTime      *unixTime `json:"auth_time"`
		Name          string    `json:"name"`
		PreferredName string    `json:"preferred_username"`
		AZP           string    `json:"azp"`
	}
	if err := tok.Claims(&c); err != nil {
		return nil, NewVerifyError(KindClaims, "failed to decode id token claims")
	}
	if c.AZP != "" && c.AZP != ver.clientID {
		return nil, NewVerifyError(KindAudience, "id token azp does not match the relying party client")
	}
	if tok.Subject == "" {
		return nil, NewVerifyError(KindClaims, "id token missing subject")
	}

	claims := &Claims{
		Issuer:        tok.Issuer,
		Subject:       tok.Subject,
		Email:         c.Email,
		EmailVerified: bool(c.EmailVerified),
		Name:          firstNonEmpty(c.Name, c.PreferredName),
	}
	if c.AuthTime != nil {
		claims.AuthTime = c.AuthTime.Time
	}
	return claims, nil
}

// unixTime 解码 OIDC 的数字日期声明（auth_time / iat / exp 均为 Unix 秒数）。
type unixTime struct {
	time.Time
}

func (t *unixTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	sec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	t.Time = time.Unix(sec, 0).UTC()
	return nil
}

// ExchangeAndVerify 用授权码 + PKCE verifier 交换令牌并校验 ID token。
// 错误文本绝不回显令牌内容。
func (m *Manager) ExchangeAndVerify(ctx context.Context, p *models.Provider,
	cfg *oauth2.Config, verifier *Verifier, code, pkceVerifier string) (*Claims, *oauth2.Token, error) {

	exCtx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	// oauth2 包内部将 S256 verifier 放入 token 请求（PKCE）。
	tok, err := cfg.Exchange(exCtx, code,
		oauth2.SetAuthURLParam("code_verifier", pkceVerifier))
	if err != nil {
		return nil, nil, classifyExchangeError(err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, nil, NewVerifyError(KindNoIDToken, "token response did not contain an id_token")
	}
	claims, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, nil, err
	}
	return claims, tok, nil
}

// AuthCodeURL 生成 IdP 授权地址，注入 nonce、PKCE challenge；
// forceLogin 时要求 IdP 重新交互式认证（关联账号时强制两个身份各自重认证）。
func AuthCodeURL(cfg *oauth2.Config, state, nonce, challenge, challengeMethod string,
	forceLogin bool, extra map[string]string) string {

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", challengeMethod),
	}
	if forceLogin {
		// prompt=login 强制重新认证；max_age=0 是等价的 OIDC 表达，二者都带上。
		opts = append(opts,
			oauth2.SetAuthURLParam("prompt", "login"),
			oauth2.SetAuthURLParam("max_age", "0"),
		)
	}
	for k, v := range extra {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	return cfg.AuthCodeURL(state, opts...)
}

// boolOrStr 容忍 IdP 把 email_verified 编码成字符串 "true"。
type boolOrStr bool

func (b *boolOrStr) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	switch strings.ToLower(s) {
	case "true":
		*b = true
	case "false", "":
		*b = false
	default:
		*b = false
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
