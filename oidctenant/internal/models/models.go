// Package models 定义持久化层的数据结构。
package models

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// NullString / NullTime 复用标准库可空标量类型，便于 pgx 直接互操作。
type (
	NullString = sql.NullString
	NullTime   = sql.NullTime
)

type Tenant struct {
	ID        uuid.UUID
	Slug      string
	Name      string
	CreatedAt time.Time
}

type Provider struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	Issuer         string
	ClientID       string
	ClientSecret   string
	RedirectURIs   []string
	AuthTimeMaxAge int
	Enabled        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type Member struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	DisplayName string
	CreatedAt   time.Time
}

type Identity struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	MemberID      uuid.UUID
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
}

type AuthRequest struct {
	State        string
	Kind         string
	TenantID     uuid.UUID
	IDPID        uuid.UUID
	Nonce        string
	PKCEVerifier string
	ReturnTo     string
	LinkToken    NullString
	SessionID    *uuid.UUID
	CreatedAt    time.Time
}

type Session struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	MemberID  uuid.UUID
	TokenHash []byte
	// DisplayLabel 是仅供设备列表展示的标签（来自 User-Agent 的脱敏摘要），
	// 绝不包含 sid、授权码、ID/access token 等任何凭据内容。
	DisplayLabel   string
	CreatedAt      time.Time
	LastActivityAt time.Time
	ExpiresAt      time.Time
	// RevokedAt 非空表示该设备会话已被撤销（永久、幂等状态）。
	RevokedAt NullTime
}

type LinkSession struct {
	Token          string
	TenantID       uuid.UUID
	AnchorMemberID uuid.UUID
	SessionID      uuid.UUID
	TargetIDPID    uuid.UUID
	AIssuer        string
	ASubject       string
	AAuthTime      NullTime
	BIssuer        string
	BSubject       string
	BEmail         string
	BAuthTime      NullTime
	BIDPID         uuid.UUID
	BState         string
	Status         string
	ExpiresAt      time.Time
}
