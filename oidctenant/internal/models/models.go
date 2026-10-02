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
	// DeviceLabel 是不含任何令牌内容的展示标签（如截断后的 User-Agent）。
	DeviceLabel string
	CreatedAt   time.Time
	LastSeenAt  time.Time
	// LastIP 仅用于展示最近活动地址。
	LastIP    string
	ExpiresAt time.Time
	// RevokedAt.Valid 表示已撤销（活跃 = 未撤销且未过期）。
	RevokedAt     NullTime
	RevokedReason NullString
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
