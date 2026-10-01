-- 0001_init.sql
-- OIDC 多租户登录 / 账号关联
--
-- 核心原则：业务身份 = (tenant_id, issuer, subject)。
-- email 仅用于展示，不参与任何账号匹配，因此不同租户下相同邮箱天然隔离。

CREATE TABLE tenants (
    id          uuid PRIMARY KEY,
    slug        text NOT NULL UNIQUE,
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE identity_providers (
    id                  uuid PRIMARY KEY,
    tenant_id           uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    issuer              text NOT NULL,
    client_id           text NOT NULL,
    client_secret       text NOT NULL,
    -- 允许的 redirect_uri 白名单（精确匹配，不做前缀匹配）
    redirect_uris       text[] NOT NULL DEFAULT '{}',
    -- 关联账号时要求 provider 声明在多长时间内完成过强认证（秒）
    auth_time_max_age   integer NOT NULL DEFAULT 300,
    enabled             boolean NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, issuer)
);

CREATE TABLE members (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_members_tenant ON members (tenant_id);

CREATE TABLE identities (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    member_id       uuid NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    issuer          text NOT NULL,
    subject         text NOT NULL,
    -- 邮箱仅作展示，故意不加 UNIQUE 约束
    email           text NOT NULL DEFAULT '',
    email_verified  boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- 业务身份锚点：同一租户内 (issuer, subject) 全局唯一
    UNIQUE (tenant_id, issuer, subject)
);
-- 仅为展示页按邮箱检索使用
CREATE INDEX idx_identities_email ON identities (tenant_id, email);

-- 进行中的 OIDC 授权请求（state / nonce / PKCE verifier 的服务端存储）
CREATE TABLE auth_requests (
    state          text PRIMARY KEY,
    kind           text NOT NULL CHECK (kind IN ('login', 'link_a', 'link_b')),
    tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    idp_id         uuid NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    nonce          text NOT NULL,
    pkce_verifier  text NOT NULL,
    return_to      text NOT NULL DEFAULT '/',
    -- link 场景下的关联会话
    link_token     text,
    session_id     uuid,
    created_at     timestamptz NOT NULL DEFAULT now(),
    consumed_at    timestamptz
);
CREATE INDEX idx_authreq_created ON auth_requests (created_at);

CREATE TABLE sessions (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    member_id   uuid NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    token_hash  bytea NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz
);
CREATE INDEX idx_sessions_member ON sessions (member_id);

-- 账号关联会话：要求两个身份各自重新认证（两条 leg）
CREATE TABLE link_sessions (
    token            text PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    anchor_member_id uuid NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    session_id       uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    target_idp_id    uuid NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    a_issuer         text NOT NULL,
    a_subject        text NOT NULL,
    a_auth_time      timestamptz,
    b_issuer         text NOT NULL DEFAULT '',
    b_subject        text NOT NULL DEFAULT '',
    b_email          text NOT NULL DEFAULT '',
    b_auth_time      timestamptz,
    b_idp_id         uuid REFERENCES identity_providers(id) ON DELETE CASCADE,
    b_state          text NOT NULL DEFAULT '',
    status           text NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'completed', 'consumed')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    completed_at     timestamptz
);
CREATE INDEX idx_linksessions_status ON link_sessions (status, expires_at);
