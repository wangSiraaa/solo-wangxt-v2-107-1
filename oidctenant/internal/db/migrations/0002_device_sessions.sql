-- 0002_device_sessions.sql
-- 设备会话管理
--
-- 在不透明 sid 会话之上补充“设备视角”的展示信息与活跃/已撤销状态：
--   - device_label 只保存展示标签（User-Agent 截断），绝不保存 sid/授权码/身份令牌；
--   - last_seen_at 记录最近一次受保护请求；
--   - last_ip 记录展示用对端地址（不含凭据）；
--   - revoked_reason 记录撤销来源（self_logout / device_revoke / revoke_all），
--     revoked_at 已在 0001 中存在，活跃 = revoked_at IS NULL 且未过期。
-- 任何列表/日志都只暴露会话的 UUID（与 sid 不可互相推导），不暴露 token_hash。

ALTER TABLE sessions
    ADD COLUMN device_label   text NOT NULL DEFAULT '',
    ADD COLUMN last_seen_at   timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN last_ip        text NOT NULL DEFAULT '',
    ADD COLUMN revoked_reason text;

-- 成员枚举自己在当前租户的会话：按租户+成员取出，最近活跃在前。
CREATE INDEX idx_sessions_tenant_member_active
    ON sessions (tenant_id, member_id, last_seen_at DESC);
