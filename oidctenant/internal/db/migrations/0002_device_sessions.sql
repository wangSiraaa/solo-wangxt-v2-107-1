-- 0002_device_sessions.sql
-- 设备会话管理：
--   在不透明 sid（数据库仅存 SHA-256 哈希）之上，为每个会话补充
--   不含任何令牌内容的展示标签、创建时间与最近活动时间，
--   以支持“列出我的设备 / 撤销指定设备 / 全部设备退出”。
--
-- 活跃状态由 (revoked_at IS NULL AND expires_at > now()) 派生；
-- revoked_at 非空即“已撤销”，撤销是永久、幂等的状态位。

ALTER TABLE sessions ADD COLUMN display_label text NOT NULL DEFAULT 'Unknown device';
ALTER TABLE sessions ADD COLUMN last_activity_at timestamptz;

UPDATE sessions SET last_activity_at = created_at WHERE last_activity_at IS NULL;
ALTER TABLE sessions ALTER COLUMN last_activity_at SET NOT NULL;
ALTER TABLE sessions ALTER COLUMN last_activity_at SET DEFAULT now();

-- 设备列表按 (租户, 成员) 过滤；撤销其他设备时的归属校验同样走这组列。
CREATE INDEX idx_sessions_tenant_member ON sessions (tenant_id, member_id);
