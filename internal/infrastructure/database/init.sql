CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE
    IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(20) NOT NULL CHECK (role IN ('user', 'admin')),
        status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
        first_name VARCHAR(255) NOT NULL,
        last_name VARCHAR(255) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW ()
    );

CREATE TABLE
    IF NOT EXISTS refresh_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
        user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        token_hash TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW ()
    );

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens (user_id);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens (token_hash);

ALTER TABLE users
ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active';

CREATE INDEX IF NOT EXISTS idx_users_role_status ON users (role, status);

-- api_rate_limits — скользящее окно rate limiter'а (SEC: защита от
-- Account-Lockout DoS и разделение лимитов между маршрутами).
--
-- Формат bucket_key: rl:<route_policy>:<version>:<hmac_sha256(id)>, например
--   rl:register:v1:<hmac(ip)>      — POST /register (per-IP);
--   rl:login_ip:v1:<hmac(ip|email)> / rl:login_failed:v1:... — POST /login
--     (неудачные попытки считаются только при 401, успешный вход сбрасывает);
--   rl:logout:v1:<hmac(ip)>        — POST /logout (изолирован от /register!).
-- Идентификаторы (IP/email/токен) хешируются HMAC-SHA256 с отдельным ключом
-- RATE_LIMIT_HMAC_KEY — в таблице НИКОГДА не хранится PII в открытом виде.
-- Строки старого формата (ip:<IP>, login:<IP>:<email> без префикса rl:)
-- устарели: новый код их не читает и не пишет; они удаляются сборщиком
-- мусора (Cleanup) по истечении окна.
CREATE TABLE
    IF NOT EXISTS api_rate_limits (
        bucket_key TEXT PRIMARY KEY,
        window_start TIMESTAMPTZ NOT NULL,
        hits INTEGER NOT NULL CHECK (hits > 0),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW ()
    );

CREATE INDEX IF NOT EXISTS idx_api_rate_limits_updated ON api_rate_limits (updated_at);

-- Идемпотентная миграция для баз, созданных до введения колонки updated_at и
-- CHECK-ограничения (старые строки не конфликтуют: SELECT/DELETE фильтруют
-- бакеты по точному ключу, а фоновый Cleanup удалит устаревшие записи).
ALTER TABLE api_rate_limits
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW ();

UPDATE api_rate_limits
SET updated_at = window_start
WHERE
    updated_at IS NULL;