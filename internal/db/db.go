package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Connect(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("Не удалось разобрать URL базы данных: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("Ошибка подключения к базе данных: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("База данных недоступна: %w", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS api_rate_limits (bucket_key TEXT PRIMARY KEY, window_start TIMESTAMPTZ NOT NULL, hits INTEGER NOT NULL CHECK (hits > 0), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()); CREATE INDEX IF NOT EXISTS idx_api_rate_limits_updated ON api_rate_limits(updated_at)`); err != nil {
		pool.Close()
		return nil, fmt.Errorf("Не удалось подготовить Rate-limiter: %w", err)
	}
	return pool, nil
}
