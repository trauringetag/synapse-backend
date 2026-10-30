package persistence

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupTestPool подключается к PostgreSQL из DATABASE_URL (или локальных
// POSTGRES_* переменных окружения, как в .env). Если база недоступна —
// тест пропускается (не каждый CI/рабочее окружение имеет PostgreSQL).
func setupTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		user := getenvDefault("POSTGRES_USER", "synapse-default-user")
		pass := getenvDefault("POSTGRES_PASSWORD", "synapse-default-password")
		host := getenvDefault("POSTGRES_HOST", "localhost")
		port := getenvDefault("POSTGRES_PORT", "5432")
		name := getenvDefault("POSTGRES_DB", "synapse-default-db")
		url = "postgres://" + user + ":" + pass + "@" + host + ":" + port + "/" + name + "?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("pgxpool.New: база недоступна, интеграционный тест пропущен: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("PostgreSQL недоступен (%s), интеграционный тест пропущен: %v", url, err)
	}
	t.Cleanup(pool.Close)

	// Гарантируем существование таблицы (DDL идемпотентен, см. init.sql).
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS api_rate_limits (
		bucket_key TEXT PRIMARY KEY,
		window_start TIMESTAMPTZ NOT NULL,
		hits INTEGER NOT NULL CHECK (hits > 0),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`); err != nil {
		t.Fatalf("не удалось создать таблицу api_rate_limits: %v", err)
	}
	return pool
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// TestRateLimitRepository_Cleanup — интеграционный тест: вставляет запись с
// window_start в далёком прошлом и запись с текущим window_start, вызывает
// Cleanup и проверяет, что устаревшая запись удалена, а актуальная осталась.
func TestRateLimitRepository_Cleanup(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewRateLimitRepository(pool)

	ctx := context.Background()
	suffix := time.Now().UnixNano()
	staleKey := fmt.Sprintf("test:cleanup:stale:%d", suffix)
	freshKey := fmt.Sprintf("test:cleanup:fresh:%d", suffix)

	const maxWindow = time.Hour // 3600 секунд — максимальное окно в системе

	// Очистка на случай повторного запуска теста.
	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM api_rate_limits WHERE bucket_key = $1 OR bucket_key = $2`, staleKey, freshKey)
	}()
	_, _ = pool.Exec(ctx, `DELETE FROM api_rate_limits WHERE bucket_key = $1 OR bucket_key = $2`, staleKey, freshKey)

	// 1. Устаревшая запись: окно началось 10 часов назад (заведомо истекло).
	var staleWindowStart time.Time
	if err := pool.QueryRow(ctx, `SELECT now() - interval '10 hours'`).Scan(&staleWindowStart); err != nil {
		t.Fatalf("вычисление window_start устаревшей записи: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO api_rate_limits (bucket_key, window_start, hits) VALUES ($1, $2, 5)`, staleKey, staleWindowStart); err != nil {
		t.Fatalf("вставка устаревшей записи: %v", err)
	}

	// 2. Актуальная запись: окно началось сейчас.
	var freshWindowStart time.Time
	if err := pool.QueryRow(ctx, `SELECT now()`).Scan(&freshWindowStart); err != nil {
		t.Fatalf("вычисление window_start актуальной записи: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO api_rate_limits (bucket_key, window_start, hits) VALUES ($1, $2, 1)`, freshKey, freshWindowStart); err != nil {
		t.Fatalf("вставка актуальной записи: %v", err)
	}

	// 3. Вызов Cleanup — метод под тест.
	if err := repo.Cleanup(ctx, maxWindow); err != nil {
		t.Fatalf("Cleanup вернул ошибку: %v", err)
	}

	// 4. Проверяем результат.
	existsStale := rowExists(t, pool, ctx, staleKey)
	existsFresh := rowExists(t, pool, ctx, freshKey)

	if existsStale {
		t.Error("устаревшая запись (окно истекло 9 часов назад) не была удалена методом Cleanup")
	}
	if !existsFresh {
		t.Error("актуальная запись (текущее окно) ошибочно удалена методом Cleanup")
	}
}

// TestRateLimitRepository_Cleanup_Boundary проверяет границу: запись, чьё
// окно истекло ровно maxWindow назад (window_start + maxWindow == now-ish),
// удаляется; запись с окном, истекающим в будущем — остаётся.
func TestRateLimitRepository_Cleanup_Boundary(t *testing.T) {
	pool := setupTestPool(t)
	repo := NewRateLimitRepository(pool)

	ctx := context.Background()
	suffix := time.Now().UnixNano()
	expiredKey := fmt.Sprintf("test:cleanup:expired:%d", suffix)
	activeKey := fmt.Sprintf("test:cleanup:active:%d", suffix)

	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM api_rate_limits WHERE bucket_key = $1 OR bucket_key = $2`, expiredKey, activeKey)
	}()

	const maxWindow = time.Hour

	// Окно завершилось чуть больше часа назад => заведомо истекло.
	if _, err := pool.Exec(ctx, `INSERT INTO api_rate_limits (bucket_key, window_start, hits) VALUES ($1, now() - interval '75 minutes', 3)`, expiredKey); err != nil {
		t.Fatalf("вставка истёкшей записи: %v", err)
	}
	// Окно ещё активно (началось 10 минут назад, закончится через 50 минут).
	if _, err := pool.Exec(ctx, `INSERT INTO api_rate_limits (bucket_key, window_start, hits) VALUES ($1, now() - interval '10 minutes', 2)`, activeKey); err != nil {
		t.Fatalf("вставка активной записи: %v", err)
	}

	if err := repo.Cleanup(ctx, maxWindow); err != nil {
		t.Fatalf("Cleanup вернул ошибку: %v", err)
	}

	if rowExists(t, pool, ctx, expiredKey) {
		t.Error("запись с истёкшим окном (75 мин > 60 мин maxWindow) не удалена")
	}
	if !rowExists(t, pool, ctx, activeKey) {
		t.Error("запись с активным окном удалена — Cleanup удаляет слишком агрессивно")
	}
}

// TestRateLimitRepository_Cleanup_Validation проверяет валидацию аргументов
// без обращения к базе.
func TestRateLimitRepository_Cleanup_Validation(t *testing.T) {
	var nilRepo RateLimitRepository // pool == nil
	if err := nilRepo.Cleanup(context.Background(), time.Hour); err == nil {
		t.Error("ожидалась ошибка при отсутствии пула соединений")
	}

	pool := setupTestPool(t)
	repo := NewRateLimitRepository(pool)
	if err := repo.Cleanup(context.Background(), 500*time.Millisecond); err == nil {
		t.Error("ожидалась ошибка при maxWindow меньше одной секунды")
	}
}

func rowExists(t *testing.T, pool *pgxpool.Pool, ctx context.Context, key string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM api_rate_limits WHERE bucket_key = $1)`, key).Scan(&exists); err != nil {
		t.Fatalf("проверка существования записи %q: %v", key, err)
	}
	return exists
}
