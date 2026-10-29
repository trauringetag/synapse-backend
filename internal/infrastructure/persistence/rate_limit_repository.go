package persistence

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trauringetag/synapse-backend/internal/domain"
)

// RateLimitRepository — инфраструктурная реализация порта domain.RateLimitStore
// на PostgreSQL (таблица api_rate_limits). Вся работа с БД для rate limiting
// инкапсулирована здесь: middleware (транспортный слой) не содержит SQL.
//
// Компиляционная проверка: реализация удовлетворяет порту RateLimitStore
// из домена (единственный источник правды — internal/domain/rate_limit_store.go).
var _ domain.RateLimitStore = (*RateLimitRepository)(nil)

type RateLimitRepository struct {
	pool *pgxpool.Pool
}

// NewRateLimitRepository создаёт репозиторий счётчиков лимитов запросов.
func NewRateLimitRepository(pool *pgxpool.Pool) *RateLimitRepository {
	return &RateLimitRepository{pool: pool}
}

// Increment атомарно увеличивает счётчик hits для bucket_key в текущем окне
// фиксированной длительности window и возвращает новое значение.
//
// Логика окна: window_start вычисляется как граница текущего окна, кратная
// window от Unix epoch. Если существующая запись относится к истёкшему окну
// (window_start + window <= now()), окно переустанавливается, а счётчик
// сбрасывается в 1; иначе счётчик увеличивается на 1.
func (r *RateLimitRepository) Increment(ctx context.Context, key string, window time.Duration) (int, error) {
	if r.pool == nil {
		return 0, errors.New("rate limit database is not configured")
	}
	if window < time.Second {
		return 0, errors.New("rate limit window must be at least one second")
	}
	var count int
	err := r.pool.QueryRow(ctx, `INSERT INTO api_rate_limits (bucket_key, window_start, hits) VALUES ($1, to_timestamp(floor(extract(epoch from now()) / $2) * $2), 1) ON CONFLICT (bucket_key) DO UPDATE SET window_start = CASE WHEN api_rate_limits.window_start + ($2 * interval '1 second') <= now() THEN EXCLUDED.window_start ELSE api_rate_limits.window_start END, hits = CASE WHEN api_rate_limits.window_start + ($2 * interval '1 second') <= now() THEN 1 ELSE api_rate_limits.hits + 1 END RETURNING hits`, key, int(window.Seconds())).Scan(&count)
	return count, err
}
