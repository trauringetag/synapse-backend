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
// фиксированной длительности window и возвращает новое значение вместе с
// границей сброса окна (reset_at) — по ней middleware считает Retry-After.
//
// Логика окна: window_start вычисляется как граница текущего окна, кратная
// window от Unix epoch. Если существующая запись относится к истёкшему окну
// (window_start + window <= now()), окно переустанавливается, а счётчик
// сбрасывается в 1; иначе счётчик увеличивается на 1.
func (r *RateLimitRepository) Increment(ctx context.Context, key string, window time.Duration) (domain.RateLimitResult, error) {
	if r.pool == nil {
		return domain.RateLimitResult{}, errors.New("rate limit database is not configured")
	}
	if window < time.Second {
		return domain.RateLimitResult{}, errors.New("rate limit window must be at least one second")
	}
	var res domain.RateLimitResult
	err := r.pool.QueryRow(ctx, `INSERT INTO api_rate_limits (bucket_key, window_start, hits) VALUES ($1, to_timestamp(floor(extract(epoch from now()) / $2) * $2), 1) ON CONFLICT (bucket_key) DO UPDATE SET window_start = CASE WHEN api_rate_limits.window_start + ($2 * interval '1 second') <= now() THEN EXCLUDED.window_start ELSE api_rate_limits.window_start END, hits = CASE WHEN api_rate_limits.window_start + ($2 * interval '1 second') <= now() THEN 1 ELSE api_rate_limits.hits + 1 END, updated_at = NOW() RETURNING hits, window_start + ($2 * interval '1 second') AS reset_at`,
		key, int(window.Seconds())).Scan(&res.Count, &res.ResetAt)
	return res, err
}

// Reset удаляет запись счётчика для ключа (no-op, если записи нет).
// Используется политикой login_failed: успешный вход (200) сбрасывает
// счётчик неудачных попыток аутентификации для данного email/IP, поэтому
// «лимит по ошибкам» не накапливается после легитимного входа.
func (r *RateLimitRepository) Reset(ctx context.Context, key string) error {
	if r.pool == nil {
		return errors.New("rate limit database is not configured")
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM api_rate_limits WHERE bucket_key = $1`, key)
	return err
}

// Cleanup удаляет из таблицы api_rate_limits все записи, чьё окно заведомо
// истекло: window_start + maxWindow <= now(). Такие строки больше никогда не
// будут «переиспользованы» методом Increment (он всегда открывает новое окно),
// поэтому их удаление безопасно и предотвращает бесконечный рост таблицы.
//
// maxWindow — максимально возможная длительность окна в системе (например,
// 1 час для эндпоинтов регистрации). Вызывается фоновым воркером
// (internal/infrastructure/jobs.RateLimitCleanupWorker).
func (r *RateLimitRepository) Cleanup(ctx context.Context, maxWindow time.Duration) error {
	if r.pool == nil {
		return errors.New("rate limit database is not configured")
	}
	if maxWindow < time.Second {
		return errors.New("rate limit max window must be at least one second")
	}
	_, err := r.pool.Exec(ctx, `DELETE FROM api_rate_limits WHERE window_start + ($1 * interval '1 second') <= now()`, int(maxWindow.Seconds()))
	return err
}

// Release — атомарный decrement засчитанного hit в текущем окне: вызывается
// middleware при OnFailedStatus, когда запрос НЕ завершился неудачной
// аутентификацией (успешный вход, ошибка валидации и т.п. не должны тратить
// per-IP бюджет login_ip). Если после вычитания счётчик стал нулевым,
// строка удаляется — окно фактически освобождается.
//
// Метод НЕ входит в порт domain.RateLimitStore: middleware вызывает его
// через необязательный type assertion (см. releaseIncrement), что сохраняет
// совместимость с простыми реализациями хранилища (тесты, кэш).
func (r *RateLimitRepository) Release(ctx context.Context, key string, window time.Duration) error {
	if r.pool == nil {
		return errors.New("rate limit database is not configured")
	}
	if window < time.Second {
		return errors.New("rate limit window must be at least one second")
	}
	_, err := r.pool.Exec(ctx, `WITH upd AS (
		UPDATE api_rate_limits
		SET hits = hits - 1, updated_at = NOW()
		WHERE bucket_key = $1 AND hits > 0
		  AND window_start + ($2 * interval '1 second') > now()
		RETURNING hits
	)
	DELETE FROM api_rate_limits WHERE bucket_key = $1 AND NOT EXISTS (SELECT 1 FROM upd WHERE hits > 0)`,
		key, int(window.Seconds()))
	return err
}
