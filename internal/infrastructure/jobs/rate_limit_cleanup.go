package jobs

import (
	"context"
	"log"
	"time"

	"github.com/trauringetag/synapse-backend/internal/domain"
)

// RateLimitCleanupWorker — фоновый воркер, периодически удаляющий устаревшие
// записи из хранилища лимитов запросов (таблица api_rate_limits).
//
// Без такой очистки таблица растёт бесконечно: Increment только обновляет
// строку при истечении окна, но никогда не удаляет её, поэтому записи для
// одноразовых или устаревших IP/ключей остаются навсегда.
//
// Воркер запускается как goroutine методом Run и корректно завершается при
// отмене переданного контекста (graceful shutdown): тикер останавливается,
// функция возвращается.
type RateLimitCleanupWorker struct {
	store     domain.RateLimitStore
	interval  time.Duration // периодичность запуска Cleanup
	maxWindow time.Duration // максимально возможное окно в системе (порог устаревания)
	logf      func(format string, args ...any)
}

// NewRateLimitCleanupWorker создаёт воркер очистки.
// interval — как часто запускать Cleanup (например, 1 час);
// maxWindow — максимальная длительность окна лимитов в системе (из конфига),
// записи старше порога window_start + maxWindow <= now() удаляются.
// Некорректные (неположительные) значения заменяются безопасными
// значениями по умолчанию (1 час), чтобы воркер не устроил busy-loop.
func NewRateLimitCleanupWorker(store domain.RateLimitStore, interval, maxWindow time.Duration) *RateLimitCleanupWorker {
	if interval <= 0 {
		interval = time.Hour
	}
	if maxWindow <= 0 {
		maxWindow = time.Hour
	}
	return &RateLimitCleanupWorker{
		store:     store,
		interval:  interval,
		maxWindow: maxWindow,
		logf:      log.Printf,
	}
}

// Run запускает цикл очистки и блокирует goroutine до отмены контекста ctx.
// На каждом тике вызывается store.Cleanup(ctx, maxWindow); ошибки Cleanup
// логируются, но не останавливают воркер (следующий тик попробует снова).
// Метод возвращает управление сразу после отмены ctx (graceful shutdown).
func (w *RateLimitCleanupWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Сигнал остановки: завершаемся без новых обращений к БД.
			return
		case <-ticker.C:
			if err := w.store.Cleanup(ctx, w.maxWindow); err != nil {
				w.logf("rate limit cleanup: ошибка очистки api_rate_limits: %v", err)
				continue
			}
			w.logf("rate limit cleanup: устаревшие записи api_rate_limits удалены (maxWindow=%s)", w.maxWindow)
		}
	}
}
