package domain

import (
	"context"
	"time"
)

// RateLimitStore — порт для хранения счётчиков ограничения частоты запросов
// (Clean Architecture: порты объявляются во внутреннем круге, в домене).
// Инфраструктурная реализация — internal/infrastructure/persistence.RateLimitRepository.
// Транспортный слой (middleware) зависит только от этого интерфейса и не
// содержит прямых SQL-запросов.
//
// Методы:
//   - Increment — атомарно увеличивает счётчик для ключа в текущем окне
//     фиксированной длительности window и возвращает новое значение счётчика.
//     Окна привязаны к «эпохе» (Unix epoch), поэтому все экземпляры сервиса
//     используют одинаковые границы окон без синхронизации.
type RateLimitStore interface {
	// Increment увеличивает счетчик для ключа и возвращает новое значение.
	Increment(ctx context.Context, key string, window time.Duration) (int, error)
}
