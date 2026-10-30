package jobs

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/trauringetag/synapse-backend/internal/domain"
)

// compile-time check: mock implements the domain port.
var _ domain.RateLimitStore = (*mockRateLimitStore)(nil)

// mockRateLimitStore — потокобезопасный мок порта domain.RateLimitStore
// для тестирования фонового воркера без PostgreSQL.
type mockRateLimitStore struct {
	mu       sync.Mutex
	calls    []time.Duration // maxWindow каждого вызова Cleanup
	cleanupN int
	err      error // если задан, Cleanup возвращает эту ошибку
}

func (m *mockRateLimitStore) Increment(_ context.Context, _ string, _ time.Duration) (int, error) {
	return 1, nil
}

func (m *mockRateLimitStore) Cleanup(_ context.Context, maxWindow time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupN++
	m.calls = append(m.calls, maxWindow)
	return m.err
}

func (m *mockRateLimitStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cleanupN
}

func (m *mockRateLimitStore) windows() []time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]time.Duration, len(m.calls))
	copy(out, m.calls)
	return out
}

// waitForBlocks блокируется до достижения store количества вызовов want
// или истечения дедлайна timeout. Возвращает true, если условие выполнено.
func waitForBlocks(t *testing.T, store *mockRateLimitStore, want int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.After(timeout)
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline:
			return false
		case <-tick.C:
			if store.count() >= want {
				return true
			}
		}
	}
}

// TestCleanupWorker_Periodicity проверяет, что воркер вызывает Cleanup
// с ожидаемой периодичностью (каждый тик таймера) и передаёт корректный
// maxWindow.
func TestCleanupWorker_Periodicity(t *testing.T) {
	store := &mockRateLimitStore{}
	interval := 20 * time.Millisecond
	maxWindow := time.Hour

	w := NewRateLimitCleanupWorker(store, interval, maxWindow)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	// За ~5 интервалов воркер должен вызвать Cleanup не менее 3 раз
	// (допускаем погрешность планировщика).
	if !waitForBlocks(t, store, 3, 2*time.Second) {
		cancel()
		t.Fatalf("Cleanup вызван %d раз(а), ожидалось >= 3 за ~5 интервалов по %s", store.count(), interval)
	}

	for i, got := range store.windows() {
		if got != maxWindow {
			t.Errorf("вызов #%d: maxWindow = %v, ожидается %v", i+1, got, maxWindow)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("воркер не завершился после отмены контекста")
	}
}

// TestCleanupWorker_GracefulStop проверяет, что воркер корректно
// останавливается при отмене контекста: Run возвращается, новых вызовов
// Cleanup после остановки нет.
func TestCleanupWorker_GracefulStop(t *testing.T) {
	store := &mockRateLimitStore{}
	w := NewRateLimitCleanupWorker(store, 10*time.Millisecond, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	// Даём несколько тиков состояться.
	if !waitForBlocks(t, store, 2, 2*time.Second) {
		cancel()
		t.Fatal("Cleanup не был вызван ни разу до остановки воркера")
	}

	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run не вернулся в разумный срок после cancel()")
	}

	// После завершения воркера новые вызовы недопустимы.
	n := store.count()
	time.Sleep(100 * time.Millisecond) // ~10 интервалов
	if got := store.count(); got != n {
		t.Errorf("после отмены контекста число вызовов выросло с %d до %d — воркер не остановился", n, got)
	}
}

// TestCleanupWorker_NotStartedWhenContextCanceled проверяет, что Run сразу
// возвращается на уже отменённом контексте и не обращается к хранилищу.
func TestCleanupWorker_NotStartedWhenContextCanceled(t *testing.T) {
	store := &mockRateLimitStore{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	w := NewRateLimitCleanupWorker(store, time.Millisecond, time.Hour)
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run не вернулся на уже отменённом контексте")
	}
	if n := store.count(); n != 0 {
		t.Errorf("Cleanup вызван %d раз(а) на отменённом контексте, ожидалось 0", n)
	}
}

// TestCleanupWorker_ContinuesOnError проверяет, что ошибка Cleanup
// не останавливает воркер — следующий тик выполняется как обычно.
func TestCleanupWorker_ContinuesOnError(t *testing.T) {
	store := &mockRateLimitStore{err: errors.New("db down")}
	w := NewRateLimitCleanupWorker(store, 10*time.Millisecond, time.Hour)
	w.logf = func(string, ...any) {} // заглушаем логирование ошибок в тесте

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	if !waitForBlocks(t, store, 3, 2*time.Second) {
		t.Fatalf("после ошибки Cleanup воркер остановился: вызовов %d, ожидалось >= 3", store.count())
	}
}

// TestNewRateLimitCleanupWorker_Defaults проверяет подмену некорректных
// параметров безопасными значениями по умолчанию.
func TestNewRateLimitCleanupWorker_Defaults(t *testing.T) {
	store := &mockRateLimitStore{}
	w := NewRateLimitCleanupWorker(store, 0, -time.Second)
	if w.interval != time.Hour {
		t.Errorf("interval = %v, ожидается значение по умолчанию %v", w.interval, time.Hour)
	}
	if w.maxWindow != time.Hour {
		t.Errorf("maxWindow = %v, ожидается значение по умолчанию %v", w.maxWindow, time.Hour)
	}
}
