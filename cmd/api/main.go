package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/trauringetag/synapse-backend/docs"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/database"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/jobs"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/persistence"
	auth "github.com/trauringetag/synapse-backend/internal/infrastructure/security"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/transport"
	"github.com/trauringetag/synapse-backend/internal/usecase"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Конфигурация: %v", err)
	}

	// Корневой контекст приложения: отменяется при получении SIGINT/SIGTERM.
	// Используется для graceful shutdown HTTP-сервера и фоновых воркеров.
	rootCtx, rootCancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer rootCancel()

	ctx, cancel := context.WithTimeout(rootCtx, 30*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("База данных: %v", err)
	}
	defer pool.Close()

	users := persistence.NewUserRepository(pool)
	tokens := persistence.NewTokenRepository(pool)
	// Реализация порта domain.RateLimitStore: вся работа с БД для лимитов
	// запросов инкапсулирована в инфраструктурном слое (репозитории),
	// middleware получает только интерфейс.
	rateLimitRepo := persistence.NewRateLimitRepository(pool)

	// Фоновый воркер очистки api_rate_limits: периодически удаляет записи,
	// чьё окно заведомо истекло (window_start + maxWindow <= now()), чтобы
	// таблица не росла бесконечно. Завершается при отмене rootCtx
	// (graceful shutdown по SIGINT/SIGTERM).
	cleanupWorker := jobs.NewRateLimitCleanupWorker(
		rateLimitRepo,
		cfg.RateLimitCleanupInterval,
		time.Duration(cfg.RateLimitMaxWindowSeconds)*time.Second,
	)
	go cleanupWorker.Run(rootCtx)

	// Слой use-case собирается здесь (Composition Root): сценарии получают
	// репозитории и сервисы безопасности. HTTP-обработчики знают только
	// интерфейсы usecase.AuthUseCase / usecase.UserUseCase.
	hasher := auth.NewBcryptHasher()
	jwtService := auth.NewJWTService(cfg)
	csrfService := auth.NewCSRFService(cfg)
	authUC := usecase.NewAuthUseCase(users, tokens, hasher, jwtService, csrfService, cfg.AdminRegisterToken)
	userUC := usecase.NewUserUseCase(users, tokens, hasher)

	handler := router.New(cfg, authUC, userUC, users, rateLimitRepo, docs.OpenAPI)

	srv := &http.Server{
		Addr:              ":" + cfg.AppPort,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("Прослушивание на: %s (env=%s)", cfg.AppPort, cfg.AppEnv)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	// Ждём SIGINT/SIGTERM (rootCtx отменяется signal.NotifyContext), затем
	// корректно останавливаем HTTP-сервер. Фоновый воркер очистки завершается
	// сам при отмене rootCtx (см. cleanupWorker.Run).
	<-rootCtx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
}
