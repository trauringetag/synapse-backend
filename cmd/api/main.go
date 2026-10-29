package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/trauringetag/synapse-backend/docs"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/database"
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
}
