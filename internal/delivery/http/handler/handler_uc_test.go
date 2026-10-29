package handler

// Сборка use-case'ов для unit-тестов HTTP-слоя. Тесты гоняют реальный слой
// use-case поверх in-memory mockStore — так проверяется и тонкость handlers,
// и корректность DI.

import (
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	auth "github.com/trauringetag/synapse-backend/internal/infrastructure/security"
	"github.com/trauringetag/synapse-backend/internal/usecase"
)

func newAuthUC(cfg *config.Config, store *mockStore) usecase.AuthUseCase {
	return usecase.NewAuthUseCase(
		store,
		store,
		auth.NewJWTService(cfg),
		auth.NewCSRFService(cfg),
		cfg.AdminRegisterToken,
	)
}

func newUserUC(store *mockStore) usecase.UserUseCase {
	return usecase.NewUserUseCase(store, store)
}
