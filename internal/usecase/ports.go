package usecase

import (
	"github.com/trauringetag/synapse-backend/internal/domain"
)

// Порты репозиториев объявлены во внутреннем круге — пакете internal/domain
// (Clean Architecture: источник правды для контрактов хранилища — domain/ports.go).
// Здесь оставлены только type-алиасы для обратной совместимости: старый код,
// тесты и моки, ссылающиеся на usecase.UserRepository / usecase.TokenRepository,
// продолжают работать без изменений, поскольку алиас — это тот же самый тип.
//
// Алиасы для обратной совместимости (будут удалены в следующем мажорном релизе).
// Новый код должен ссылаться напрямую на domain.UserRepository и
// domain.RefreshTokenRepository.
type (
	// UserRepository — алиас порта хранилища пользователей из домена.
	// Инфраструктурная реализация — internal/infrastructure/persistence.UserRepository.
	UserRepository = domain.UserRepository

	// TokenRepository — алиас порта хранилища refresh-токенов из домена
	// (каноническое имя в domain — RefreshTokenRepository).
	// Инфраструктурная реализация — internal/infrastructure/persistence.TokenRepository.
	TokenRepository = domain.RefreshTokenRepository
)
