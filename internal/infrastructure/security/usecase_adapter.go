package auth

import (
	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	"github.com/trauringetag/synapse-backend/internal/usecase"
)

// JWTService — инфраструктурная адаптация выпуска/разбора JWT-пар под порт
// usecase.TokenIssuer. Благодаря ей слой use-case не зависит от config и
// формата токенов: HTTP-слой и сценарии общаются только через интерфейс.
type JWTService struct {
	cfg *config.Config
}

func NewJWTService(cfg *config.Config) *JWTService {
	return &JWTService{cfg: cfg}
}

var _ usecase.TokenIssuer = (*JWTService)(nil)

// IssuePair выпускает новую пару access/refresh и преобразует инфраструктурный
// тип Pair в DTO слоя use-case (TokenPair).
func (s *JWTService) IssuePair(userID uuid.UUID, email, role string) (*usecase.TokenPair, error) {
	pair, err := IssuePair(s.cfg, userID, email, role)
	if err != nil {
		return nil, err
	}
	return &usecase.TokenPair{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		AccessExp:    pair.AccessExp,
		RefreshExp:   pair.RefreshExp,
	}, nil
}

// ParseRefresh разбирает refresh-токен и возвращает subject (ID пользователя).
func (s *JWTService) ParseRefresh(raw string) (string, error) {
	claims, err := Parse(s.cfg, raw, "refresh")
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// CSRFService — адаптация генератора CSRF-токенов под порт usecase.CSRFIssuer.
type CSRFService struct {
	cfg *config.Config
}

func NewCSRFService(cfg *config.Config) *CSRFService {
	return &CSRFService{cfg: cfg}
}

var _ usecase.CSRFIssuer = (*CSRFService)(nil)

func (s *CSRFService) IssueCSRF() (string, error) {
	return IssueCSRF(s.cfg.JWTSecret)
}
