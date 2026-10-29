// Package models — слой совместимости (backward-compatibility alias layer).
//
// Канонические сущности и доменные ошибки объявлены в пакете internal/domain
// (Clean Architecture: domain не импортирует ничего внутреннего). Пакет models
// предоставляет старые имена models.User / models.RefreshToken / models.RoleXxx,
// чтобы существующий код и unit-тесты продолжали работать без правок логики.
package models

import "github.com/trauringetag/synapse-backend/internal/domain"

const (
	RoleUser       = domain.RoleUser
	RoleAdmin      = domain.RoleAdmin
	StatusActive   = domain.StatusActive
	StatusInactive = domain.StatusInactive
)

type User = domain.User
type RefreshToken = domain.RefreshToken

// Псевдонимы доменных ошибок — errors.Is/== работают через них корректно,
// поскольку это те же самые значения, объявленные в domain.
var (
	ErrNotFound           = domain.ErrNotFound
	ErrConflict           = domain.ErrConflict
	ErrProtected          = domain.ErrProtected
	ErrRefreshTokenReplay = domain.ErrRefreshTokenReplay
	ErrInactiveTokenUser  = domain.ErrInactiveTokenUser
	UUIDFromString        = domain.UUIDFromString
)

// Псевдонимы типов (интерфейсы и структуры) — объявлены как type-алиасы.
type (
	UserListFilter         = domain.UserListFilter
	UserListResult         = domain.UserListResult
	UserRepository         = domain.UserRepository
	RefreshTokenRepository = domain.RefreshTokenRepository
)
