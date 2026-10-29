package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// UserListFilter — параметры пагинации и фильтрации списка пользователей.
// Используется портом UserRepository.List как часть контракта чтения.
type UserListFilter struct {
	Page   int
	Limit  int
	Search string
	Role   string
	Status string
}

// UserListResult — страница пользователей с метаданными пагинации.
// Возвращается портом UserRepository.List.
type UserListResult struct {
	Items      []User `json:"items"`
	Page       int    `json:"page"`
	Limit      int    `json:"limit"`
	Total      int64  `json:"total"`
	TotalPages int64  `json:"total_pages"`
}

// UserRepository — ЕДИНСТВЕННЫЙ источник правды для порта хранилища
// пользователей (Clean Architecture: порты объявляются во внутреннем круге,
// в домене). Слой use-case использует этот интерфейс напрямую (или через
// type-алиас usecase.UserRepository), инфраструктурная реализация —
// internal/infrastructure/persistence.UserRepository.
//
// Методы:
//   - Create     — создаёт пользователя по email, хешу пароля, роли и имени;
//     возвращает сохранённую сущность.
//   - GetByID / GetByEmail — поиск по первичному ключу / email;
//     если не найдено — ошибка domain.ErrNotFound.
//   - List       — постраничная выдача с фильтрами (UserListFilter).
//   - ReplaceProfile — полная замена профиля (email, имя, фамилия).
//   - Update     — частичное обновление (nil-указатели = поле не менять).
//   - Replace    — полная замена всех полей пользователя.
//   - Delete     — удаление пользователя по ID.
type UserRepository interface {
	Create(context.Context, string, string, string, string, string) (*User, error)
	GetByID(context.Context, uuid.UUID) (*User, error)
	GetByEmail(context.Context, string) (*User, error)
	List(context.Context, UserListFilter) (*UserListResult, error)
	ReplaceProfile(context.Context, uuid.UUID, string, string, string) (*User, error)
	Update(context.Context, uuid.UUID, *string, *string, *string, *string, *string) (*User, error)
	Replace(context.Context, uuid.UUID, string, string, string, string, string) (*User, error)
	Delete(context.Context, uuid.UUID) error
}

// RefreshTokenRepository — ЕДИНСТВЕННЫЙ источник правды для порта хранилища
// refresh-токенов (объявляется в домене, см. также alias usecase.TokenRepository).
// Инфраструктурная реализация — internal/infrastructure/persistence.TokenRepository.
//
// Методы:
//   - Store — сохраняет хеш нового refresh-токена для пользователя с сроком
//     жизни expiresAt.
//   - Rotate — ротация токена: находит запись по oldHash, проверяет, что она
//     принадлежит expectedUserID, вызывает createSuccessor (который получает
//     владельца и возвращает хеш/срок преемника), отзывает старый токен и
//     возвращает обновлённого пользователя. При повторном использовании
//     отозванного токена — ошибка domain.ErrRefreshTokenReplay.
//   - Revoke — отзывает один токен по его хешу.
//   - RevokeAllForUser — отзывает все активные токены пользователя
//     (используется при смене пароля / выходе из всех сессий).
type RefreshTokenRepository interface {
	Store(context.Context, uuid.UUID, string, time.Time) error
	Rotate(context.Context, string, uuid.UUID, func(*User) (string, time.Time, error)) (*User, error)
	Revoke(context.Context, string) error
	RevokeAllForUser(context.Context, uuid.UUID) error
}
