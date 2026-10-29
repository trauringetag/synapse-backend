package usecase

import (
	"context"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/domain/models"
)

// ---------- DTO входа (Input) ----------

// RegisterInput — данные для регистрации обычного пользователя и администратора.
type RegisterInput struct {
	Email      string
	Password   string
	FirstName  string
	LastName   string
	AdminToken string // X-Admin-Token: только для RegisterAdmin
}

// LoginInput — данные для входа в систему.
type LoginInput struct {
	Email    string
	Password string
}

// RefreshInput — сырой refresh-токен из cookie (JWT).
type RefreshInput struct {
	RawRefreshToken string
}

// LogoutInput — сырой refresh-токен из cookie для отзыва при выходе.
type LogoutInput struct {
	RawRefreshToken string // пустая строка, если cookie отсутствует
	HasCookie       bool
}

// ListUsersInput — параметры списка пользователей (уже разобранные из query).
type ListUsersInput struct {
	Page   int
	Limit  int
	Search string
	Role   string
	Status string
}

// CreateUserInput — данные админского создания пользователя.
type CreateUserInput struct {
	Email     string
	Password  string
	FirstName string
	LastName  string
	Role      string
}

// ReplaceProfileInput — полная замена профиля самим пользователем (PUT /me).
type ReplaceProfileInput struct {
	UserID    uuid.UUID
	Email     string
	FirstName string
	LastName  string
}

// UpdateOwnProfileInput — частичное обновление собственного профиля (PATCH /me).
type UpdateOwnProfileInput struct {
	UserID    uuid.UUID
	Email     *string
	FirstName *string
	LastName  *string
}

// AdminReplaceUserInput — полная замена карточки пользователя админом (PUT /users/{id}).
type AdminReplaceUserInput struct {
	ID        uuid.UUID
	Email     string
	Password  string
	FirstName string
	LastName  string
	Status    string
}

// AdminUpdateUserInput — частичное обновление карточки пользователя админом (PATCH /users/{id}).
type AdminUpdateUserInput struct {
	ID        uuid.UUID
	Email     *string
	Password  *string
	FirstName *string
	LastName  *string
	Status    *string
}

// DeleteUserInput — удаление пользователя админом с проверкой self-delete.
type DeleteUserInput struct {
	TargetID    uuid.UUID
	PrincipalID uuid.UUID
}

// ---------- DTO выхода (Output) ----------

// CSRFResult — выданный CSRF-токен.
type CSRFResult struct {
	Token string
}

// ---------- Интерфейсы сценариев использования ----------

// SessionResult — результат входа: пользователь и выпущенная пара токенов.
type SessionResult struct {
	User *models.User
	Pair *TokenPair
}

// ---------- Интерфейсы сценариев использования ----------

// AuthUseCase — бизнес-сценарии модуля аутентификации: регистрация (обычная и
// админская со строгим сравнением токена), вход с защитой от timing-атак,
// ротация refresh-токенов с детектом replay, выход и выдача CSRF-токена.
type AuthUseCase interface {
	Register(ctx context.Context, in RegisterInput) (*models.User, error)
	RegisterAdmin(ctx context.Context, in RegisterInput) (*models.User, error)
	Login(ctx context.Context, in LoginInput) (*SessionResult, error)
	// Refresh возвращает пару токенов; ok == false означает «отклонить токен»
	// (401). Атрибут ClearCookies указывает HTTP-слою сбросить cookie.
	Refresh(ctx context.Context, in RefreshInput) (pair *TokenPair, ok bool, err error)
	Logout(ctx context.Context, in LogoutInput) error
	IssueCSRF() (*CSRFResult, error)
}

// UserUseCase — бизнес-сценарии управления пользователями: чтение, список с
// фильтрацией, создание, замена/обновление профиля (своего и админские),
// удаление с защитой собственной учетной записи.
type UserUseCase interface {
	GetMe(ctx context.Context, userID uuid.UUID) (*models.User, error)
	List(ctx context.Context, in ListUsersInput) (*domain.UserListResult, error)
	Create(ctx context.Context, in CreateUserInput) (*models.User, error)
	ReplaceProfile(ctx context.Context, in ReplaceProfileInput) (*models.User, error)
	UpdateOwnProfile(ctx context.Context, in UpdateOwnProfileInput) (*models.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	AdminReplace(ctx context.Context, in AdminReplaceUserInput) (*models.User, error)
	AdminUpdate(ctx context.Context, in AdminUpdateUserInput) (*models.User, error)
	Delete(ctx context.Context, in DeleteUserInput) error
}
