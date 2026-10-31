package usecase

import (
	"context"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/domain"
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

// RefreshResult — результат ротации refresh-токена (Refresh).
// HTTP-слой, не зная бизнес-правил, действует по этим флагам:
//   - Pair != nil -> 200 + установить новые cookie;
//   - ClearCookies -> сбросить refresh-cookie (всегда при отказе/ошибке);
//   - Reject -> отклонить токен (401 с сообщением InvalidOrExpiredRefreshToken);
//   - InternalError -> ошибка уже классифицирована (respondError подберёт статус).
type RefreshResult struct {
	Pair          *TokenPair
	ClearCookies  bool
	Reject        bool
	InternalError bool
}

// ---------- Интерфейсы сценариев использования ----------

// SessionResult — результат входа: пользователь и выпущенная пара токенов.
type SessionResult struct {
	User *domain.User
	Pair *TokenPair
}

// ---------- Интерфейсы сценариев использования ----------

// AuthUseCase — бизнес-сценарии модуля аутентификации: регистрация (обычная и
// админская со строгим сравнением токена; опционально — с выпуском стартовой
// JWT-сессии для мобильных клиентов), вход с защитой от timing-атак,
// ротация refresh-токенов с детектом replay, выход и выдача CSRF-токена.
type AuthUseCase interface {
	// Register регистрирует обычного пользователя. Если withSession == true,
	// сразу выпускает пару токенов (пользователь входит после регистрации):
	// Pair заполнен, иначе nil. Формат транспорта (cookie vs JSON) — задача
	// delivery-слоя, use-case этого не знает.
	Register(ctx context.Context, in RegisterInput, withSession bool) (*SessionResult, error)
	// RegisterAdmin — то же для роли admin (проверка X-Admin-Token внутри).
	RegisterAdmin(ctx context.Context, in RegisterInput, withSession bool) (*SessionResult, error)
	Login(ctx context.Context, in LoginInput) (*SessionResult, error)
	// Refresh возвращает результат ротации refresh-токена:
	//   - Pair != nil               -> успех: установить новые cookie;
	//   - Reject && !InternalError  -> отклонить: 401 + сброс cookie;
	//   - InternalError             -> внутренняя ошибка: 5xx + сброс cookie.
	Refresh(ctx context.Context, in RefreshInput) (*RefreshResult, error)
	Logout(ctx context.Context, in LogoutInput) error
	IssueCSRF() (*CSRFResult, error)
}

// UserUseCase — бизнес-сценарии управления пользователями: чтение, список с
// фильтрацией, создание, замена/обновление профиля (своего и админские),
// самоудаление (деактивация, DELETE /me) и физическое удаление админом с
// защитой собственной учетной записи.
type UserUseCase interface {
	GetMe(ctx context.Context, userID uuid.UUID) (*domain.User, error)
	List(ctx context.Context, in ListUsersInput) (*domain.UserListResult, error)
	Create(ctx context.Context, in CreateUserInput) (*domain.User, error)
	ReplaceProfile(ctx context.Context, in ReplaceProfileInput) (*domain.User, error)
	UpdateOwnProfile(ctx context.Context, in UpdateOwnProfileInput) (*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	AdminReplace(ctx context.Context, in AdminReplaceUserInput) (*domain.User, error)
	AdminUpdate(ctx context.Context, in AdminUpdateUserInput) (*domain.User, error)
	// DeleteMe — самоудаление текущего пользователя (DELETE /users/me):
	// физическое (hard) удаление с немедленным отзывом всех refresh-токенов.
	DeleteMe(ctx context.Context, userID uuid.UUID) error
	Delete(ctx context.Context, in DeleteUserInput) error
}
