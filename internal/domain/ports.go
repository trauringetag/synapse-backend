package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
//   - Delete     — физическое (hard) удаление пользователя по ID; используется
//     и админским сценарием (DELETE /users/{id}), и самоудалением
//     (DELETE /users/me), отзыв refresh-токенов выполняется слоем use-case.
//   - UpdateTx / ReplaceTx / DeleteTx / DeleteSelfTx — транзакционные
//     варианты (Unit of Work): выполняются внутри транзакции из контекста
//     (см. domain.UnitOfWork), что позволяет выполнить изменение/удаление
//     пользователя вместе с отзывом сессий атомарно. Вне транзакции
//     эквивалентны нетранзакционным аналогам.
type UserRepository interface {
	Create(context.Context, string, string, string, string, string) (*User, error)
	GetByID(context.Context, uuid.UUID) (*User, error)
	GetByEmail(context.Context, string) (*User, error)
	List(context.Context, UserListFilter) (*UserListResult, error)
	ReplaceProfile(context.Context, uuid.UUID, string, string, string) (*User, error)
	Update(context.Context, uuid.UUID, *string, *string, *string, *string, *string) (*User, error)
	Replace(context.Context, uuid.UUID, string, string, string, string, string) (*User, error)
	Delete(context.Context, uuid.UUID) error
	// DeleteSelf — физическое удаление собственного аккаунта (DELETE /users/me):
	// в отличие от Delete не защищён ролью admin, т.к. субъект удаляет себя сам.
	DeleteSelf(context.Context, uuid.UUID) error
	// Транзакционные операции (Unit of Work): выполняются внутри pgx.Tx,
	// положенной в контекст реализацией domain.UnitOfWork.Run.
	UpdateTx(context.Context, uuid.UUID, *string, *string, *string, *string, *string) (*User, error)
	ReplaceTx(context.Context, uuid.UUID, string, string, string, string, string) (*User, error)
	DeleteTx(context.Context, uuid.UUID) error
	DeleteSelfTx(context.Context, uuid.UUID) error
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
//     (используется при смене пароля / выходе из всех сессий). Если в
//     контексте есть активная транзакция UnitOfWork (см. TxFromContext),
//     отзыв выполняется внутри неё — это даёт атомарность «смена пароля +
//     отзыв сессий» без изменения сигнатуры порта.
type RefreshTokenRepository interface {
	Store(context.Context, uuid.UUID, string, time.Time) error
	Rotate(context.Context, string, uuid.UUID, func(*User) (string, time.Time, error)) (*User, error)
	Revoke(context.Context, string) error
	RevokeAllForUser(context.Context, uuid.UUID) error
}

// UnitOfWork — порт атомарного выполнения нескольких репозиторных операций
// в одной транзакции БД (паттерн Unit of Work). Реализация — в слое
// инфраструктуры (persistence.PgxUnitOfWork поверх pgxpool.Pool).
//
// Семантика Run:
//   - открывает транзакцию и помещает её в контекст (см. TxFromContext);
//     транзакционные методы репозиториев обязаны доставать tx из контекста
//     и выполнять запросы внутри неё;
//   - если fn вернул ошибку — транзакция ОТКАТЫВАЕТСЯ целиком: ни одно
//     изменение не применяется (например, при сбое отзыва сессий смена
//     пароля не считается успешной);
//   - при успехе — COMMIT.
type UnitOfWork interface {
	Run(ctx context.Context, fn func(ctx context.Context) error) error
}

// txContextKey — ключ контекста, под которым UnitOfWork помещает активную
// транзакцию pgx.Tx. Неэкспортируемый: доступ только через WithTx/TxFromContext.
type txContextKey struct{}

// WithTx возвращает копию ctx с помещённой в него транзакцией. Используется
// реализацией UnitOfWork; продуктовый код use-case напрямую не вызывает.
func WithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txContextKey{}, tx)
}

// TxFromContext извлекает транзакцию из контекста. ok == false означает, что
// операция выполняется вне транзакции — репозиторий обязан использовать
// собственный пул соединений.
func TxFromContext(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(txContextKey{}).(pgx.Tx)
	return tx, ok && tx != nil
}
