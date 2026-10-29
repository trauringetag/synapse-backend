package usecase

// Моки зависимостей слоя use-case (Вариант А: ручные моки, без библиотек
// генерации моков). Каждый мок построен по шаблону function-fields:
// поведение конкретной зависимости задаётся через *Func-поле теста, а
// вызовы логируются в поле calls — это позволяет проверять и результат,
// и факт/аргументы обращения к порту.
//
// Моки реализуют ровно те же порты, что и продуктовый код:
//   - MockUserRepository        -> domain.UserRepository
//   - MockTokenRepository       -> domain.RefreshTokenRepository
//   - MockPasswordHasher        -> usecase.PasswordHasher
//   - MockTokenIssuer           -> usecase.TokenIssuer
//   - MockCSRFIssuer            -> usecase.CSRFIssuer

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/domain"
)

// errMockNotConfigured — защита от «забыли настроить мок»: если тест не
// задал соответствующее *Func-поле, вызов метода вернёт эту ошибку вместо
// паники, и тест упадёт с понятным сообщением.
var errMockNotConfigured = errors.New("mock: поведение не настроено")

// ---------- UserRepository ----------

type userCall struct {
	method string
	args   []any
}

// MockUserRepository — мок порта domain.UserRepository.
type MockUserRepository struct {
	mu    sync.Mutex
	calls []userCall

	CreateFunc         func(ctx context.Context, email, passwordHash, role, firstName, lastName string) (*domain.User, error)
	GetByIDFunc        func(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByEmailFunc     func(ctx context.Context, email string) (*domain.User, error)
	ListFunc           func(ctx context.Context, filter domain.UserListFilter) (*domain.UserListResult, error)
	ReplaceProfileFunc func(ctx context.Context, id uuid.UUID, email, firstName, lastName string) (*domain.User, error)
	UpdateFunc         func(ctx context.Context, id uuid.UUID, email, firstName, lastName, passwordHash, status *string) (*domain.User, error)
	ReplaceFunc        func(ctx context.Context, id uuid.UUID, email, firstName, lastName, passwordHash, status string) (*domain.User, error)
	DeleteFunc         func(ctx context.Context, id uuid.UUID) error
}

var _ domain.UserRepository = (*MockUserRepository)(nil)

func (m *MockUserRepository) record(method string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, userCall{method: method, args: args})
}

// Calls возвращает копию журнала вызовов (безопасно для параллельных assert'ов).
func (m *MockUserRepository) Calls() []userCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]userCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// CountCalls возвращает количество обращений к методу с указанным именем.
func (m *MockUserRepository) CountCalls(method string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.calls {
		if c.method == method {
			n++
		}
	}
	return n
}

func (m *MockUserRepository) Create(ctx context.Context, email, passwordHash, role, firstName, lastName string) (*domain.User, error) {
	m.record("Create", email, passwordHash, role, firstName, lastName)
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, email, passwordHash, role, firstName, lastName)
	}
	return nil, errMockNotConfigured
}

func (m *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	m.record("GetByID", id)
	if m.GetByIDFunc != nil {
		return m.GetByIDFunc(ctx, id)
	}
	return nil, errMockNotConfigured
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	m.record("GetByEmail", email)
	if m.GetByEmailFunc != nil {
		return m.GetByEmailFunc(ctx, email)
	}
	return nil, errMockNotConfigured
}

func (m *MockUserRepository) List(ctx context.Context, filter domain.UserListFilter) (*domain.UserListResult, error) {
	m.record("List", filter)
	if m.ListFunc != nil {
		return m.ListFunc(ctx, filter)
	}
	return nil, errMockNotConfigured
}

func (m *MockUserRepository) ReplaceProfile(ctx context.Context, id uuid.UUID, email, firstName, lastName string) (*domain.User, error) {
	m.record("ReplaceProfile", id, email, firstName, lastName)
	if m.ReplaceProfileFunc != nil {
		return m.ReplaceProfileFunc(ctx, id, email, firstName, lastName)
	}
	return nil, errMockNotConfigured
}

func (m *MockUserRepository) Update(ctx context.Context, id uuid.UUID, email, firstName, lastName, passwordHash, status *string) (*domain.User, error) {
	m.record("Update", id, email, firstName, lastName, passwordHash, status)
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, id, email, firstName, lastName, passwordHash, status)
	}
	return nil, errMockNotConfigured
}

func (m *MockUserRepository) Replace(ctx context.Context, id uuid.UUID, email, firstName, lastName, passwordHash, status string) (*domain.User, error) {
	m.record("Replace", id, email, firstName, lastName, passwordHash, status)
	if m.ReplaceFunc != nil {
		return m.ReplaceFunc(ctx, id, email, firstName, lastName, passwordHash, status)
	}
	return nil, errMockNotConfigured
}

func (m *MockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	m.record("Delete", id)
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, id)
	}
	return errMockNotConfigured
}

// ---------- RefreshTokenRepository ----------

type tokenCall struct {
	method string
	args   []any
}

// MockTokenRepository — мок порта domain.RefreshTokenRepository.
type MockTokenRepository struct {
	mu    sync.Mutex
	calls []tokenCall

	StoreFunc            func(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
	RotateFunc           func(ctx context.Context, oldHash string, expectedUserID uuid.UUID, createSuccessor func(*domain.User) (string, time.Time, error)) (*domain.User, error)
	RevokeFunc           func(ctx context.Context, tokenHash string) error
	RevokeAllForUserFunc func(ctx context.Context, userID uuid.UUID) error
}

var _ domain.RefreshTokenRepository = (*MockTokenRepository)(nil)

func (m *MockTokenRepository) record(method string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, tokenCall{method: method, args: args})
}

func (m *MockTokenRepository) Calls() []tokenCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]tokenCall, len(m.calls))
	copy(out, m.calls)
	return out
}

func (m *MockTokenRepository) CountCalls(method string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.calls {
		if c.method == method {
			n++
		}
	}
	return n
}

func (m *MockTokenRepository) Store(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	m.record("Store", userID, tokenHash, expiresAt)
	if m.StoreFunc != nil {
		return m.StoreFunc(ctx, userID, tokenHash, expiresAt)
	}
	return nil
}

func (m *MockTokenRepository) Rotate(ctx context.Context, oldHash string, expectedUserID uuid.UUID, createSuccessor func(*domain.User) (string, time.Time, error)) (*domain.User, error) {
	m.record("Rotate", oldHash, expectedUserID)
	if m.RotateFunc != nil {
		return m.RotateFunc(ctx, oldHash, expectedUserID, createSuccessor)
	}
	return nil, errMockNotConfigured
}

func (m *MockTokenRepository) Revoke(ctx context.Context, tokenHash string) error {
	m.record("Revoke", tokenHash)
	if m.RevokeFunc != nil {
		return m.RevokeFunc(ctx, tokenHash)
	}
	return nil
}

func (m *MockTokenRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	m.record("RevokeAllForUser", userID)
	if m.RevokeAllForUserFunc != nil {
		return m.RevokeAllForUserFunc(ctx, userID)
	}
	return nil
}

// ---------- PasswordHasher ----------

// MockPasswordHasher — мок порта usecase.PasswordHasher. Поведение по
// умолчанию детерминировано: Hash добавляет префикс "hash:", Compare
// требует этого префикса — этого достаточно для бизнес-логики use-case.
type MockPasswordHasher struct {
	HashFunc    func(password string) (string, error)
	CompareFunc func(hash, password string) error
}

var _ PasswordHasher = (*MockPasswordHasher)(nil)

// ErrWrongPassword — аналог bcrypt.ErrMismatchedHashAndPassword для мока.
var ErrWrongPassword = errors.New("crypto/bcrypt: hashedSecret too short to be a bcrypted password")

func (m *MockPasswordHasher) Hash(password string) (string, error) {
	if m.HashFunc != nil {
		return m.HashFunc(password)
	}
	return "hash:" + password, nil
}

func (m *MockPasswordHasher) Compare(hash, password string) error {
	if m.CompareFunc != nil {
		return m.CompareFunc(hash, password)
	}
	if hash == "hash:"+password {
		return nil
	}
	return ErrWrongPassword
}

// ---------- TokenIssuer ----------

// MockTokenIssuer — мок порта usecase.TokenIssuer (выпуск/разбор JWT-пар).
type MockTokenIssuer struct {
	mu               sync.Mutex
	issueCalls       int
	parseCalls       int
	IssuePairFunc    func(userID uuid.UUID, email, role string) (*TokenPair, error)
	ParseRefreshFunc func(raw string) (string, error)
}

var _ TokenIssuer = (*MockTokenIssuer)(nil)

// IssueCallCount / ParseCallCount — число обращений к методам эмитента.
func (m *MockTokenIssuer) IssueCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.issueCalls
}

func (m *MockTokenIssuer) ParseCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.parseCalls
}

func (m *MockTokenIssuer) IssuePair(userID uuid.UUID, email, role string) (*TokenPair, error) {
	m.mu.Lock()
	m.issueCalls++
	m.mu.Unlock()
	if m.IssuePairFunc != nil {
		return m.IssuePairFunc(userID, email, role)
	}
	return &TokenPair{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		AccessExp:    time.Now().Add(15 * time.Minute),
		RefreshExp:   time.Now().Add(72 * time.Hour),
	}, nil
}

func (m *MockTokenIssuer) ParseRefresh(raw string) (string, error) {
	m.mu.Lock()
	m.parseCalls++
	m.mu.Unlock()
	if m.ParseRefreshFunc != nil {
		return m.ParseRefreshFunc(raw)
	}
	return "", errors.New("invalid refresh token")
}

// ---------- CSRFIssuer ----------

// MockCSRFIssuer — мок порта usecase.CSRFIssuer.
type MockCSRFIssuer struct {
	IssueCSRFFunc func() (string, error)
}

var _ CSRFIssuer = (*MockCSRFIssuer)(nil)

func (m *MockCSRFIssuer) IssueCSRF() (string, error) {
	if m.IssueCSRFFunc != nil {
		return m.IssueCSRFFunc()
	}
	return "csrf-token", nil
}
