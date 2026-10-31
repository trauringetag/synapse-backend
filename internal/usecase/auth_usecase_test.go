package usecase

// Unit-тесты слоя Use Case для сценариев аутентификации (AuthUseCaseImpl).
// Тесты полностью изолированы: все зависимости (репозитории, хешер, JWT-эмитент,
// CSRF-эмитент) — ручные моки из mocks_test.go. Ни БД, ни HTTP, ни внешние
// сервисы не участвуют.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/messages"
)

// ---------- Хелперы ----------

const testAdminToken = "s3cret-admin-token"

// newValidRegisterInput — корректный набор данных регистрации.
func newValidRegisterInput() RegisterInput {
	return RegisterInput{
		Email:     "Test.User@Example.com",
		Password:  "password123",
		FirstName: "Test",
		LastName:  "User",
	}
}

// authFixture — собранный AuthUseCase поверх моков со «счастливым» поведением
// по умолчанию; отдельные тесты переопределяют нужное поле.
type authFixture struct {
	users  *MockUserRepository
	tokens *MockTokenRepository
	hasher *MockPasswordHasher
	issuer *MockTokenIssuer
	csrf   *MockCSRFIssuer
	uc     *AuthUseCaseImpl
}

func newAuthFixture() *authFixture {
	f := &authFixture{
		users:  &MockUserRepository{},
		tokens: &MockTokenRepository{},
		hasher: &MockPasswordHasher{},
		issuer: &MockTokenIssuer{},
		csrf:   &MockCSRFIssuer{},
	}
	// По умолчанию регистрация успешно создаёт активного пользователя-role user.
	f.users.CreateFunc = func(_ context.Context, email, hash, role, first, last string) (*domain.User, error) {
		return &domain.User{
			ID:           uuid.New(),
			Email:        email,
			PasswordHash: hash,
			Role:         role,
			Status:       domain.StatusActive,
			FirstName:    first,
			LastName:     last,
		}, nil
	}
	f.uc = NewAuthUseCase(f.users, f.tokens, f.hasher, f.issuer, f.csrf, testAdminToken)
	return f
}

// requireUseCaseErr — ассерт, что ошибка является *UseCaseError с указанным кодом.
func requireUseCaseErr(t *testing.T, err error, code ErrorCode) *UseCaseError {
	t.Helper()
	require.Error(t, err)
	ue, ok := AsUseCaseError(err)
	require.True(t, ok, "ошибка должна быть *UseCaseError, получено: %T (%v)", err, err)
	assert.Equal(t, code, ue.Code)
	return ue
}

// ---------- Регистрация ----------

func TestAuthUseCase_Register_Success(t *testing.T) {
	f := newAuthFixture()

	res, err := f.uc.Register(context.Background(), newValidRegisterInput(), false)

	require.NoError(t, err)
	user := res.User
	require.NotNil(t, res.User)
	// Email нормализуется (lowercase) — бизнес-правило слоя use-case.
	assert.Equal(t, "test.user@example.com", user.Email)
	assert.Equal(t, domain.RoleUser, user.Role, "обычная регистрация всегда выдаёт роль user")
	assert.Equal(t, domain.StatusActive, user.Status)
	assert.Equal(t, "Test", user.FirstName)
	assert.Equal(t, "User", user.LastName)

	// Пароль НЕ передаётся в репозиторий в открытом виде — только хеш.
	require.Equal(t, 1, f.users.CountCalls("Create"))
	call := f.users.Calls()[0]
	assert.Equal(t, "hash:password123", call.args[1], "в репозиторий должен попасть хеш пароля")
	assert.Equal(t, domain.RoleUser, call.args[2])
}

func TestAuthUseCase_Register_ValidationError(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(in *RegisterInput)
		wantDetails []string // поля, которые должны быть в деталях ошибки
	}{
		{
			name:        "invalid email",
			mutate:      func(in *RegisterInput) { in.Email = "not-an-email" },
			wantDetails: []string{"email"},
		},
		{
			name:        "empty email",
			mutate:      func(in *RegisterInput) { in.Email = "" },
			wantDetails: []string{"email"},
		},
		{
			name:        "short password",
			mutate:      func(in *RegisterInput) { in.Password = "short" },
			wantDetails: []string{"password"},
		},
		{
			name:        "too long password (>72 bytes for bcrypt)",
			mutate:      func(in *RegisterInput) { in.Password = strings.Repeat("a", 73) },
			wantDetails: []string{"password"},
		},
		{
			name:        "blank first name",
			mutate:      func(in *RegisterInput) { in.FirstName = "   " },
			wantDetails: []string{"first_name"},
		},
		{
			name:        "blank last name",
			mutate:      func(in *RegisterInput) { in.LastName = "" },
			wantDetails: []string{"last_name"},
		},
		{
			name:        "all fields invalid -> all details present",
			mutate:      func(in *RegisterInput) { *in = RegisterInput{} },
			wantDetails: []string{"email", "password", "first_name", "last_name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAuthFixture()
			in := newValidRegisterInput()
			tt.mutate(&in)

			res, err := f.uc.Register(context.Background(), in, false)

			assert.Nil(t, res)
			ue := requireUseCaseErr(t, err, ErrCodeValidation)
			assert.Equal(t, messages.CheckRequiredFields, ue.Message)
			for _, field := range tt.wantDetails {
				assert.NotEmpty(t, ue.Details[field], "ожидалась ошибка валидации для поля %q", field)
			}
			// До валидации дошла только проверка полей — репозиторий не тронут.
			assert.Zero(t, f.users.CountCalls("Create"), "при ошибке валидации создавать пользователя нельзя")
		})
	}
}

func TestAuthUseCase_Register_DuplicateEmail(t *testing.T) {
	f := newAuthFixture()
	f.users.CreateFunc = func(_ context.Context, _, _, _, _, _ string) (*domain.User, error) {
		return nil, domain.ErrConflict
	}

	res, err := f.uc.Register(context.Background(), newValidRegisterInput(), false)

	assert.Nil(t, res)
	ue := requireUseCaseErr(t, err, ErrCodeConflict)
	assert.Equal(t, messages.EmailAlreadyUsed, ue.Message)
	// Оригинальная доменная ошибка сохраняется в цепочке (errors.Is работает).
	assert.ErrorIs(t, err, domain.ErrConflict)
}

func TestAuthUseCase_Register_RepositoryFailure(t *testing.T) {
	f := newAuthFixture()
	repoErr := errors.New("connection reset by peer")
	f.users.CreateFunc = func(_ context.Context, _, _, _, _, _ string) (*domain.User, error) {
		return nil, repoErr
	}

	res, err := f.uc.Register(context.Background(), newValidRegisterInput(), false)

	assert.Nil(t, res)
	ue := requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Equal(t, messages.FailedToCreateUser, ue.Message)
	assert.ErrorIs(t, err, repoErr)
}

func TestAuthUseCase_Register_HashFailure(t *testing.T) {
	f := newAuthFixture()
	hashErr := errors.New("bcrypt: salt too short")
	f.hasher.HashFunc = func(string) (string, error) { return "", hashErr }

	res, err := f.uc.Register(context.Background(), newValidRegisterInput(), false)

	assert.Nil(t, res)
	ue := requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Equal(t, messages.FailedToHashPassword, ue.Message)
	assert.ErrorIs(t, err, hashErr)
	assert.Zero(t, f.users.CountCalls("Create"), "при сбое хеширования пользователь не создаётся")
}

// ---------- Админская регистрация ----------

func TestAuthUseCase_RegisterAdmin_Success(t *testing.T) {
	f := newAuthFixture()
	in := newValidRegisterInput()
	in.AdminToken = testAdminToken

	res, err := f.uc.RegisterAdmin(context.Background(), in, false)

	require.NoError(t, err)
	require.NotNil(t, res.User)
	assert.Equal(t, domain.RoleAdmin, res.User.Role, "админская регистрация выдаёт роль admin")
}

func TestAuthUseCase_RegisterAdmin_InvalidToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"wrong token", "wrong-token"},
		{"token with extra spaces is trimmed but still must match", "  " + testAdminToken + "  "}, // нормализация -> совпадёт
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if i == 2 {
				// Этот кейс — позитивный: normalizeToken обрезает пробелы.
				f := newAuthFixture()
				in := newValidRegisterInput()
				in.AdminToken = tt.token
				res, err := f.uc.RegisterAdmin(context.Background(), in, false)
				require.NoError(t, err)
				require.NotNil(t, res.User)
				assert.Equal(t, domain.RoleAdmin, res.User.Role)
				return
			}
			f := newAuthFixture()
			in := newValidRegisterInput()
			in.AdminToken = tt.token

			res, err := f.uc.RegisterAdmin(context.Background(), in, false)

			assert.Nil(t, res)
			ue := requireUseCaseErr(t, err, ErrCodeForbidden)
			assert.Equal(t, messages.InvalidAdminToken, ue.Message)
			assert.Zero(t, f.users.CountCalls("Create"), "пользователь не создаётся при неверном админ-токене")
		})
	}
}

func TestAuthUseCase_RegisterAdmin_EmptyConfiguredToken_AlwaysRejectsProvidedNonEmpty(t *testing.T) {
	// Если секрет админской регистрации не задан в конфиге, пустой входящий
	// токен тоже не проходит сравнение (ConstantTimeCompare с разной длиной).
	f := newAuthFixture()
	f.uc = NewAuthUseCase(f.users, f.tokens, f.hasher, f.issuer, f.csrf, "")

	in := newValidRegisterInput()
	in.AdminToken = "anything"
	_, err := f.uc.RegisterAdmin(context.Background(), in, false)
	requireUseCaseErr(t, err, ErrCodeForbidden)

	// Пустой токен против пустого конфига — одинаковые строки, сравнение проходит.
	in.AdminToken = ""
	res, err := f.uc.RegisterAdmin(context.Background(), in, false)
	require.NoError(t, err)
	assert.Equal(t, domain.RoleAdmin, res.User.Role)
}

func TestAuthUseCase_RegisterAdmin_ValidationErrorBeforeTokenCheck(t *testing.T) {
	f := newAuthFixture()
	in := newValidRegisterInput()
	in.Password = "short"          // невалидное поле
	in.AdminToken = testAdminToken // валидный токен

	_, err := f.uc.RegisterAdmin(context.Background(), in, false)

	ue := requireUseCaseErr(t, err, ErrCodeValidation)
	assert.NotEmpty(t, ue.Details["password"])
}

// ---------- Логин ----------

func activeUser(email string) *domain.User {
	return &domain.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: "hash:password123",
		Role:         domain.RoleUser,
		Status:       domain.StatusActive,
		FirstName:    "Test",
		LastName:     "User",
	}
}

func TestAuthUseCase_Login_Success(t *testing.T) {
	f := newAuthFixture()
	stored := activeUser("test@example.com")
	f.users.GetByEmailFunc = func(_ context.Context, email string) (*domain.User, error) {
		assert.Equal(t, "test@example.com", email, "email нормализуется перед поиском")
		return stored, nil
	}
	var storedHash string
	f.tokens.StoreFunc = func(_ context.Context, userID uuid.UUID, tokenHash string, _ time.Time) error {
		storedHash = tokenHash
		assert.Equal(t, stored.ID, userID)
		return nil
	}

	result, err := f.uc.Login(context.Background(), LoginInput{
		Email:    " TEST@Example.com ",
		Password: "password123",
	})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Pair)
	assert.Equal(t, "access-token", result.Pair.AccessToken)
	assert.Equal(t, "refresh-token", result.Pair.RefreshToken)
	assert.False(t, result.Pair.AccessExp.IsZero())
	assert.False(t, result.Pair.RefreshExp.IsZero())
	require.NotNil(t, result.User)
	assert.Equal(t, stored.ID, result.User.ID)

	// Refresh-токен сохраняется в БД в виде SHA-256 хеша, а не в открытом виде.
	assert.Equal(t, HashToken("refresh-token"), storedHash)
	assert.Equal(t, 1, f.tokens.CountCalls("Store"))
}

func TestAuthUseCase_Login_InvalidPassword(t *testing.T) {
	f := newAuthFixture()
	stored := activeUser("test@example.com")
	f.users.GetByEmailFunc = func(_ context.Context, _ string) (*domain.User, error) {
		return stored, nil
	}
	f.hasher.CompareFunc = func(hash, password string) error {
		// Сравнивается реальный хеш пользователя, но пароль не совпадает.
		assert.Equal(t, stored.PasswordHash, hash)
		return ErrWrongPassword // аналог bcrypt.ErrMismatchedHashAndPassword
	}

	result, err := f.uc.Login(context.Background(), LoginInput{
		Email:    "test@example.com",
		Password: "wrong-password",
	})

	assert.Nil(t, result)
	ue := requireUseCaseErr(t, err, ErrCodeUnauthorized)
	assert.Equal(t, messages.InvalidCredentials, ue.Message)
	assert.Zero(t, f.issuer.IssueCallCount(), "токены не выпускаются при неверном пароле")
	assert.Zero(t, f.tokens.CountCalls("Store"))
}

func TestAuthUseCase_Login_UserNotFound_TimingProtection(t *testing.T) {
	f := newAuthFixture()
	f.users.GetByEmailFunc = func(_ context.Context, _ string) (*domain.User, error) {
		return nil, domain.ErrNotFound
	}
	var comparedHash string
	f.hasher.CompareFunc = func(hash, password string) error {
		comparedHash = hash
		return ErrWrongPassword
	}

	result, err := f.uc.Login(context.Background(), LoginInput{
		Email:    "ghost@example.com",
		Password: "whatever123",
	})

	assert.Nil(t, result)
	ue := requireUseCaseErr(t, err, ErrCodeUnauthorized)
	assert.Equal(t, messages.InvalidCredentials, ue.Message,
		"ответ для несуществующего пользователя неотличим от неверного пароля")
	// Защита от timing-атаки: сравнение всё равно выполняется — с dummy-хешем.
	assert.NotEmpty(t, comparedHash, "hasher.Compare должен вызываться даже когда пользователь не найден")
	assert.NotEqual(t, "", f.uc.dummyHash, "dummy-хеш вычисляется в конструкторе")
	assert.Zero(t, f.issuer.IssueCallCount())
}

func TestAuthUseCase_Login_InactiveUser(t *testing.T) {
	f := newAuthFixture()
	inactive := activeUser("test@example.com")
	inactive.Status = domain.StatusInactive
	f.users.GetByEmailFunc = func(_ context.Context, _ string) (*domain.User, error) {
		return inactive, nil
	}
	// Даже если пароль верный, неактивный пользователь не получает доступ.
	f.hasher.CompareFunc = func(_, _ string) error { return nil }

	result, err := f.uc.Login(context.Background(), LoginInput{
		Email:    "test@example.com",
		Password: "password123",
	})

	assert.Nil(t, result)
	requireUseCaseErr(t, err, ErrCodeUnauthorized)
	assert.Zero(t, f.issuer.IssueCallCount(), "неактивному пользователю токены не выдаются")
}

func TestAuthUseCase_Login_InputTooLong(t *testing.T) {
	tests := []struct {
		name  string
		input LoginInput
	}{
		{"email longer than 255", LoginInput{Email: strings.Repeat("a", 256) + "@x.com", Password: "password123"}},
		{"password longer than 72 bytes (bcrypt limit)", LoginInput{Email: "test@example.com", Password: strings.Repeat("p", 73)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAuthFixture()

			result, err := f.uc.Login(context.Background(), tt.input)

			assert.Nil(t, result)
			ue := requireUseCaseErr(t, err, ErrCodeValidation)
			assert.Equal(t, messages.InvalidJSONBody, ue.Message)
			assert.Zero(t, f.users.CountCalls("GetByEmail"), "поиск не выполняется при невалидном вводе")
		})
	}
}

func TestAuthUseCase_Login_RepositoryUnavailable(t *testing.T) {
	f := newAuthFixture()
	dbErr := errors.New("pgx: pool exhausted")
	f.users.GetByEmailFunc = func(_ context.Context, _ string) (*domain.User, error) {
		return nil, dbErr
	}

	result, err := f.uc.Login(context.Background(), LoginInput{
		Email:    "test@example.com",
		Password: "password123",
	})

	assert.Nil(t, result)
	ue := requireUseCaseErr(t, err, ErrCodeUnavailable)
	assert.Equal(t, messages.AuthenticationUnavailable, ue.Message)
	assert.ErrorIs(t, err, dbErr)
}

func TestAuthUseCase_Login_IssuerFailure(t *testing.T) {
	f := newAuthFixture()
	stored := activeUser("test@example.com")
	f.users.GetByEmailFunc = func(_ context.Context, _ string) (*domain.User, error) {
		return stored, nil
	}
	issueErr := errors.New("jwt: signing failed")
	f.issuer.IssuePairFunc = func(_ uuid.UUID, _, _ string) (*TokenPair, error) {
		return nil, issueErr
	}

	result, err := f.uc.Login(context.Background(), LoginInput{
		Email:    "test@example.com",
		Password: "password123",
	})

	assert.Nil(t, result)
	ue := requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Equal(t, messages.FailedToIssueTokens, ue.Message)
	assert.ErrorIs(t, err, issueErr)
}

func TestAuthUseCase_Login_StoreFailure(t *testing.T) {
	f := newAuthFixture()
	stored := activeUser("test@example.com")
	f.users.GetByEmailFunc = func(_ context.Context, _ string) (*domain.User, error) {
		return stored, nil
	}
	storeErr := errors.New("db write failed")
	f.tokens.StoreFunc = func(_ context.Context, _ uuid.UUID, _ string, _ time.Time) error {
		return storeErr
	}

	result, err := f.uc.Login(context.Background(), LoginInput{
		Email:    "test@example.com",
		Password: "password123",
	})

	assert.Nil(t, result)
	requireUseCaseErr(t, err, ErrCodeInternal)
	assert.ErrorIs(t, err, storeErr)
}

// ---------- Ротация refresh-токена ----------

// rotateSuccess — мок Rotate, эмулирующий успешную ротацию: репозиторий сам
// вызывает createSuccessor и возвращает владельца.
func rotateSuccess(owner *domain.User) func(ctx context.Context, oldHash string, expectedUserID uuid.UUID, createSuccessor func(*domain.User) (string, time.Time, error)) (*domain.User, error) {
	return func(_ context.Context, _ string, _ uuid.UUID, createSuccessor func(*domain.User) (string, time.Time, error)) (*domain.User, error) {
		if _, _, err := createSuccessor(owner); err != nil {
			return nil, err
		}
		return owner, nil
	}
}

func TestAuthUseCase_Refresh_Success(t *testing.T) {
	f := newAuthFixture()
	owner := activeUser("test@example.com")
	const raw = "raw-refresh-token"

	f.issuer.ParseRefreshFunc = func(got string) (string, error) {
		assert.Equal(t, raw, got)
		return owner.ID.String(), nil
	}
	f.tokens.RotateFunc = rotateSuccess(owner)

	result, err := f.uc.Refresh(context.Background(), RefreshInput{RawRefreshToken: raw})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Pair, "успешная ротация обязана вернуть новую пару токенов")
	assert.Equal(t, "access-token", result.Pair.AccessToken)
	assert.False(t, result.Reject)
	assert.False(t, result.InternalError)
	assert.Equal(t, 1, f.tokens.CountCalls("Rotate"))
}

func TestAuthUseCase_Refresh_EmptyToken(t *testing.T) {
	f := newAuthFixture()

	result, err := f.uc.Refresh(context.Background(), RefreshInput{RawRefreshToken: ""})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Nil(t, result.Pair)
	assert.True(t, result.Reject)
	assert.True(t, result.ClearCookies)
	assert.False(t, result.InternalError)
	// Пустой токен не должен доходить ни до парсинга, ни до БД.
	assert.Zero(t, f.issuer.ParseCallCount())
	assert.Zero(t, f.tokens.CountCalls("Rotate"))
}

func TestAuthUseCase_Refresh_InvalidSignature(t *testing.T) {
	f := newAuthFixture()
	f.issuer.ParseRefreshFunc = func(string) (string, error) {
		return "", errors.New("jwt: token signature is invalid")
	}

	result, err := f.uc.Refresh(context.Background(), RefreshInput{RawRefreshToken: "forged"})

	require.NoError(t, err)
	assert.True(t, result.Reject)
	assert.True(t, result.ClearCookies)
	assert.Nil(t, result.Pair)
	assert.Zero(t, f.tokens.CountCalls("Rotate"))
}

func TestAuthUseCase_Refresh_BadSubject(t *testing.T) {
	f := newAuthFixture()
	f.issuer.ParseRefreshFunc = func(string) (string, error) {
		return "not-a-uuid", nil // subject невозможно разобрать в UUID
	}

	result, err := f.uc.Refresh(context.Background(), RefreshInput{RawRefreshToken: "weird-token"})

	require.NoError(t, err)
	assert.True(t, result.Reject)
	assert.Zero(t, f.tokens.CountCalls("Rotate"))
}

func TestAuthUseCase_Refresh_ReplayAttack_RevokesAllSessions(t *testing.T) {
	f := newAuthFixture()
	owner := activeUser("test@example.com")
	f.issuer.ParseRefreshFunc = func(string) (string, error) { return owner.ID.String(), nil }
	f.tokens.RotateFunc = func(_ context.Context, _ string, _ uuid.UUID, _ func(*domain.User) (string, time.Time, error)) (*domain.User, error) {
		return nil, domain.ErrRefreshTokenReplay
	}
	var revokedFor uuid.UUID
	f.tokens.RevokeAllForUserFunc = func(_ context.Context, userID uuid.UUID) error {
		revokedFor = userID
		return nil
	}

	result, err := f.uc.Refresh(context.Background(), RefreshInput{RawRefreshToken: "replayed-token"})

	require.NoError(t, err, "replay — не внутренняя ошибка, а отклонение 401")
	assert.True(t, result.Reject)
	assert.True(t, result.ClearCookies)
	assert.False(t, result.InternalError)
	assert.Equal(t, owner.ID, revokedFor, "при replay должны быть отозваны ВСЕ сессии пользователя")
}

func TestAuthUseCase_Refresh_ReplayAndRevokeFailure_StillRejects(t *testing.T) {
	f := newAuthFixture()
	owner := activeUser("test@example.com")
	f.issuer.ParseRefreshFunc = func(string) (string, error) { return owner.ID.String(), nil }
	f.tokens.RotateFunc = func(_ context.Context, _ string, _ uuid.UUID, _ func(*domain.User) (string, time.Time, error)) (*domain.User, error) {
		return nil, domain.ErrRefreshTokenReplay
	}
	f.tokens.RevokeAllForUserFunc = func(_ context.Context, _ uuid.UUID) error {
		return errors.New("db unavailable")
	}

	// Сбой отзыва всех сессий логируется, но не меняет ответа: всё равно 401+reject.
	result, err := f.uc.Refresh(context.Background(), RefreshInput{RawRefreshToken: "replayed-token"})

	require.NoError(t, err)
	assert.True(t, result.Reject)
	assert.False(t, result.InternalError)
}

func TestAuthUseCase_Refresh_NotFound(t *testing.T) {
	f := newAuthFixture()
	owner := activeUser("test@example.com")
	f.issuer.ParseRefreshFunc = func(string) (string, error) { return owner.ID.String(), nil }
	f.tokens.RotateFunc = func(_ context.Context, _ string, _ uuid.UUID, _ func(*domain.User) (string, time.Time, error)) (*domain.User, error) {
		return nil, domain.ErrNotFound
	}

	result, err := f.uc.Refresh(context.Background(), RefreshInput{RawRefreshToken: "expired-or-unknown"})

	require.NoError(t, err)
	assert.True(t, result.Reject)
	assert.True(t, result.ClearCookies)
	assert.False(t, result.InternalError)
}

func TestAuthUseCase_Refresh_InactiveUser(t *testing.T) {
	f := newAuthFixture()
	owner := activeUser("test@example.com")
	f.issuer.ParseRefreshFunc = func(string) (string, error) { return owner.ID.String(), nil }
	f.tokens.RotateFunc = func(_ context.Context, _ string, _ uuid.UUID, _ func(*domain.User) (string, time.Time, error)) (*domain.User, error) {
		return nil, domain.ErrInactiveTokenUser
	}

	result, err := f.uc.Refresh(context.Background(), RefreshInput{RawRefreshToken: "token-of-inactive-user"})

	require.NoError(t, err)
	assert.True(t, result.Reject, "ротация для неактивного пользователя отклоняется")
	assert.False(t, result.InternalError)
}

func TestAuthUseCase_Refresh_InternalError(t *testing.T) {
	f := newAuthFixture()
	owner := activeUser("test@example.com")
	f.issuer.ParseRefreshFunc = func(string) (string, error) { return owner.ID.String(), nil }
	dbErr := errors.New("db connection lost")
	f.tokens.RotateFunc = func(_ context.Context, _ string, _ uuid.UUID, _ func(*domain.User) (string, time.Time, error)) (*domain.User, error) {
		return nil, dbErr
	}

	result, err := f.uc.Refresh(context.Background(), RefreshInput{RawRefreshToken: "any"})

	// Внутренняя ошибка: результат классифицирован, ошибка обёрнута в UseCaseError.
	require.Error(t, err)
	require.NotNil(t, result)
	assert.True(t, result.InternalError)
	assert.True(t, result.ClearCookies)
	assert.Nil(t, result.Pair)
	ue := requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Equal(t, messages.FailedToIssueTokens, ue.Message)
	assert.ErrorIs(t, err, dbErr)
}

func TestAuthUseCase_Refresh_SuccessorIssuerFailure(t *testing.T) {
	f := newAuthFixture()
	owner := activeUser("test@example.com")
	f.issuer.ParseRefreshFunc = func(string) (string, error) { return owner.ID.String(), nil }
	// Эмитент падает внутри createSuccessor; Rotate пробрасывает эту ошибку как внутреннюю.
	issueErr := errors.New("jwt: cannot sign")
	f.issuer.IssuePairFunc = func(_ uuid.UUID, _, _ string) (*TokenPair, error) { return nil, issueErr }
	f.tokens.RotateFunc = func(_ context.Context, _ string, _ uuid.UUID, createSuccessor func(*domain.User) (string, time.Time, error)) (*domain.User, error) {
		_, _, err := createSuccessor(owner)
		if err != nil {
			return nil, err
		}
		return owner, nil
	}

	result, err := f.uc.Refresh(context.Background(), RefreshInput{RawRefreshToken: "any"})

	require.Error(t, err)
	assert.True(t, result.InternalError)
	assert.ErrorIs(t, err, issueErr)
}

// ---------- Выход ----------

func TestAuthUseCase_Logout_WithCookie(t *testing.T) {
	f := newAuthFixture()
	var revokedHash string
	f.tokens.RevokeFunc = func(_ context.Context, tokenHash string) error {
		revokedHash = tokenHash
		return nil
	}

	err := f.uc.Logout(context.Background(), LogoutInput{
		RawRefreshToken: "refresh-token-raw",
		HasRefreshToken: true,
	})

	require.NoError(t, err)
	assert.Equal(t, HashToken("refresh-token-raw"), revokedHash, "отзывается SHA-256 хеш токена")
	assert.Equal(t, 1, f.tokens.CountCalls("Revoke"))
}

func TestAuthUseCase_Logout_NoCookie_IsNoop(t *testing.T) {
	f := newAuthFixture()

	err := f.uc.Logout(context.Background(), LogoutInput{HasRefreshToken: false})

	require.NoError(t, err, "выход без cookie — успешный no-op")
	assert.Zero(t, f.tokens.CountCalls("Revoke"))
}

func TestAuthUseCase_Logout_EmptyTokenWithCookie_IsNoop(t *testing.T) {
	f := newAuthFixture()

	err := f.uc.Logout(context.Background(), LogoutInput{HasRefreshToken: true, RawRefreshToken: ""})

	require.NoError(t, err)
	assert.Zero(t, f.tokens.CountCalls("Revoke"))
}

func TestAuthUseCase_Logout_RevokeFailure(t *testing.T) {
	f := newAuthFixture()
	revokeErr := errors.New("db timeout")
	f.tokens.RevokeFunc = func(_ context.Context, _ string) error { return revokeErr }

	err := f.uc.Logout(context.Background(), LogoutInput{
		RawRefreshToken: "refresh-token-raw",
		HasRefreshToken: true,
	})

	ue := requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Equal(t, messages.FailedToRevokeRefreshToken, ue.Message)
	assert.ErrorIs(t, err, revokeErr)
}

// ---------- CSRF ----------

func TestAuthUseCase_IssueCSRF_Success(t *testing.T) {
	f := newAuthFixture()
	f.csrf.IssueCSRFFunc = func() (string, error) { return "csrf-abc-123", nil }

	res, err := f.uc.IssueCSRF()

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "csrf-abc-123", res.Token)
}

func TestAuthUseCase_IssueCSRF_Failure(t *testing.T) {
	f := newAuthFixture()
	csrfErr := errors.New("crypto/rand: read failed")
	f.csrf.IssueCSRFFunc = func() (string, error) { return "", csrfErr }

	res, err := f.uc.IssueCSRF()

	assert.Nil(t, res)
	ue := requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Equal(t, messages.FailedToPrepareCSRFProtection, ue.Message)
	assert.ErrorIs(t, err, csrfErr)
}

// ---------- Конструктор / вспомогательное ----------

func TestNewAuthUseCase_NilHasherDoesNotPanic(t *testing.T) {
	f := newAuthFixture()
	// Nil-hasher допустим на входе: dummy-хеш просто не вычисляется.
	uc := NewAuthUseCase(f.users, f.tokens, nil, f.issuer, f.csrf, testAdminToken)
	require.NotNil(t, uc)
	assert.Empty(t, uc.dummyHash)
}

func TestHashToken_DeterministicSHA256(t *testing.T) {
	// Контрольная сумма SHA-256 от "abc" — известный вектор.
	assert.Equal(t,
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		HashToken("abc"))
	assert.Len(t, HashToken("anything"), 64)
}
