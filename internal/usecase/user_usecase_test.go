package usecase

// Unit-тесты слоя Use Case для сценариев управления пользователями
// (UserUseCaseImpl). Все зависимости — ручные моки из mocks_test.go;
// тесты изолированы от БД, HTTP и внешних сервисов.

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

// userFixture — собранный UserUseCase поверх моков.
type userFixture struct {
	users  *MockUserRepository
	tokens *MockTokenRepository
	hasher *MockPasswordHasher
	uc     *UserUseCaseImpl
}

func newUserFixture() *userFixture {
	f := &userFixture{
		users:  &MockUserRepository{},
		tokens: &MockTokenRepository{},
		hasher: &MockPasswordHasher{},
	}
	f.uc = NewUserUseCase(f.users, f.tokens, f.hasher)
	return f
}

func sampleUser(id uuid.UUID) *domain.User {
	return &domain.User{
		ID:           id,
		Email:        "test@example.com",
		PasswordHash: "hash:password123",
		Role:         domain.RoleUser,
		Status:       domain.StatusActive,
		FirstName:    "Test",
		LastName:     "User",
	}
}

func strPtr(s string) *string { return &s }

// ---------- GetMe / GetByID ----------

func TestUserUseCase_GetMe_Success(t *testing.T) {
	f := newUserFixture()
	id := uuid.New()
	want := sampleUser(id)
	f.users.GetByIDFunc = func(_ context.Context, got uuid.UUID) (*domain.User, error) {
		assert.Equal(t, id, got)
		return want, nil
	}

	got, err := f.uc.GetMe(context.Background(), id)

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, want, got)
	assert.Equal(t, 1, f.users.CountCalls("GetByID"))
}

func TestUserUseCase_GetMe_NotFound(t *testing.T) {
	f := newUserFixture()
	f.users.GetByIDFunc = func(_ context.Context, _ uuid.UUID) (*domain.User, error) {
		return nil, domain.ErrNotFound
	}

	got, err := f.uc.GetMe(context.Background(), uuid.New())

	assert.Nil(t, got)
	ue := requireUseCaseErr(t, err, ErrCodeNotFound)
	assert.Equal(t, messages.UserNotFound, ue.Message)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestUserUseCase_GetMe_InternalError(t *testing.T) {
	f := newUserFixture()
	dbErr := errors.New("db down")
	f.users.GetByIDFunc = func(_ context.Context, _ uuid.UUID) (*domain.User, error) {
		return nil, dbErr
	}

	got, err := f.uc.GetMe(context.Background(), uuid.New())

	assert.Nil(t, got)
	ue := requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Equal(t, messages.FailedToGetUser, ue.Message)
	assert.ErrorIs(t, err, dbErr)
}

func TestUserUseCase_GetByID_Success(t *testing.T) {
	f := newUserFixture()
	id := uuid.New()
	want := sampleUser(id)
	f.users.GetByIDFunc = func(_ context.Context, _ uuid.UUID) (*domain.User, error) { return want, nil }

	got, err := f.uc.GetByID(context.Background(), id)

	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestUserUseCase_GetByID_NotFound(t *testing.T) {
	f := newUserFixture()
	f.users.GetByIDFunc = func(_ context.Context, _ uuid.UUID) (*domain.User, error) {
		return nil, domain.ErrNotFound
	}

	got, err := f.uc.GetByID(context.Background(), uuid.New())

	assert.Nil(t, got)
	requireUseCaseErr(t, err, ErrCodeNotFound)
}

func TestUserUseCase_GetByID_InternalError(t *testing.T) {
	f := newUserFixture()
	f.users.GetByIDFunc = func(_ context.Context, _ uuid.UUID) (*domain.User, error) {
		return nil, errors.New("read timeout")
	}

	got, err := f.uc.GetByID(context.Background(), uuid.New())

	assert.Nil(t, got)
	requireUseCaseErr(t, err, ErrCodeInternal)
}

// ---------- List ----------

func TestUserUseCase_List_WithPagination(t *testing.T) {
	f := newUserFixture()
	page := &domain.UserListResult{
		Items:      []domain.User{*sampleUser(uuid.New()), *sampleUser(uuid.New())},
		Page:       2,
		Limit:      20,
		Total:      45,
		TotalPages: 3,
	}
	var gotFilter domain.UserListFilter
	f.users.ListFunc = func(_ context.Context, filter domain.UserListFilter) (*domain.UserListResult, error) {
		gotFilter = filter
		return page, nil
	}

	result, err := f.uc.List(context.Background(), ListUsersInput{Page: 2, Limit: 20})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, page, result)
	// Параметры пагинации пробрасываются в репозиторий без изменений.
	assert.Equal(t, 2, gotFilter.Page)
	assert.Equal(t, 20, gotFilter.Limit)
	assert.Empty(t, gotFilter.Search)
	assert.Empty(t, gotFilter.Role)
	assert.Empty(t, gotFilter.Status)
}

func TestUserUseCase_List_WithSearch(t *testing.T) {
	f := newUserFixture()
	var gotFilter domain.UserListFilter
	f.users.ListFunc = func(_ context.Context, filter domain.UserListFilter) (*domain.UserListResult, error) {
		gotFilter = filter
		return &domain.UserListResult{Page: 1, Limit: 10}, nil
	}

	_, err := f.uc.List(context.Background(), ListUsersInput{
		Page:   1,
		Limit:  10,
		Search: "   Ivan   Ivanov  ",
	})

	require.NoError(t, err)
	assert.Equal(t, "Ivan   Ivanov", gotFilter.Search, "поисковый запрос нормализуется (trim)")
}

func TestUserUseCase_List_RoleAndStatusFiltersNormalized(t *testing.T) {
	f := newUserFixture()
	var gotFilter domain.UserListFilter
	f.users.ListFunc = func(_ context.Context, filter domain.UserListFilter) (*domain.UserListResult, error) {
		gotFilter = filter
		return &domain.UserListResult{}, nil
	}

	_, err := f.uc.List(context.Background(), ListUsersInput{Role: " ADMIN ", Status: "Active"})

	require.NoError(t, err)
	assert.Equal(t, domain.RoleAdmin, gotFilter.Role, "роль приводится к нижнему регистру")
	assert.Equal(t, domain.StatusActive, gotFilter.Status, "статус приводится к нижнему регистру")
}

func TestUserUseCase_List_InvalidRole(t *testing.T) {
	f := newUserFixture()

	result, err := f.uc.List(context.Background(), ListUsersInput{Role: "superuser"})

	assert.Nil(t, result)
	ue := requireUseCaseErr(t, err, ErrCodeValidation)
	assert.Equal(t, messages.InvalidParameterValue, ue.Message)
	assert.NotEmpty(t, ue.Details["role"])
	assert.Zero(t, f.users.CountCalls("List"), "репозиторий не вызывается при невалидном фильтре")
}

func TestUserUseCase_List_InvalidStatus(t *testing.T) {
	f := newUserFixture()

	result, err := f.uc.List(context.Background(), ListUsersInput{Status: "banned"})

	assert.Nil(t, result)
	ue := requireUseCaseErr(t, err, ErrCodeValidation)
	assert.NotEmpty(t, ue.Details["status"])
	assert.Zero(t, f.users.CountCalls("List"))
}

func TestUserUseCase_List_SearchTooLong(t *testing.T) {
	f := newUserFixture()

	result, err := f.uc.List(context.Background(), ListUsersInput{Search: strings.Repeat("q", 201)})

	assert.Nil(t, result)
	requireUseCaseErr(t, err, ErrCodeValidation)
	assert.Zero(t, f.users.CountCalls("List"))
}

func TestUserUseCase_List_RepositoryFailure(t *testing.T) {
	f := newUserFixture()
	dbErr := errors.New("list query failed")
	f.users.ListFunc = func(_ context.Context, _ domain.UserListFilter) (*domain.UserListResult, error) {
		return nil, dbErr
	}

	result, err := f.uc.List(context.Background(), ListUsersInput{Page: 1, Limit: 10})

	assert.Nil(t, result)
	ue := requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Equal(t, messages.FailedToGetUsersList, ue.Message)
	assert.ErrorIs(t, err, dbErr)
}

// ---------- Create (админ) ----------

func validCreateInput() CreateUserInput {
	return CreateUserInput{
		Email:     "New.User@Example.COM",
		Password:  "strongpass123",
		FirstName: "New",
		LastName:  "User",
	}
}

func TestUserUseCase_AdminCreate_Success(t *testing.T) {
	f := newUserFixture()
	f.users.CreateFunc = func(_ context.Context, email, hash, role, first, last string) (*domain.User, error) {
		return &domain.User{
			ID: uuid.New(), Email: email, PasswordHash: hash,
			Role: role, Status: domain.StatusActive, FirstName: first, LastName: last,
		}, nil
	}

	user, err := f.uc.Create(context.Background(), validCreateInput())

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "new.user@example.com", user.Email, "email нормализуется")
	assert.Equal(t, domain.RoleUser, user.Role, "пустая роль по умолчанию -> user")
	assert.Equal(t, "hash:strongpass123", user.PasswordHash, "пароль хешируется до записи")
}

func TestUserUseCase_AdminCreate_ExplicitAdminRole(t *testing.T) {
	f := newUserFixture()
	f.users.CreateFunc = func(_ context.Context, email, hash, role, first, last string) (*domain.User, error) {
		return &domain.User{ID: uuid.New(), Email: email, Role: role, Status: domain.StatusActive}, nil
	}
	in := validCreateInput()
	in.Role = " ADMIN "

	user, err := f.uc.Create(context.Background(), in)

	require.NoError(t, err)
	assert.Equal(t, domain.RoleAdmin, user.Role)
}

func TestUserUseCase_AdminCreate_ValidationError(t *testing.T) {
	f := newUserFixture()
	in := validCreateInput()
	in.Email = "bad-email"
	in.Password = "short"

	user, err := f.uc.Create(context.Background(), in)

	assert.Nil(t, user)
	ue := requireUseCaseErr(t, err, ErrCodeValidation)
	assert.Equal(t, messages.CheckRequiredFields, ue.Message)
	assert.Zero(t, f.users.CountCalls("Create"))
}

func TestUserUseCase_AdminCreate_InvalidRole(t *testing.T) {
	f := newUserFixture()
	in := validCreateInput()
	in.Role = "moderator" // не проходит валидацию ролей

	user, err := f.uc.Create(context.Background(), in)

	assert.Nil(t, user)
	ue := requireUseCaseErr(t, err, ErrCodeValidation)
	assert.NotEmpty(t, ue.Details["role"])
	assert.Zero(t, f.users.CountCalls("Create"))
}

func TestUserUseCase_AdminCreate_DuplicateEmail(t *testing.T) {
	f := newUserFixture()
	f.users.CreateFunc = func(_ context.Context, _, _, _, _, _ string) (*domain.User, error) {
		return nil, domain.ErrConflict
	}

	user, err := f.uc.Create(context.Background(), validCreateInput())

	assert.Nil(t, user)
	ue := requireUseCaseErr(t, err, ErrCodeConflict)
	assert.Equal(t, messages.EmailAlreadyUsed, ue.Message)
	assert.ErrorIs(t, err, domain.ErrConflict)
}

func TestUserUseCase_AdminCreate_HashFailure(t *testing.T) {
	f := newUserFixture()
	f.hasher.HashFunc = func(string) (string, error) { return "", errors.New("hasher unavailable") }

	user, err := f.uc.Create(context.Background(), validCreateInput())

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Zero(t, f.users.CountCalls("Create"))
}

func TestUserUseCase_AdminCreate_RepositoryFailure(t *testing.T) {
	f := newUserFixture()
	repoErr := errors.New("insert failed")
	f.users.CreateFunc = func(_ context.Context, _, _, _, _, _ string) (*domain.User, error) {
		return nil, repoErr
	}

	user, err := f.uc.Create(context.Background(), validCreateInput())

	assert.Nil(t, user)
	ue := requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Equal(t, messages.FailedToCreateUser, ue.Message)
	assert.ErrorIs(t, err, repoErr)
}

// ---------- ReplaceProfile (PUT /me) ----------

func TestUserUseCase_ReplaceProfile_Success(t *testing.T) {
	f := newUserFixture()
	id := uuid.New()
	f.users.ReplaceProfileFunc = func(_ context.Context, got uuid.UUID, email, first, last string) (*domain.User, error) {
		assert.Equal(t, id, got)
		assert.Equal(t, "updated@example.com", email)
		assert.Equal(t, "Updated", first)
		assert.Equal(t, "Profile", last)
		u := sampleUser(id)
		u.Email, u.FirstName, u.LastName = email, first, last
		return u, nil
	}

	user, err := f.uc.ReplaceProfile(context.Background(), ReplaceProfileInput{
		UserID:    id,
		Email:     "Updated@Example.com",
		FirstName: "Updated",
		LastName:  "Profile",
	})

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "updated@example.com", user.Email)
	assert.Equal(t, "Updated", user.FirstName)
}

func TestUserUseCase_ReplaceProfile_ValidationError(t *testing.T) {
	f := newUserFixture()

	user, err := f.uc.ReplaceProfile(context.Background(), ReplaceProfileInput{
		UserID:    uuid.New(),
		Email:     "no-at-sign",
		FirstName: "",
		LastName:  "",
	})

	assert.Nil(t, user)
	ue := requireUseCaseErr(t, err, ErrCodeValidation)
	assert.NotEmpty(t, ue.Details["email"])
	assert.NotEmpty(t, ue.Details["first_name"])
	assert.NotEmpty(t, ue.Details["last_name"])
	assert.Zero(t, f.users.CountCalls("ReplaceProfile"))
}

func TestUserUseCase_ReplaceProfile_EmailConflict(t *testing.T) {
	f := newUserFixture()
	f.users.ReplaceProfileFunc = func(_ context.Context, _ uuid.UUID, _, _, _ string) (*domain.User, error) {
		return nil, domain.ErrConflict
	}

	user, err := f.uc.ReplaceProfile(context.Background(), ReplaceProfileInput{
		UserID: uuid.New(), Email: "taken@example.com", FirstName: "A", LastName: "B",
	})

	assert.Nil(t, user)
	ue := requireUseCaseErr(t, err, ErrCodeConflict)
	assert.Equal(t, messages.EmailAlreadyUsed, ue.Message)
}

func TestUserUseCase_ReplaceProfile_NotFound(t *testing.T) {
	f := newUserFixture()
	f.users.ReplaceProfileFunc = func(_ context.Context, _ uuid.UUID, _, _, _ string) (*domain.User, error) {
		return nil, domain.ErrNotFound
	}

	user, err := f.uc.ReplaceProfile(context.Background(), ReplaceProfileInput{
		UserID: uuid.New(), Email: "x@example.com", FirstName: "A", LastName: "B",
	})

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeNotFound)
}

func TestUserUseCase_ReplaceProfile_InternalError(t *testing.T) {
	f := newUserFixture()
	f.users.ReplaceProfileFunc = func(_ context.Context, _ uuid.UUID, _, _, _ string) (*domain.User, error) {
		return nil, errors.New("update failed")
	}

	user, err := f.uc.ReplaceProfile(context.Background(), ReplaceProfileInput{
		UserID: uuid.New(), Email: "x@example.com", FirstName: "A", LastName: "B",
	})

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeInternal)
}

// ---------- UpdateOwnProfile (PATCH /me) ----------

func TestUserUseCase_UpdateMe_Success(t *testing.T) {
	f := newUserFixture()
	id := uuid.New()
	var gotEmail, gotFirst, gotLast, gotHash, gotStatus *string
	f.users.UpdateFunc = func(_ context.Context, got uuid.UUID, email, first, last, passwordHash, status *string) (*domain.User, error) {
		assert.Equal(t, id, got)
		gotEmail, gotFirst, gotLast, gotHash, gotStatus = email, first, last, passwordHash, status
		u := sampleUser(id)
		if email != nil {
			u.Email = *email
		}
		if first != nil {
			u.FirstName = *first
		}
		return u, nil
	}

	user, err := f.uc.UpdateOwnProfile(context.Background(), UpdateOwnProfileInput{
		UserID:    id,
		Email:     strPtr("  new@example.com  "),
		FirstName: strPtr("NewName"),
	})

	require.NoError(t, err)
	require.NotNil(t, user)
	require.NotNil(t, gotEmail)
	assert.Equal(t, "new@example.com", *gotEmail, "email нормализуется перед обновлением")
	require.NotNil(t, gotFirst)
	assert.Equal(t, "NewName", *gotFirst)
	assert.Nil(t, gotLast, "незаданные поля передаются как nil (не менять)")
	// Пользователь НЕ может менять себе пароль/роль/статус через PATCH /me.
	assert.Nil(t, gotHash, "смена пароля недоступна в собственном профиле")
	assert.Nil(t, gotStatus, "смена статуса недоступна в собственном профиле")
}

func TestUserUseCase_UpdateMe_EmptyBody(t *testing.T) {
	f := newUserFixture()

	user, err := f.uc.UpdateOwnProfile(context.Background(), UpdateOwnProfileInput{UserID: uuid.New()})

	assert.Nil(t, user)
	ue := requireUseCaseErr(t, err, ErrCodeValidation)
	assert.Equal(t, messages.EmptyUpdateData, ue.Message)
	assert.NotEmpty(t, ue.Details["body"])
	assert.Zero(t, f.users.CountCalls("Update"))
}

func TestUserUseCase_UpdateMe_InvalidEmail(t *testing.T) {
	f := newUserFixture()

	user, err := f.uc.UpdateOwnProfile(context.Background(), UpdateOwnProfileInput{
		UserID: uuid.New(),
		Email:  strPtr("invalid"),
	})

	assert.Nil(t, user)
	ue := requireUseCaseErr(t, err, ErrCodeValidation)
	assert.NotEmpty(t, ue.Details["email"])
}

func TestUserUseCase_UpdateMe_BlankNames(t *testing.T) {
	tests := []struct {
		name  string
		input UpdateOwnProfileInput
		field string
	}{
		{"blank first name", UpdateOwnProfileInput{UserID: uuid.New(), FirstName: strPtr("   ")}, "first_name"},
		{"blank last name", UpdateOwnProfileInput{UserID: uuid.New(), LastName: strPtr("  ")}, "last_name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newUserFixture()

			user, err := f.uc.UpdateOwnProfile(context.Background(), tt.input)

			assert.Nil(t, user)
			ue := requireUseCaseErr(t, err, ErrCodeValidation)
			assert.NotEmpty(t, ue.Details[tt.field])
		})
	}
}

func TestUserUseCase_UpdateMe_EmailConflict(t *testing.T) {
	f := newUserFixture()
	f.users.UpdateFunc = func(_ context.Context, _ uuid.UUID, _, _, _, _, _ *string) (*domain.User, error) {
		return nil, domain.ErrConflict
	}

	user, err := f.uc.UpdateOwnProfile(context.Background(), UpdateOwnProfileInput{
		UserID: uuid.New(), Email: strPtr("taken@example.com"),
	})

	assert.Nil(t, user)
	ue := requireUseCaseErr(t, err, ErrCodeConflict)
	assert.Equal(t, messages.EmailAlreadyUsed, ue.Message)
}

func TestUserUseCase_UpdateMe_NotFound(t *testing.T) {
	f := newUserFixture()
	f.users.UpdateFunc = func(_ context.Context, _ uuid.UUID, _, _, _, _, _ *string) (*domain.User, error) {
		return nil, domain.ErrNotFound
	}

	user, err := f.uc.UpdateOwnProfile(context.Background(), UpdateOwnProfileInput{
		UserID: uuid.New(), FirstName: strPtr("X"),
	})

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeNotFound)
}

func TestUserUseCase_UpdateMe_InternalError(t *testing.T) {
	f := newUserFixture()
	f.users.UpdateFunc = func(_ context.Context, _ uuid.UUID, _, _, _, _, _ *string) (*domain.User, error) {
		return nil, errors.New("deadlock detected")
	}

	user, err := f.uc.UpdateOwnProfile(context.Background(), UpdateOwnProfileInput{
		UserID: uuid.New(), FirstName: strPtr("X"),
	})

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeInternal)
}

// ---------- AdminReplace (PUT /users/{id}) ----------

func validAdminReplaceInput(id uuid.UUID) AdminReplaceUserInput {
	return AdminReplaceUserInput{
		ID:        id,
		Email:     "replaced@example.com",
		Password:  "newpassword123",
		FirstName: "Replaced",
		LastName:  "User",
		Status:    domain.StatusActive,
	}
}

func TestUserUseCase_AdminReplace_Success(t *testing.T) {
	f := newUserFixture()
	id := uuid.New()
	var gotHash, gotStatus string
	f.users.ReplaceFunc = func(_ context.Context, got uuid.UUID, email, first, last, passwordHash, status string) (*domain.User, error) {
		assert.Equal(t, id, got)
		gotHash, gotStatus = passwordHash, status
		return &domain.User{ID: got, Email: email, Role: domain.RoleUser, Status: status, FirstName: first, LastName: last}, nil
	}

	user, err := f.uc.AdminReplace(context.Background(), validAdminReplaceInput(id))

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "replaced@example.com", user.Email)
	assert.Equal(t, "hash:newpassword123", gotHash, "пароль перезаписывается через хеш")
	assert.Equal(t, domain.StatusActive, gotStatus)
}

func TestUserUseCase_AdminReplace_ValidationError(t *testing.T) {
	f := newUserFixture()
	in := validAdminReplaceInput(uuid.New())
	in.Email = "bad"
	in.Password = "short"
	in.FirstName = ""
	in.LastName = ""
	in.Status = "deleted"

	user, err := f.uc.AdminReplace(context.Background(), in)

	assert.Nil(t, user)
	ue := requireUseCaseErr(t, err, ErrCodeValidation)
	for _, field := range []string{"email", "password", "first_name", "last_name", "status"} {
		assert.NotEmpty(t, ue.Details[field], "ожидалась ошибка для поля %s", field)
	}
	assert.Zero(t, f.users.CountCalls("Replace"))
}

func TestUserUseCase_AdminReplace_NotFound(t *testing.T) {
	f := newUserFixture()
	f.users.ReplaceFunc = func(_ context.Context, _ uuid.UUID, _, _, _, _, _ string) (*domain.User, error) {
		return nil, domain.ErrNotFound
	}

	user, err := f.uc.AdminReplace(context.Background(), validAdminReplaceInput(uuid.New()))

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeNotFound)
}

func TestUserUseCase_AdminReplace_EmailConflict(t *testing.T) {
	f := newUserFixture()
	f.users.ReplaceFunc = func(_ context.Context, _ uuid.UUID, _, _, _, _, _ string) (*domain.User, error) {
		return nil, domain.ErrConflict
	}

	user, err := f.uc.AdminReplace(context.Background(), validAdminReplaceInput(uuid.New()))

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeConflict)
}

func TestUserUseCase_AdminReplace_HashFailure(t *testing.T) {
	f := newUserFixture()
	f.hasher.HashFunc = func(string) (string, error) { return "", errors.New("hasher down") }

	user, err := f.uc.AdminReplace(context.Background(), validAdminReplaceInput(uuid.New()))

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Zero(t, f.users.CountCalls("Replace"))
}

func TestUserUseCase_AdminReplace_InternalError(t *testing.T) {
	f := newUserFixture()
	f.users.ReplaceFunc = func(_ context.Context, _ uuid.UUID, _, _, _, _, _ string) (*domain.User, error) {
		return nil, errors.New("fk violation")
	}

	user, err := f.uc.AdminReplace(context.Background(), validAdminReplaceInput(uuid.New()))

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeInternal)
}

// ---------- AdminUpdate (PATCH /users/{id}) ----------

func TestUserUseCase_AdminUpdate_Success(t *testing.T) {
	f := newUserFixture()
	id := uuid.New()
	f.users.UpdateFunc = func(_ context.Context, got uuid.UUID, email, first, last, passwordHash, status *string) (*domain.User, error) {
		assert.Equal(t, id, got)
		require.NotNil(t, email)
		assert.Equal(t, "changed@example.com", *email)
		assert.Nil(t, passwordHash, "без смены пароля хеш не трогаем")
		u := sampleUser(got)
		u.Email = *email
		return u, nil
	}
	var revoked bool
	f.tokens.RevokeAllForUserFunc = func(_ context.Context, _ uuid.UUID) error {
		revoked = true
		return nil
	}

	user, err := f.uc.AdminUpdate(context.Background(), AdminUpdateUserInput{
		ID:    id,
		Email: strPtr("Changed@Example.com"),
	})

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.False(t, revoked, "при обновлении без пароля сессии НЕ отзываются")
}

func TestUserUseCase_AdminUpdate_WithPasswordChange(t *testing.T) {
	f := newUserFixture()
	userID := uuid.New()
	var updatedHash *string
	f.users.UpdateFunc = func(_ context.Context, _ uuid.UUID, _, _, _, passwordHash, _ *string) (*domain.User, error) {
		updatedHash = passwordHash
		u := sampleUser(userID)
		if passwordHash != nil {
			u.PasswordHash = *passwordHash
		}
		return u, nil
	}
	var revokedSessions bool
	var revokedFor uuid.UUID
	f.tokens.RevokeAllForUserFunc = func(_ context.Context, uid uuid.UUID) error {
		revokedSessions = true
		revokedFor = uid
		return nil
	}

	user, err := f.uc.AdminUpdate(context.Background(), AdminUpdateUserInput{
		ID:       userID,
		Password: strPtr("brand-new-password"),
	})

	require.NoError(t, err)
	require.NotNil(t, user)
	require.NotNil(t, updatedHash, "новый хеш пароля должен быть передан в репозиторий")
	assert.Equal(t, "hash:brand-new-password", *updatedHash)
	assert.True(t, revokedSessions, "Сессии должны быть отозваны при смене пароля")
	assert.Equal(t, userID, revokedFor)
}

func TestUserUseCase_AdminUpdate_PasswordChange_RevokesSessions(t *testing.T) {
	// Отдельный сценарий из ТЗ: отзыв всех сессий при смене пароля админом.
	f := newUserFixture()
	userID := uuid.New()
	f.users.UpdateFunc = func(_ context.Context, _ uuid.UUID, _, _, _, _, _ *string) (*domain.User, error) {
		return sampleUser(userID), nil
	}
	var revokedSessions bool
	f.tokens.RevokeAllForUserFunc = func(_ context.Context, uid uuid.UUID) error {
		revokedSessions = true
		assert.Equal(t, userID, uid)
		return nil
	}

	_, err := f.uc.AdminUpdate(context.Background(), AdminUpdateUserInput{
		ID:       userID,
		Password: strPtr("newpassword123"),
	})

	require.NoError(t, err)
	assert.True(t, revokedSessions, "Сессии должны быть отозваны при смене пароля")
	assert.Equal(t, 1, f.tokens.CountCalls("RevokeAllForUser"))
}

func TestUserUseCase_AdminUpdate_RevokeFailure_StillSucceeds(t *testing.T) {
	// Сбой отзыва сессий не должен ломать уже выполненное обновление:
	// пользователь обновлён, ошибка только логируется.
	f := newUserFixture()
	userID := uuid.New()
	f.users.UpdateFunc = func(_ context.Context, _ uuid.UUID, _, _, _, _, _ *string) (*domain.User, error) {
		return sampleUser(userID), nil
	}
	f.tokens.RevokeAllForUserFunc = func(_ context.Context, _ uuid.UUID) error {
		return errors.New("db timeout")
	}

	user, err := f.uc.AdminUpdate(context.Background(), AdminUpdateUserInput{
		ID:       userID,
		Password: strPtr("newpassword123"),
	})

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, 1, f.tokens.CountCalls("RevokeAllForUser"))
}

func TestUserUseCase_AdminUpdate_ValidationErrors(t *testing.T) {
	tests := []struct {
		name  string
		input func(id uuid.UUID) AdminUpdateUserInput
		field string
	}{
		{"invalid email", func(id uuid.UUID) AdminUpdateUserInput {
			return AdminUpdateUserInput{ID: id, Email: strPtr("not-an-email")}
		}, "email"},
		{"empty email after trim", func(id uuid.UUID) AdminUpdateUserInput {
			return AdminUpdateUserInput{ID: id, Email: strPtr("   ")}
		}, "email"},
		{"blank first name", func(id uuid.UUID) AdminUpdateUserInput {
			return AdminUpdateUserInput{ID: id, FirstName: strPtr(" ")}
		}, "first_name"},
		{"blank last name", func(id uuid.UUID) AdminUpdateUserInput {
			return AdminUpdateUserInput{ID: id, LastName: strPtr(" ")}
		}, "last_name"},
		{"invalid status", func(id uuid.UUID) AdminUpdateUserInput {
			return AdminUpdateUserInput{ID: id, Status: strPtr("archived")}
		}, "status"},
		{"short password", func(id uuid.UUID) AdminUpdateUserInput {
			return AdminUpdateUserInput{ID: id, Password: strPtr("short")}
		}, "password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newUserFixture()
			id := uuid.New()

			user, err := f.uc.AdminUpdate(context.Background(), tt.input(id))

			assert.Nil(t, user)
			ue := requireUseCaseErr(t, err, ErrCodeValidation)
			assert.NotEmpty(t, ue.Details[tt.field])
			assert.Zero(t, f.users.CountCalls("Update"), "репозиторий не вызывается при ошибке валидации")
		})
	}
}

func TestUserUseCase_AdminUpdate_HashFailure(t *testing.T) {
	f := newUserFixture()
	f.hasher.HashFunc = func(string) (string, error) { return "", errors.New("hasher down") }

	user, err := f.uc.AdminUpdate(context.Background(), AdminUpdateUserInput{
		ID:       uuid.New(),
		Password: strPtr("validpassword123"),
	})

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Zero(t, f.users.CountCalls("Update"))
}

func TestUserUseCase_AdminUpdate_NotFound(t *testing.T) {
	f := newUserFixture()
	f.users.UpdateFunc = func(_ context.Context, _ uuid.UUID, _, _, _, _, _ *string) (*domain.User, error) {
		return nil, domain.ErrNotFound
	}

	user, err := f.uc.AdminUpdate(context.Background(), AdminUpdateUserInput{
		ID: uuid.New(), FirstName: strPtr("Z"),
	})

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeNotFound)
}

func TestUserUseCase_AdminUpdate_EmailConflict(t *testing.T) {
	f := newUserFixture()
	f.users.UpdateFunc = func(_ context.Context, _ uuid.UUID, _, _, _, _, _ *string) (*domain.User, error) {
		return nil, domain.ErrConflict
	}

	user, err := f.uc.AdminUpdate(context.Background(), AdminUpdateUserInput{
		ID: uuid.New(), Email: strPtr("taken@example.com"),
	})

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeConflict)
}

func TestUserUseCase_AdminUpdate_InternalError(t *testing.T) {
	f := newUserFixture()
	f.users.UpdateFunc = func(_ context.Context, _ uuid.UUID, _, _, _, _, _ *string) (*domain.User, error) {
		return nil, errors.New("serialization failure")
	}

	user, err := f.uc.AdminUpdate(context.Background(), AdminUpdateUserInput{
		ID: uuid.New(), FirstName: strPtr("Z"),
	})

	assert.Nil(t, user)
	requireUseCaseErr(t, err, ErrCodeInternal)
}

// ---------- Delete ----------

func TestUserUseCase_AdminDelete_Success(t *testing.T) {
	f := newUserFixture()
	target, principal := uuid.New(), uuid.New()
	var deleted uuid.UUID
	f.users.DeleteFunc = func(_ context.Context, id uuid.UUID) error {
		deleted = id
		return nil
	}

	err := f.uc.Delete(context.Background(), DeleteUserInput{TargetID: target, PrincipalID: principal})

	require.NoError(t, err)
	assert.Equal(t, target, deleted)
}

func TestUserUseCase_AdminDelete_CannotDeleteSelf(t *testing.T) {
	f := newUserFixture()
	self := uuid.New()
	f.users.DeleteFunc = func(_ context.Context, _ uuid.UUID) error {
		t.Fatal("репозиторий не должен вызываться при попытке self-delete")
		return nil
	}

	err := f.uc.Delete(context.Background(), DeleteUserInput{TargetID: self, PrincipalID: self})

	ue := requireUseCaseErr(t, err, ErrCodeForbidden)
	assert.Equal(t, messages.AdminCannotDeleteSelf, ue.Message)
	assert.Zero(t, f.users.CountCalls("Delete"))
}

func TestUserUseCase_AdminDelete_NotFound(t *testing.T) {
	f := newUserFixture()
	f.users.DeleteFunc = func(_ context.Context, _ uuid.UUID) error { return domain.ErrNotFound }

	err := f.uc.Delete(context.Background(), DeleteUserInput{TargetID: uuid.New(), PrincipalID: uuid.New()})

	ue := requireUseCaseErr(t, err, ErrCodeNotFound)
	assert.Equal(t, messages.UserNotFound, ue.Message)
}

func TestUserUseCase_AdminDelete_ProtectedAdminAccount(t *testing.T) {
	f := newUserFixture()
	f.users.DeleteFunc = func(_ context.Context, _ uuid.UUID) error { return domain.ErrProtected }

	err := f.uc.Delete(context.Background(), DeleteUserInput{TargetID: uuid.New(), PrincipalID: uuid.New()})

	ue := requireUseCaseErr(t, err, ErrCodeForbidden)
	assert.Equal(t, messages.CannotDeleteAdminAccount, ue.Message)
	assert.ErrorIs(t, err, domain.ErrProtected)
}

func TestUserUseCase_AdminDelete_InternalError(t *testing.T) {
	f := newUserFixture()
	dbErr := errors.New("fk constraint: users still own resources")
	f.users.DeleteFunc = func(_ context.Context, _ uuid.UUID) error { return dbErr }

	err := f.uc.Delete(context.Background(), DeleteUserInput{TargetID: uuid.New(), PrincipalID: uuid.New()})

	ue := requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Equal(t, messages.FailedToDeleteUser, ue.Message)
	assert.ErrorIs(t, err, dbErr)
}

// ---------- Классификация ошибок (HTTP-адаптер) ----------

func TestErrorCode_HTTPStatus(t *testing.T) {
	cases := map[ErrorCode]int{
		ErrCodeInternal:     500,
		ErrCodeValidation:   400,
		ErrCodeUnauthorized: 401,
		ErrCodeForbidden:    403,
		ErrCodeNotFound:     404,
		ErrCodeConflict:     409,
		ErrCodeUnavailable:  503,
	}
	for code, want := range cases {
		assert.Equal(t, want, code.HTTPStatus(), "код %d -> HTTP %d", code, want)
	}
}

func TestUseCaseError_UnwrapAndMessages(t *testing.T) {
	inner := errors.New("root cause")
	ue := &UseCaseError{Code: ErrCodeInternal, Message: "boom", Err: inner}
	assert.Equal(t, "boom: root cause", ue.Error())
	assert.ErrorIs(t, ue, inner)

	withoutInner := &UseCaseError{Code: ErrCodeNotFound, Message: "missing"}
	assert.Equal(t, "missing", withoutInner.Error())
	assert.NoError(t, withoutInner.Unwrap())
}

var _ = time.Now // на случай расширения тестов работой со временем
