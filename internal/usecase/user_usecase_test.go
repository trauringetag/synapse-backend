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

func TestUserUseCase_AdminUpdate_WithPasswordChange_RevokesSessions(t *testing.T) {
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

	var revokedFor uuid.UUID
	f.tokens.RevokeAllForUserFunc = func(_ context.Context, uid uuid.UUID) error {
		revokedFor = uid
		return nil
	}

	// Act
	user, err := f.uc.AdminUpdate(context.Background(), AdminUpdateUserInput{
		ID:       userID,
		Password: strPtr("brand-new-password"),
	})

	// Assert
	require.NoError(t, err)
	require.NotNil(t, user)

	// 1. Проверяем, что пароль захеширован
	require.NotNil(t, updatedHash, "новый хеш пароля должен быть передан в репозиторий")
	assert.Equal(t, "hash:brand-new-password", *updatedHash)

	// 2. Проверяем, что сессии отозваны
	assert.Equal(t, userID, revokedFor, "Сессии должны быть отозваны для правильного пользователя")
	assert.Equal(t, 1, f.tokens.CountCalls("RevokeAllForUser"), "RevokeAllForUser должен быть вызван ровно один раз")
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

// ---------- DeleteMe (самоудаление / hard delete, DELETE /users/me) ----------

func TestUserUseCase_DeleteMe(t *testing.T) {
	dbErr := errors.New("db connection broken")

	tests := []struct {
		name string

		getFunc    func(ctx context.Context, id uuid.UUID) (*domain.User, error)
		revokeFunc func(ctx context.Context, id uuid.UUID) error
		deleteFunc     func(ctx context.Context, id uuid.UUID) error
deleteSelfFunc func(ctx context.Context, id uuid.UUID) error

		wantErr     bool
		wantCode    ErrorCode
		wantMessage string
		wantErrIs   error // errors.Is для обёрнутой доменной ошибки (опционально)
		wantRevokes int   // сколько раз должен быть вызван RevokeAllForUser
		wantDeletes int   // сколько раз должен быть вызван users.Delete
	}{
		{
			name: "success: hard delete + revoke all sessions",
			getFunc: func(_ context.Context, id uuid.UUID) (*domain.User, error) {
				return sampleUser(id), nil
			},
			revokeFunc:  func(_ context.Context, _ uuid.UUID) error { return nil },
			deleteFunc:  func(_ context.Context, _ uuid.UUID) error { return nil },
			wantErr:     false,
			wantRevokes: 1,
			wantDeletes: 1,
		},
		{
			name: "user not found -> 404, no revoke, no delete",
			getFunc: func(_ context.Context, _ uuid.UUID) (*domain.User, error) {
				return nil, domain.ErrNotFound
			},
			wantErr:     true,
			wantCode:    ErrCodeNotFound,
			wantMessage: messages.UserNotFound,
			wantErrIs:   domain.ErrNotFound,
			wantRevokes: 0,
			wantDeletes: 0,
		},
		{
			name: "already inactive -> conflict, no revoke, no delete",
			getFunc: func(_ context.Context, id uuid.UUID) (*domain.User, error) {
				u := sampleUser(id)
				u.Status = domain.StatusInactive
				return u, nil
			},
			wantErr:     true,
			wantCode:    ErrCodeConflict,
			wantMessage: messages.AccountAlreadyInactive,
			wantRevokes: 0,
			wantDeletes: 0,
		},
		{
			name: "revoke failure is logged but operation continues (record still deleted)",
			getFunc: func(_ context.Context, id uuid.UUID) (*domain.User, error) {
				return sampleUser(id), nil
			},
			revokeFunc: func(_ context.Context, _ uuid.UUID) error {
				return errors.New("token store timeout")
			},
			deleteFunc:  func(_ context.Context, _ uuid.UUID) error { return nil },
			wantErr:     false, // частичный сбой отзыва не откатывает удаление
			wantRevokes: 1,
			wantDeletes: 1,
		},
		{
			name: "delete DB error -> internal error",
			getFunc: func(_ context.Context, id uuid.UUID) (*domain.User, error) {
				return sampleUser(id), nil
			},
			revokeFunc: func(_ context.Context, _ uuid.UUID) error { return nil },
			deleteFunc: func(_ context.Context, _ uuid.UUID) error {
				return dbErr
			},
			wantErr:     true,
			wantCode:    ErrCodeInternal,
			wantMessage: messages.FailedToDeleteUser,
			wantErrIs:   dbErr,
			wantRevokes: 1,
			wantDeletes: 1,
		},
		{
			name: "delete not found (race) -> 404",
			getFunc: func(_ context.Context, id uuid.UUID) (*domain.User, error) {
				return sampleUser(id), nil
			},
			revokeFunc: func(_ context.Context, _ uuid.UUID) error { return nil },
			deleteFunc: func(_ context.Context, _ uuid.UUID) error {
				return domain.ErrNotFound
			},
			wantErr:     true,
			wantCode:    ErrCodeNotFound,
			wantMessage: messages.UserNotFound,
			wantErrIs:   domain.ErrNotFound,
			wantRevokes: 1,
			wantDeletes: 1,
		},
		{
			name: "admin self-delete: Delete -> ErrProtected, fallback DeleteSelf succeeds",
			getFunc: func(_ context.Context, id uuid.UUID) (*domain.User, error) {
				u := sampleUser(id)
				u.Role = domain.RoleAdmin
				return u, nil
			},
			revokeFunc: func(_ context.Context, _ uuid.UUID) error { return nil },
			deleteFunc: func(_ context.Context, _ uuid.UUID) error {
				return domain.ErrProtected
			},
			deleteSelfFunc: func(_ context.Context, _ uuid.UUID) error { return nil },
			wantErr:        false,
			wantRevokes:    1,
			wantDeletes:    1, // один из двух методов удаления обязательно вызван
		},
		{
			name: "admin self-delete: DeleteSelf fails after ErrProtected -> internal error",
			getFunc: func(_ context.Context, id uuid.UUID) (*domain.User, error) {
				u := sampleUser(id)
				u.Role = domain.RoleAdmin
				return u, nil
			},
			revokeFunc: func(_ context.Context, _ uuid.UUID) error { return nil },
			deleteFunc: func(_ context.Context, _ uuid.UUID) error {
				return domain.ErrProtected
			},
			deleteSelfFunc: func(_ context.Context, _ uuid.UUID) error {
				return dbErr
			},
			wantErr:     true,
			wantCode:    ErrCodeInternal,
			wantMessage: messages.FailedToDeleteUser,
			wantErrIs:   dbErr,
			wantRevokes: 1,
			wantDeletes: 1,
		},
		{
			name: "get internal error -> internal error, no revoke/delete",
			getFunc: func(_ context.Context, _ uuid.UUID) (*domain.User, error) {
				return nil, dbErr
			},
			wantErr:     true,
			wantCode:    ErrCodeInternal,
			wantMessage: messages.FailedToGetUser,
			wantRevokes: 0,
			wantDeletes: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newUserFixture()
			userID := uuid.New()

			if tt.getFunc != nil {
				f.users.GetByIDFunc = tt.getFunc
			}
			if tt.revokeFunc != nil {
				f.tokens.RevokeAllForUserFunc = tt.revokeFunc
			}
			if tt.deleteFunc != nil {
				f.users.DeleteFunc = tt.deleteFunc
			}
			if tt.deleteSelfFunc != nil {
				f.users.DeleteSelfFunc = tt.deleteSelfFunc
			}

			err := f.uc.DeleteMe(context.Background(), userID)

			if tt.wantErr {
				require.Error(t, err)
				ue := requireUseCaseErr(t, err, tt.wantCode)
				assert.Equal(t, tt.wantMessage, ue.Message)
				if tt.wantErrIs != nil {
					assert.ErrorIs(t, err, tt.wantErrIs)
				}
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantRevokes, f.tokens.CountCalls("RevokeAllForUser"),
				"количество вызовов RevokeAllForUser")
			assert.Equal(t, tt.wantDeletes, f.users.CountCalls("Delete"),
				"количество вызовов users.Delete")

			// Порядок вызовов при успехе: GetByID -> Delete (или DeleteSelf для
			// admin-аккаунта), причём отзыв сессий выполняется строго перед
			// физическим удалением.
			if !tt.wantErr && tt.wantDeletes == 1 {
				var seq []string
				for _, c := range f.users.Calls() {
					seq = append(seq, c.method)
				}
				require.GreaterOrEqual(t, len(seq), 2)
				assert.Equal(t, "GetByID", seq[0])
				assert.Contains(t, []string{"Delete", "DeleteSelf"}, seq[len(seq)-1])
				assert.Equal(t, 1, f.tokens.CountCalls("RevokeAllForUser"))
			}
		})
	}
}

// ---------- AdminUpdate: политика деактивации (Задача 2) ----------

func TestUserUseCase_AdminUpdate_StatusInactive_RevokesSessions(t *testing.T) {
	// Перевод статуса в inactive обязан ровно один раз вызвать RevokeAllForUser.
	f := newUserFixture()
	id := uuid.New()
	f.users.UpdateFunc = func(_ context.Context, got uuid.UUID, _, _, _, _, status *string) (*domain.User, error) {
		require.NotNil(t, status)
		assert.Equal(t, domain.StatusInactive, *status)
		u := sampleUser(got)
		u.Status = *status
		return u, nil
	}
	var revokedFor uuid.UUID
	f.tokens.RevokeAllForUserFunc = func(_ context.Context, uid uuid.UUID) error {
		revokedFor = uid
		return nil
	}

	user, err := f.uc.AdminUpdate(context.Background(), AdminUpdateUserInput{
		ID:     id,
		Status: strPtr(domain.StatusInactive),
	})

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, domain.StatusInactive, user.Status)
	assert.Equal(t, id, revokedFor, "отзыв должен быть выполнен для целевого пользователя")
	assert.Equal(t, 1, f.tokens.CountCalls("RevokeAllForUser"),
		"при status=inactive RevokeAllForUser вызывается ровно 1 раз")
}

func TestUserUseCase_AdminUpdate_StatusActive_DoesNotRevoke(t *testing.T) {
	// Реактивация (active) без смены пароля сессии НЕ отзывает.
	f := newUserFixture()
	id := uuid.New()
	f.users.UpdateFunc = func(_ context.Context, got uuid.UUID, _, _, _, _, _ *string) (*domain.User, error) {
		return sampleUser(got), nil
	}

	user, err := f.uc.AdminUpdate(context.Background(), AdminUpdateUserInput{
		ID:     id,
		Status: strPtr(domain.StatusActive),
	})

	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, 0, f.tokens.CountCalls("RevokeAllForUser"))
}

// ---------- Delete (admin): отзыв сессий ДО физического удаления ----------

func TestUserUseCase_AdminDelete_Success_RevokesBeforeDelete(t *testing.T) {
	// Проверяем порядок: RevokeAllForUser строго до users.Delete.
	f := newUserFixture()
	target, principal := uuid.New(), uuid.New()

	var order []string
	f.tokens.RevokeAllForUserFunc = func(_ context.Context, uid uuid.UUID) error {
		assert.Equal(t, target, uid)
		order = append(order, "RevokeAllForUser")
		return nil
	}
	f.users.DeleteFunc = func(_ context.Context, id uuid.UUID) error {
		assert.Equal(t, target, id)
		order = append(order, "Delete")
		return nil
	}

	err := f.uc.Delete(context.Background(), DeleteUserInput{TargetID: target, PrincipalID: principal})

	require.NoError(t, err)
	assert.Equal(t, []string{"RevokeAllForUser", "Delete"}, order,
		"сессии должны отзываться до физического удаления")
}

func TestUserUseCase_AdminDelete_RevokeFailure_AbortsDelete(t *testing.T) {
	// Стратегия (зафиксирована в докстроке Delete): при сбое отзыва сессий
	// физическое удаление НЕ выполняется — возвращаем внутреннюю ошибку.
	f := newUserFixture()
	target, principal := uuid.New(), uuid.New()
	revokeErr := errors.New("token store unavailable")

	f.tokens.RevokeAllForUserFunc = func(_ context.Context, _ uuid.UUID) error {
		return revokeErr
	}
	f.users.DeleteFunc = func(_ context.Context, _ uuid.UUID) error {
		t.Fatal("users.Delete не должен вызываться при сбое отзыва сессий")
		return nil
	}

	err := f.uc.Delete(context.Background(), DeleteUserInput{TargetID: target, PrincipalID: principal})

	ue := requireUseCaseErr(t, err, ErrCodeInternal)
	assert.Equal(t, messages.FailedToDeleteUser, ue.Message)
	assert.ErrorIs(t, err, revokeErr)
	assert.Zero(t, f.users.CountCalls("Delete"))
	assert.Equal(t, 1, f.tokens.CountCalls("RevokeAllForUser"))
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
