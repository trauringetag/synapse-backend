package usecase

import (
	"context"
	"errors"
	"log"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/domain/models"
	"github.com/trauringetag/synapse-backend/internal/messages"
)

// UserUseCaseImpl — реализация UserUseCase. Содержит всю бизнес-логику
// управления пользователями, которая ранее находилась в HTTP-обработчике
// user_handler.go: валидацию и нормализацию полей, хеширование паролей,
// проверку допустимых ролей/статусов, отзыв сессий при смене пароля и
// защиту от удаления собственной учетной записи.
type UserUseCaseImpl struct {
	// Порты репозиториев — из домена (единственный источник правды: domain/ports.go).
	users  domain.UserRepository
	tokens domain.RefreshTokenRepository
	hasher PasswordHasher // порт хеширования паролей (реализация — в инфраструктуре)
}

// NewUserUseCase собирает сценарии работы с пользователями через DI.
func NewUserUseCase(users domain.UserRepository, tokens domain.RefreshTokenRepository, hasher PasswordHasher) *UserUseCaseImpl {
	return &UserUseCaseImpl{users: users, tokens: tokens, hasher: hasher}
}

var _ UserUseCase = (*UserUseCaseImpl)(nil)

// ---------- Чтение ----------

// GetMe возвращает профиль аутентифицированного пользователя.
func (uc *UserUseCaseImpl) GetMe(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	user, err := uc.users.GetByID(ctx, userID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, wrapErr(ErrCodeNotFound, messages.UserNotFound, err)
	}
	if err != nil {
		return nil, wrapErr(ErrCodeInternal, messages.FailedToGetUser, err)
	}
	return user, nil
}

// GetByID возвращает пользователя по идентификатору (админский сценарий).
func (uc *UserUseCaseImpl) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	user, err := uc.users.GetByID(ctx, id)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, wrapErr(ErrCodeNotFound, messages.UserNotFound, err)
	}
	if err != nil {
		return nil, wrapErr(ErrCodeInternal, messages.FailedToGetUser, err)
	}
	return user, nil
}

// List валидирует фильтры (role/status/search) и возвращает страницу
// пользователей. Нормализация регистров и пробелов — бизнес-правило.
func (uc *UserUseCaseImpl) List(ctx context.Context, in ListUsersInput) (*domain.UserListResult, error) {
	role := normalizeLower(in.Role)
	if role != "" && !validRole(role) {
		return nil, validationErr(messages.InvalidParameterValue, map[string][]string{"role": {messages.RoleInvalidValue}})
	}
	status := normalizeLower(in.Status)
	if status != "" && !validStatus(status) {
		return nil, validationErr(messages.InvalidParameterValue, map[string][]string{"status": {messages.StatusInvalidValue}})
	}
	search := normalizeName(in.Search)
	if len(search) > 200 {
		return nil, newErr(ErrCodeValidation, messages.InvalidParameterValue)
	}

	result, err := uc.users.List(ctx, domain.UserListFilter{
		Page:   in.Page,
		Limit:  in.Limit,
		Search: search,
		Role:   role,
		Status: status,
	})
	if err != nil {
		return nil, wrapErr(ErrCodeInternal, messages.FailedToGetUsersList, err)
	}
	return result, nil
}

// ---------- Создание (админ) ----------

// Create создает пользователя с указанной ролью (по умолчанию — user).
// Пароль хешируется через внедренный порт PasswordHasher; невалидная роль отклоняется.
func (uc *UserUseCaseImpl) Create(ctx context.Context, in CreateUserInput) (*models.User, error) {
	email := normalizeEmail(in.Email)
	first := normalizeName(in.FirstName)
	last := normalizeName(in.LastName)
	role := normalizeLower(in.Role)

	if !validEmail(email) || !validFirstName(first) || !validLastName(last) || !validPassword(in.Password) {
		return nil, validationErr(messages.CheckRequiredFields, map[string][]string{
			"email":      {messages.InvalidEmail},
			"first_name": {messages.FirstNameRequired},
			"last_name":  {messages.LastNameRequired},
			"password":   {messages.PasswordTooShort},
		})
	}
	if role == "" {
		role = models.RoleUser
	}
	if !validRole(role) {
		return nil, validationErr(messages.InvalidParameterValue, map[string][]string{"role": {messages.RoleInvalidValue}})
	}

	hash, err := uc.hasher.Hash(in.Password)
	if err != nil {
		return nil, wrapErr(ErrCodeInternal, messages.FailedToHashPassword, err)
	}
	user, err := uc.users.Create(ctx, email, hash, role, first, last)
	switch {
	case errors.Is(err, domain.ErrConflict):
		return nil, wrapErr(ErrCodeConflict, messages.EmailAlreadyUsed, err)
	case err != nil:
		return nil, wrapErr(ErrCodeInternal, messages.FailedToCreateUser, err)
	}
	return user, nil
}

// ---------- Обновление собственного профиля ----------

// ReplaceProfile полностью заменяет профиль самого пользователя (PUT /me).
func (uc *UserUseCaseImpl) ReplaceProfile(ctx context.Context, in ReplaceProfileInput) (*models.User, error) {
	email := normalizeEmail(in.Email)
	first := normalizeName(in.FirstName)
	last := normalizeName(in.LastName)

	if !validEmail(email) || !validFirstName(first) || !validLastName(last) {
		return nil, validationErr(messages.CheckRequiredFields, map[string][]string{
			"email":      {messages.InvalidEmail},
			"first_name": {messages.FirstNameRequired},
			"last_name":  {messages.LastNameRequired},
		})
	}

	user, err := uc.users.ReplaceProfile(ctx, in.UserID, email, first, last)
	switch {
	case errors.Is(err, domain.ErrConflict):
		return nil, wrapErr(ErrCodeConflict, messages.EmailAlreadyUsed, err)
	case errors.Is(err, domain.ErrNotFound):
		return nil, wrapErr(ErrCodeNotFound, messages.UserNotFound, err)
	case err != nil:
		return nil, wrapErr(ErrCodeInternal, messages.FailedToUpdateUser, err)
	}
	return user, nil
}

// UpdateOwnProfile частично обновляет собственный профиль (PATCH /me).
// Роль и статус здесь недоступны — пользователь не может менять их себе.
func (uc *UserUseCaseImpl) UpdateOwnProfile(ctx context.Context, in UpdateOwnProfileInput) (*models.User, error) {
	if in.Email == nil && in.FirstName == nil && in.LastName == nil {
		return nil, validationErr(messages.EmptyUpdateData, map[string][]string{"body": {messages.SpecifyAtLeastOneField}})
	}

	var email, first, last *string
	if in.Email != nil {
		v := normalizeEmail(*in.Email)
		if v == "" || !validEmail(v) {
			return nil, validationErr(messages.CheckRequiredFields, map[string][]string{"email": {messages.InvalidEmail}})
		}
		email = &v
	}
	if in.FirstName != nil {
		v := normalizeName(*in.FirstName)
		if v == "" {
			return nil, validationErr(messages.CheckRequiredFields, map[string][]string{"first_name": {messages.FirstNameRequired}})
		}
		first = &v
	}
	if in.LastName != nil {
		v := normalizeName(*in.LastName)
		if v == "" {
			return nil, validationErr(messages.CheckRequiredFields, map[string][]string{"last_name": {messages.LastNameRequired}})
		}
		last = &v
	}

	user, err := uc.users.Update(ctx, in.UserID, email, first, last, nil, nil)
	switch {
	case errors.Is(err, domain.ErrConflict):
		return nil, wrapErr(ErrCodeConflict, messages.EmailAlreadyUsed, err)
	case errors.Is(err, domain.ErrNotFound):
		return nil, wrapErr(ErrCodeNotFound, messages.UserNotFound, err)
	case err != nil:
		return nil, wrapErr(ErrCodeInternal, messages.FailedToUpdateUser, err)
	}
	return user, nil
}

// ---------- Админские замена/обновление ----------

// AdminReplace полностью заменяет карточку пользователя (PUT /users/{id}).
// Поле role намеренно не принимается: роль через PUT не меняется.
func (uc *UserUseCaseImpl) AdminReplace(ctx context.Context, in AdminReplaceUserInput) (*models.User, error) {
	email := normalizeEmail(in.Email)
	first := normalizeName(in.FirstName)
	last := normalizeName(in.LastName)
	status := normalizeLower(in.Status)

	details := make(map[string][]string)
	if !validEmail(email) {
		addDetail(details, "email", messages.InvalidEmail)
	}
	if !validPassword(in.Password) {
		addDetail(details, "password", messages.PasswordTooShort)
	}
	if !validFirstName(first) {
		addDetail(details, "first_name", messages.FirstNameRequired)
	}
	if !validLastName(last) {
		addDetail(details, "last_name", messages.LastNameRequired)
	}
	if !validStatus(status) {
		addDetail(details, "status", messages.StatusInvalidValue)
	}
	if len(details) > 0 {
		return nil, validationErr(messages.CheckRequiredFields, details)
	}

	hash, err := uc.hasher.Hash(in.Password)
	if err != nil {
		return nil, wrapErr(ErrCodeInternal, messages.FailedToHashPassword, err)
	}
	user, err := uc.users.Replace(ctx, in.ID, email, first, last, hash, status)
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return nil, wrapErr(ErrCodeNotFound, messages.UserNotFound, err)
	case errors.Is(err, domain.ErrConflict):
		return nil, wrapErr(ErrCodeConflict, messages.EmailAlreadyUsed, err)
	case err != nil:
		return nil, wrapErr(ErrCodeInternal, messages.FailedToUpdateUser, err)
	}
	return user, nil
}

// AdminUpdate частично обновляет карточку пользователя админом (PATCH /users/{id}).
// При смене пароля хеш пересоздается, а все активные сессии пользователя
// отзываются (требование безопасности).
func (uc *UserUseCaseImpl) AdminUpdate(ctx context.Context, in AdminUpdateUserInput) (*models.User, error) {
	var email, first, last, passwordHash, status *string

	if in.Email != nil {
		v := normalizeEmail(*in.Email)
		if v == "" || !validEmail(v) {
			return nil, validationErr(messages.CheckRequiredFields, map[string][]string{"email": {messages.InvalidEmail}})
		}
		email = &v
	}
	if in.FirstName != nil {
		v := normalizeName(*in.FirstName)
		if v == "" {
			return nil, validationErr(messages.CheckRequiredFields, map[string][]string{"first_name": {messages.FirstNameRequired}})
		}
		first = &v
	}
	if in.LastName != nil {
		v := normalizeName(*in.LastName)
		if v == "" {
			return nil, validationErr(messages.CheckRequiredFields, map[string][]string{"last_name": {messages.LastNameRequired}})
		}
		last = &v
	}
	if in.Status != nil {
		v := normalizeLower(*in.Status)
		if !validStatus(v) {
			return nil, validationErr(messages.InvalidParameterValue, map[string][]string{"status": {messages.StatusInvalidValue}})
		}
		status = &v
	}
	if in.Password != nil {
		if !validPassword(*in.Password) {
			return nil, validationErr(messages.CheckRequiredFields, map[string][]string{"password": {messages.PasswordTooShort}})
		}
		h, err := uc.hasher.Hash(*in.Password)
		if err != nil {
			return nil, wrapErr(ErrCodeInternal, messages.FailedToHashPassword, err)
		}
		passwordHash = &h
	}

	user, err := uc.users.Update(ctx, in.ID, email, first, last, passwordHash, status)
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return nil, wrapErr(ErrCodeNotFound, messages.UserNotFound, err)
	case errors.Is(err, domain.ErrConflict):
		return nil, wrapErr(ErrCodeConflict, messages.EmailAlreadyUsed, err)
	case err != nil:
		return nil, wrapErr(ErrCodeInternal, messages.FailedToUpdateUser, err)
	}
	// Смена пароля инвалидирует все refresh-токены пользователя.
	if passwordHash != nil {
		if revokeErr := uc.tokens.RevokeAllForUser(ctx, in.ID); revokeErr != nil {
			log.Printf("event=revoke_all_sessions_failed user_id=%s error=%v", in.ID.String(), revokeErr)
		}
	}
	return user, nil
}

// ---------- Удаление ----------

// Delete удаляет пользователя админом. Запрещено удалять собственную
// учетную запись; защищенные аккаунты (администраторы) отклоняются
// репозиторием через domain.ErrProtected.
func (uc *UserUseCaseImpl) Delete(ctx context.Context, in DeleteUserInput) error {
	if in.TargetID == in.PrincipalID {
		return newErr(ErrCodeForbidden, messages.AdminCannotDeleteSelf)
	}
	err := uc.users.Delete(ctx, in.TargetID)
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return wrapErr(ErrCodeNotFound, messages.UserNotFound, err)
	case errors.Is(err, domain.ErrProtected):
		return wrapErr(ErrCodeForbidden, messages.CannotDeleteAdminAccount, err)
	case err != nil:
		return wrapErr(ErrCodeInternal, messages.FailedToDeleteUser, err)
	}
	return nil
}
