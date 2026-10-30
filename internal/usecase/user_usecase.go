package usecase

import (
	"context"
	"errors"
	"log"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/domain"
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
func (uc *UserUseCaseImpl) GetMe(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
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
func (uc *UserUseCaseImpl) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
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
func (uc *UserUseCaseImpl) Create(ctx context.Context, in CreateUserInput) (*domain.User, error) {
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
		role = domain.RoleUser
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
func (uc *UserUseCaseImpl) ReplaceProfile(ctx context.Context, in ReplaceProfileInput) (*domain.User, error) {
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
func (uc *UserUseCaseImpl) UpdateOwnProfile(ctx context.Context, in UpdateOwnProfileInput) (*domain.User, error) {
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

// deactivateSessions — единая политика деактивации (soft delete): любое
// переведение аккаунта в статус inactive обязано сопровождаться немедленным
// отзывом всех refresh-токенов пользователя, чтобы заблокированный/удаленный
// аккаунт не сохранил живые сессии. Сбой отзыва не откатывает уже выполненное
// обновление статуса (запись уже inactive — вход и ротация токенов для неё
// всё равно запрещены на уровне БД/middleware), но обязательно логируется
// для аудита и ручного вмешательства.
func (uc *UserUseCaseImpl) deactivateSessions(ctx context.Context, userID uuid.UUID) {
	if err := uc.tokens.RevokeAllForUser(ctx, userID); err != nil {
		log.Printf("event=revoke_all_sessions_failed user_id=%s error=%v", userID.String(), err)
	}
}

// AdminReplace полностью заменяет карточку пользователя (PUT /users/{id}).
// Поле role намеренно не принимается: роль через PUT не меняется.
func (uc *UserUseCaseImpl) AdminReplace(ctx context.Context, in AdminReplaceUserInput) (*domain.User, error) {
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
// отзываются (требование безопасности). Перевод статуса в inactive тоже
// отзывает все сессии — единая политика деактивации (см. deactivateSessions).
func (uc *UserUseCaseImpl) AdminUpdate(ctx context.Context, in AdminUpdateUserInput) (*domain.User, error) {
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
	// Единая политика инвалидации сессий (Задача 2): смена пароля и перевод
	// статуса в inactive (деактивация) обязывают отозвать все refresh-токены
	// пользователя. Ошибка отзыва логируется, но не откатывает уже выполненное
	// обновление (см. deactivateSessions).
	if passwordHash != nil || (status != nil && *status == domain.StatusInactive) {
		uc.deactivateSessions(ctx, in.ID)
	}
	return user, nil
}

// ---------- Удаление ----------

// DeleteMe реализует самоудаление текущего пользователя (DELETE /users/me).
//
// Самоудаление выполняется как физическое (hard) удаление записи из БД.
// Алгоритм:
//  1. Получить пользователя по userID; если не найден — ErrCodeNotFound.
//  2. Если аккаунт уже inactive — конфликт (повторное/некорректное
//     самоудаление деактивированного аккаунта запрещено).
//  3. Немедленно отозвать все refresh-токены (RevokeAllForUser), чтобы старые
//     сессии нельзя было использовать после удаления. Стратегия частичного
//     сбоя: ошибка отзыва логируется, но операция продолжается — запись всё
//     равно удаляется (после hard delete вход для несуществующего пользователя
//     невозможен в принципе, поэтому живых сессий остаться не может).
//  4. Физически удалить запись через UserRepository.Delete (DELETE FROM users).
func (uc *UserUseCaseImpl) DeleteMe(ctx context.Context, userID uuid.UUID) error {
	user, err := uc.users.GetByID(ctx, userID)
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return wrapErr(ErrCodeNotFound, messages.UserNotFound, err)
	case err != nil:
		return wrapErr(ErrCodeInternal, messages.FailedToGetUser, err)
	}
	if user.Status == domain.StatusInactive {
		// Аккаунт уже деактивирован админом — самоудаление не имеет смысла.
		return newErr(ErrCodeConflict, messages.AccountAlreadyInactive)
	}

	// Шаг 1 — отзыв сессий. При сбое логируем и продолжаем (см. докстроку).
	if revokeErr := uc.tokens.RevokeAllForUser(ctx, userID); revokeErr != nil {
		log.Printf("event=revoke_all_sessions_failed user_id=%s op=delete_me error=%v", userID.String(), revokeErr)
	}

	// Шаг 2 — физическое (hard) удаление записи пользователя.
	// Delete защищает аккаунты роли admin (domain.ErrProtected) — эта защита
	// относится к админскому маршруту DELETE /users/{id}. Самоудаление всегда
	// выполняется над собственным аккаунтом, поэтому при таком отказе удаляется
	// через DeleteSelf (DELETE FROM users без условия по роли).
	if delErr := uc.users.Delete(ctx, userID); delErr != nil {
		switch {
		case errors.Is(delErr, domain.ErrNotFound):
			return wrapErr(ErrCodeNotFound, messages.UserNotFound, delErr)
		case errors.Is(delErr, domain.ErrProtected):
			if retryErr := uc.users.DeleteSelf(ctx, userID); retryErr != nil {
				if errors.Is(retryErr, domain.ErrNotFound) {
					return wrapErr(ErrCodeNotFound, messages.UserNotFound, retryErr)
				}
				return wrapErr(ErrCodeInternal, messages.FailedToDeleteUser, retryErr)
			}
		default:
			return wrapErr(ErrCodeInternal, messages.FailedToDeleteUser, delErr)
		}
	}
	return nil
}

// Delete выполняет физическое (hard) удаление пользователя админом
// (DELETE /users/{id}). Политики (Задача 2):
//   - необратимо: запись стирается из БД; для сохранения данных используется
//     обратимая деактивация (PATCH /users/{id} со status=inactive), которая
//     также отзывает сессии (см. deactivateSessions);
//   - доступно только админскому сценарию (RBAC на уровне маршрута) и
//     защищено от самоудаления (ErrForbidden, см. AdminCannotDeleteSelf —
//     пользователь удаляет себя через DELETE /users/me, см. DeleteMe);
//   - перед удалением обязательно отзываются все refresh-токены цели, чтобы
//     не осталось «висячих» сессий. Стратегия частичного сбоя: если отзыв
//     сессий завершился ошибкой, физическое удаление НЕ выполняется (возвращается
//     внутренняя ошибка) — удаление без отзыва оставило бы живые токены, а
//     откатывать здесь нечего, поэтому безопаснее прервать операцию.
func (uc *UserUseCaseImpl) Delete(ctx context.Context, in DeleteUserInput) error {
	if in.TargetID == in.PrincipalID {
		return newErr(ErrCodeForbidden, messages.AdminCannotDeleteSelf)
	}
	// Отзываем сессии ДО физического удаления (гарантия отсутствия висячих токенов).
	if revokeErr := uc.tokens.RevokeAllForUser(ctx, in.TargetID); revokeErr != nil {
		log.Printf("event=revoke_all_sessions_failed user_id=%s op=admin_delete error=%v", in.TargetID.String(), revokeErr)
		return wrapErr(ErrCodeInternal, messages.FailedToDeleteUser, revokeErr)
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
