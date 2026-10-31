package usecase

import (
	"context"
	"errors"

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
	// uow — транзакционный порт (Unit of Work): смена пароля и отзыв сессий
	// выполняются в одной транзакции (Задача 2). Может быть nil (лёгкие
	// сборки/тесты) — тогда операции выполняются без явной транзакции.
	uow    domain.UnitOfWork
	hasher PasswordHasher // порт хеширования паролей (реализация — в инфраструктуре)
}

// NewUserUseCase собирает сценарии работы с пользователями через DI.
func NewUserUseCase(users domain.UserRepository, tokens domain.RefreshTokenRepository, uow domain.UnitOfWork, hasher PasswordHasher) *UserUseCaseImpl {
	return &UserUseCaseImpl{users: users, tokens: tokens, uow: uow, hasher: hasher}
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

// requiresSessionRevocation — единое бизнес-правило (Задача 2): изменение
// пароля (PUT всегда несёт новый пароль; PATCH — если password передан) или
// перевод аккаунта в inactive обязывают отозвать ВСЕ refresh-токены
// пользователя. Отзыв выполняется в одной транзакции с изменением карточки
// (см. runAtomic), поэтому украденный старый refresh-токен гарантированно
// перестаёт работать сразу после админского сброса пароля.
func requiresSessionRevocation(passwordHash *string, status *string) bool {
	if passwordHash != nil {
		return true
	}
	return status != nil && *status == domain.StatusInactive
}

// runAtomic выполняет fn внутри транзакции UnitOfWork. Если UoW не настроен
// (nil — например, в лёгких тестовых сборках), операция выполняется без
// транзакции: семантика вызова репозиториев при этом не меняется.
func (uc *UserUseCaseImpl) runAtomic(ctx context.Context, fn func(context.Context) error) error {
	if uc.uow == nil {
		return fn(ctx)
	}
	return uc.uow.Run(ctx, fn)
}

// mapRepoErrTranslate — отображение доменной ошибки репозитория на ошибку
// use-case с заданным внутренним кодом/сообщением (для вызовов внутри fn).
func mapReplaceErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, domain.ErrNotFound):
		return wrapErr(ErrCodeNotFound, messages.UserNotFound, err)
	case errors.Is(err, domain.ErrConflict):
		return wrapErr(ErrCodeConflict, messages.EmailAlreadyUsed, err)
	default:
		return wrapErr(ErrCodeInternal, messages.FailedToUpdateUser, err)
	}
}

// AdminReplace полностью заменяет карточку пользователя (PUT /users/{id}).
// Поле role намеренно не принимается: роль через PUT не меняется.
//
// Атомарность (Задача 2): PUT всегда содержит новый пароль, поэтому замена
// карточки и отзыв всех refresh-токенов выполняются в ОДНОЙ транзакции
// (UnitOfWork.Run): ReplaceTx + RevokeAllForUser. Если любая из операций
// падает, транзакция откатывается целиком — смена пароля без отзыва сессий
// не фиксируется, и злоумышленник с украденным refresh-токеном не сохраняет
// доступ после админского сброса пароля.
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

	var user *domain.User
	if txErr := uc.runAtomic(ctx, func(txCtx context.Context) error {
		var err error
		user, err = uc.users.ReplaceTx(txCtx, in.ID, email, first, last, hash, status)
		if err != nil {
			return mapReplaceErr(err)
		}
		// Смена пароля => обязательный отзыв всех сессий в той же транзакции.
		// Ошибка отзыва прерывает fn -> ROLLBACK: пароль НЕ изменён.
		if err := uc.tokens.RevokeAllForUser(txCtx, in.ID); err != nil {
			return wrapErr(ErrCodeInternal, messages.FailedToRevokeSessions, err)
		}
		return nil
	}); txErr != nil {
		return nil, txErr
	}
	return user, nil
}

// AdminUpdate частично обновляет карточку пользователя админом (PATCH /users/{id}).
//
// Атомарность (Задача 2): если обновление затрагивает пароль или переводит
// аккаунт в inactive, изменение карточки (UpdateTx) и отзыв всех
// refresh-токенов (RevokeAllForUser) выполняются в ОДНОЙ транзакции
// UnitOfWork. Ошибка любой из операций откатывает обе: сессии не могут
// остаться живыми после смены пароля, а сбой отзыва — сделать смену пароля
// «успешной». Обычные обновления (email/имена/реактивация) не требуют
// отзыва и по-прежнему выполняются одним запросом без транзакции.
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

	// Обновления, не требующие отзыва сессий, выполняются без транзакции.
	if !requiresSessionRevocation(passwordHash, status) {
		user, err := uc.users.Update(ctx, in.ID, email, first, last, passwordHash, status)
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

	var user *domain.User
	if txErr := uc.runAtomic(ctx, func(txCtx context.Context) error {
		var err error
		user, err = uc.users.UpdateTx(txCtx, in.ID, email, first, last, passwordHash, status)
		if err != nil {
			return mapReplaceErr(err)
		}
		// Смена пароля / деактивация => отзыв всех сессий в той же транзакции.
		// Ошибка отзыва прерывает fn -> ROLLBACK: обновление НЕ закоммичено.
		if err := uc.tokens.RevokeAllForUser(txCtx, in.ID); err != nil {
			return wrapErr(ErrCodeInternal, messages.FailedToRevokeSessions, err)
		}
		return nil
	}); txErr != nil {
		return nil, txErr
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
//  3. В ОДНОЙ транзакции UnitOfWork (Задача 2): отозвать все refresh-токены
//     (RevokeAllForUser) и физически удалить запись (DeleteTx; для роли admin
//     — DeleteSelfTx, т.к. DeleteTx защищён от удаления админов). Ошибка любой
//     из операций откатывает обе: либо аккаунт удалён И сессии отозваны, либо
//     не произошло ничего. Это устраняет окно, в котором при частичном сбое
//     удалялся аккаунт, но отзыв падал (или наоборот).
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

	return uc.runAtomic(ctx, func(txCtx context.Context) error {
		// Шаг 1 — отзыв сессий внутри транзакции. Ошибка прерывает fn ->
		// ROLLBACK: аккаунт остаётся в БД, операция повторяема.
		if revokeErr := uc.tokens.RevokeAllForUser(txCtx, userID); revokeErr != nil {
			return wrapErr(ErrCodeInternal, messages.FailedToRevokeSessions, revokeErr)
		}

		// Шаг 2 — физическое (hard) удаление записи пользователя.
		// DeleteTx защищает аккаунты роли admin (domain.ErrProtected) — эта
		// защита относится к админскому маршруту DELETE /users/{id}.
		// Самоудаление всегда выполняется над собственным аккаунтом, поэтому
		// при таком отказе удаляется через DeleteSelfTx (DELETE FROM users без
		// условия по роли).
		delErr := uc.users.DeleteTx(txCtx, userID)
		if delErr != nil && errors.Is(delErr, domain.ErrProtected) {
			delErr = uc.users.DeleteSelfTx(txCtx, userID)
		}
		switch {
		case delErr == nil:
			return nil
		case errors.Is(delErr, domain.ErrNotFound):
			return wrapErr(ErrCodeNotFound, messages.UserNotFound, delErr)
		default:
			return wrapErr(ErrCodeInternal, messages.FailedToDeleteUser, delErr)
		}
	})
}

// Delete выполняет физическое (hard) удаление пользователя админом
// (DELETE /users/{id}). Политики (Задача 2):
//   - необратимо: запись стирается из БД; для сохранения данных используется
//     обратимая деактивация (PATCH /users/{id} со status=inactive), которая
//     также отзывает сессии в той же транзакции (см. AdminUpdate);
//   - доступно только админскому сценарию (RBAC на уровне маршрута) и
//     защищено от самоудаления (ErrForbidden, см. AdminCannotDeleteSelf —
//     пользователь удаляет себя через DELETE /users/me, см. DeleteMe);
//   - отзыв всех refresh-токенов цели и физическое удаление выполняются в
//     ОДНОЙ транзакции UnitOfWork (RevokeAllForUser + DeleteTx), чтобы не
//     осталось «висячих» сессий и не было частичных состояний: ошибка любой
//     из операций откатывает обе.
func (uc *UserUseCaseImpl) Delete(ctx context.Context, in DeleteUserInput) error {
	if in.TargetID == in.PrincipalID {
		return newErr(ErrCodeForbidden, messages.AdminCannotDeleteSelf)
	}
	return uc.runAtomic(ctx, func(txCtx context.Context) error {
		// Отзываем сессии ДО физического удаления (гарантия отсутствия
		// висячих токенов); при сбое отзыва транзакция откатывается целиком.
		if revokeErr := uc.tokens.RevokeAllForUser(txCtx, in.TargetID); revokeErr != nil {
			return wrapErr(ErrCodeInternal, messages.FailedToRevokeSessions, revokeErr)
		}
		err := uc.users.DeleteTx(txCtx, in.TargetID)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, domain.ErrNotFound):
			return wrapErr(ErrCodeNotFound, messages.UserNotFound, err)
		case errors.Is(err, domain.ErrProtected):
			return wrapErr(ErrCodeForbidden, messages.CannotDeleteAdminAccount, err)
		default:
			return wrapErr(ErrCodeInternal, messages.FailedToDeleteUser, err)
		}
	})
}
