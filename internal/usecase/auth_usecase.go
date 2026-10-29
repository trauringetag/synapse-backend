package usecase

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/messages"
)

// dummyPassword — пароль, хеш которого используется для защиты от timing-атак
// при логине: если пользователь не найден или неактивен, hasher всё равно
// выполняет сравнение с фиктивным хешем, чтобы время ответа не выдавало
// существование учетной записи. Сам хеш вычисляется инфраструктурной
// реализацией порта PasswordHasher (см. security.BcryptHasher), поэтому слой
// use-case не зависит от конкретной библиотеки хеширования (Dependency Rule).
const dummyPassword = "dummy-password-for-timing-attack-protection"

// HashToken возвращает SHA-256 (hex) от токена — безопасное представление
// refresh-токена для хранения. Хелпер продублирован здесь, чтобы слой
// use-case не зависел от инфраструктурного пакета security.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// TokenPair — выпущенная пара JWT-токенов. Слой use-case оперирует этим DTO,
// а не инфраструктурным типом; HTTP-слой превращает его в cookie.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	AccessExp    time.Time
	RefreshExp   time.Time
}

// TokenIssuer инкапсулирует выпуск и разбор JWT-пары. Имплементация живёт в
// инфраструктуре (security.NewJWTService(cfg)); так слой use-case не зависит
// ни от config, ни от формата токенов напрямую.
type TokenIssuer interface {
	// IssuePair выпускает новую пару access/refresh для пользователя.
	IssuePair(userID uuid.UUID, email, role string) (*TokenPair, error)
	// ParseRefresh разбирает refresh-токен и возвращает subject (ID пользователя).
	// Ошибка — если токен недействителен, просрочен или имеет неверное назначение.
	ParseRefresh(raw string) (subject string, err error)
}

// CSRFIssuer генерирует CSRF-токен (реализация — инфраструктурный middleware).
type CSRFIssuer interface {
	IssueCSRF() (string, error)
}

// AuthUseCaseImpl — реализация AuthUseCase. Содержит всю бизнес-логику
// аутентификации, которая ранее находилась в HTTP-обработчике auth_handler.go.
type AuthUseCaseImpl struct {
	// Порты репозиториев — из домена (единственный источник правды: domain/ports.go).
	users      domain.UserRepository
	tokens     domain.RefreshTokenRepository
	hasher     PasswordHasher // порт хеширования паролей (реализация — в инфраструктуре)
	issuer     TokenIssuer
	csrf       CSRFIssuer
	adminToken string
	dummyHash  string // фиктивный хеш для защиты от timing-атак (вычисляется в конструкторе)
}

// NewAuthUseCase собирает сценарии аутентификации. Зависимости передаются явно
// (DI): репозитории, порт хеширования паролей, генератор токенов, CSRF-генератор
// и секретный токен админской регистрации.
func NewAuthUseCase(
	users domain.UserRepository,
	tokens domain.RefreshTokenRepository,
	hasher PasswordHasher,
	issuer TokenIssuer,
	csrf CSRFIssuer,
	adminRegisterToken string,
) *AuthUseCaseImpl {
	uc := &AuthUseCaseImpl{
		users:      users,
		tokens:     tokens,
		hasher:     hasher,
		issuer:     issuer,
		csrf:       csrf,
		adminToken: adminRegisterToken,
	}
	// Фиктивный хеш вычисляется один раз через внедренный порт: если
	// пользователь не найден или неактивен, Compare всё равно выполнит
	// полноценное хеширование, чтобы время ответа не выдавало существование
	// учетной записи (защита от timing-атак).
	if hasher != nil {
		if h, err := hasher.Hash(dummyPassword); err == nil {
			uc.dummyHash = h
		}
	}
	return uc
}

var _ AuthUseCase = (*AuthUseCaseImpl)(nil)

// ---------- Регистрация ----------

// validateRegister — общие бизнес-правила валидации данных регистрации.
func validateRegister(in RegisterInput) (email, first, last string, err error) {
	email = normalizeEmail(in.Email)
	first = normalizeName(in.FirstName)
	last = normalizeName(in.LastName)

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
	if len(details) > 0 {
		return "", "", "", validationErr(messages.CheckRequiredFields, details)
	}
	return email, first, last, nil
}

// createUserWithHash — общая часть: хеширование пароля (через порт
// PasswordHasher) и создание пользователя через репозиторий.
func (uc *AuthUseCaseImpl) createUserWithHash(ctx context.Context, email, password, role, first, last string) (*domain.User, error) {
	hash, err := uc.hasher.Hash(password)
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

// Register регистрирует обычного пользователя (роль user).
func (uc *AuthUseCaseImpl) Register(ctx context.Context, in RegisterInput) (*domain.User, error) {
	email, first, last, err := validateRegister(in)
	if err != nil {
		return nil, err
	}
	return uc.createUserWithHash(ctx, email, in.Password, domain.RoleUser, first, last)
}

// RegisterAdmin регистрирует администратора; дополнительно constant-time
// сравнением проверяется секретный токен админской регистрации.
func (uc *AuthUseCaseImpl) RegisterAdmin(ctx context.Context, in RegisterInput) (*domain.User, error) {
	email, first, last, err := validateRegister(in)
	if err != nil {
		return nil, err
	}
	// Проверка админ-токена выполняется ПОСЛЕ валидации полей (как раньше).
	provided := normalizeToken(in.AdminToken)
	if subtle.ConstantTimeCompare([]byte(provided), []byte(uc.adminToken)) != 1 {
		return nil, newErr(ErrCodeForbidden, messages.InvalidAdminToken)
	}
	return uc.createUserWithHash(ctx, email, in.Password, domain.RoleAdmin, first, last)
}

// ---------- Вход ----------

// Login проверяет учетные данные с защитой от timing-атак, убеждается, что
// пользователь активен, выпускает JWT-пару и сохраняет refresh-токен.
func (uc *AuthUseCaseImpl) Login(ctx context.Context, in LoginInput) (*SessionResult, error) {
	email := normalizeEmail(in.Email)
	if len(email) > 255 || len(in.Password) > 72 {
		return nil, newErr(ErrCodeValidation, messages.InvalidJSONBody)
	}

	user, err := uc.users.GetByEmail(ctx, email)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return nil, wrapErr(ErrCodeUnavailable, messages.AuthenticationUnavailable, err)
	}

	var isValidUser bool
	if err == nil && user.Status == domain.StatusActive {
		isValidUser = true
	}

	// При невалидном пользователе сравниваем с фиктивным хешем, чтобы время
	// ответа не отличалось от случая «пользователь существует».
	hashToCompare := uc.dummyHash
	if isValidUser {
		hashToCompare = user.PasswordHash
	}
	passwordErr := uc.hasher.Compare(hashToCompare, in.Password)
	if !isValidUser || passwordErr != nil {
		return nil, newErr(ErrCodeUnauthorized, messages.InvalidCredentials)
	}

	pair, err := uc.issueSession(ctx, user)
	if err != nil {
		return nil, wrapErr(ErrCodeInternal, messages.FailedToIssueTokens, err)
	}
	return &SessionResult{User: user, Pair: pair}, nil
}

// issueSession — бизнес-логика выпуска сессии: проверка статуса, генерация
// пары токенов и сохранение хеша refresh-токена. Cookie устанавливает HTTP-слой.
func (uc *AuthUseCaseImpl) issueSession(ctx context.Context, user *domain.User) (*TokenPair, error) {
	if user == nil || user.Status != domain.StatusActive {
		return nil, domain.ErrNotFound
	}
	pair, err := uc.issuer.IssuePair(user.ID, user.Email, user.Role)
	if err != nil {
		return nil, err
	}
	if err := uc.tokens.Store(ctx, user.ID, HashToken(pair.RefreshToken), pair.RefreshExp); err != nil {
		return nil, err
	}
	return pair, nil
}

// ---------- Ротация refresh-токена ----------

// Refresh выполняет ротацию refresh-токена и возвращает структурированный
// результат (RefreshResult), чтобы HTTP-слой оставался тонким и не знал
// бизнес-правил:
//   - Pair != nil                          -> успех: установить новые cookie, 200;
//   - Reject                               -> отклонить токен: 401 + сброс cookie;
//   - InternalError                        -> внутренняя ошибка: 5xx + сброс cookie.
//
// Replay-атака (повторное использование отозванного токена) приводит к отзыву
// всех сессий пользователя и отклонению (401).
func (uc *AuthUseCaseImpl) Refresh(ctx context.Context, in RefreshInput) (*RefreshResult, error) {
	reject := &RefreshResult{ClearCookies: true, Reject: true}

	if in.RawRefreshToken == "" {
		return reject, nil
	}
	subject, err := uc.issuer.ParseRefresh(in.RawRefreshToken)
	if err != nil {
		return reject, nil
	}
	id, err := domain.UUIDFromString(subject)
	if err != nil {
		return reject, nil
	}

	var issued *TokenPair
	_, err = uc.tokens.Rotate(ctx, HashToken(in.RawRefreshToken), id, func(user *domain.User) (string, time.Time, error) {
		var issueErr error
		issued, issueErr = uc.issuer.IssuePair(user.ID, user.Email, user.Role)
		if issueErr != nil {
			return "", time.Time{}, issueErr
		}
		return HashToken(issued.RefreshToken), issued.RefreshExp, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRefreshTokenReplay):
			log.Printf("security_event=refresh_token_reuse user_id=%s", id.String())
			if revokeErr := uc.tokens.RevokeAllForUser(ctx, id); revokeErr != nil {
				log.Printf("event=revoke_all_sessions_failed user_id=%s error=%v", id.String(), revokeErr)
			}
			return reject, nil
		case errors.Is(err, domain.ErrNotFound), errors.Is(err, domain.ErrInactiveTokenUser):
			if errors.Is(err, domain.ErrInactiveTokenUser) {
				log.Printf("security_event=refresh_denied_inactive_user user_id=%s", id.String())
			}
			return reject, nil
		default:
			log.Printf("event=refresh_rotation_failed user_id=%s error_type=%T", id.String(), err)
			return &RefreshResult{
				ClearCookies:  true,
				InternalError: true,
			}, wrapErr(ErrCodeInternal, messages.FailedToIssueTokens, err)
		}
	}
	return &RefreshResult{Pair: issued}, nil
}

// ---------- Выход ----------

// Logout отзывает refresh-токен (если он присутствует). Сброс cookie выполняет
// HTTP-слой.
func (uc *AuthUseCaseImpl) Logout(ctx context.Context, in LogoutInput) error {
	if in.HasCookie && in.RawRefreshToken != "" {
		if err := uc.tokens.Revoke(ctx, HashToken(in.RawRefreshToken)); err != nil {
			log.Printf("event=logout_refresh_revoke_failed error_type=%T", err)
			return wrapErr(ErrCodeInternal, messages.FailedToRevokeRefreshToken, err)
		}
	}
	return nil
}

// ---------- CSRF ----------

// IssueCSRF генерирует CSRF-токен для двухсоставной схемы защиты.
func (uc *AuthUseCaseImpl) IssueCSRF() (*CSRFResult, error) {
	token, err := uc.csrf.IssueCSRF()
	if err != nil {
		return nil, wrapErr(ErrCodeInternal, messages.FailedToPrepareCSRFProtection, err)
	}
	return &CSRFResult{Token: token}, nil
}
