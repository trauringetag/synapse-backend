package usecase

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/domain/models"
	"github.com/trauringetag/synapse-backend/internal/messages"
)

// DummyHash используется для защиты от timing-атак при логине: если пользователь
// не найден или неактивен, bcrypt всё равно выполняет сравнение с фиктивным
// хешем, чтобы время ответа не выдавало существование учетной записи.
// Экспортирован, чтобы unit-тесты HTTP-слоя могли проверить его валидность.
var DummyHash []byte

func init() {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte("dummy-password-for-timing-attack-protection"),
		bcrypt.DefaultCost,
	)
	if err != nil {
		DummyHash = []byte("$2a$10$SomeHashThatWillNeverMatchAnyPassword12345678901234")
	} else {
		DummyHash = hash
	}
}

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
	users      UserRepository
	tokens     TokenRepository
	issuer     TokenIssuer
	csrf       CSRFIssuer
	adminToken string
}

// NewAuthUseCase собирает сценарии аутентификации. Зависимости передаются явно
// (DI): репозитории, генератор токенов, CSRF-генератор и секретный токен
// админской регистрации.
func NewAuthUseCase(
	users UserRepository,
	tokens TokenRepository,
	issuer TokenIssuer,
	csrf CSRFIssuer,
	adminRegisterToken string,
) *AuthUseCaseImpl {
	return &AuthUseCaseImpl{
		users:      users,
		tokens:     tokens,
		issuer:     issuer,
		csrf:       csrf,
		adminToken: adminRegisterToken,
	}
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

// bcryptHash — единая точка хеширования пароля для всего слоя use-case
// (используется и в AuthUseCase, и в UserUseCase).
func bcryptHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// createUserWithHash — общая часть: хеширование пароля (bcrypt) и создание
// пользователя через репозиторий.
func (uc *AuthUseCaseImpl) createUserWithHash(ctx context.Context, email, password, role, first, last string) (*models.User, error) {
	hash, err := bcryptHash(password)
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
func (uc *AuthUseCaseImpl) Register(ctx context.Context, in RegisterInput) (*models.User, error) {
	email, first, last, err := validateRegister(in)
	if err != nil {
		return nil, err
	}
	return uc.createUserWithHash(ctx, email, in.Password, models.RoleUser, first, last)
}

// RegisterAdmin регистрирует администратора; дополнительно constant-time
// сравнением проверяется секретный токен админской регистрации.
func (uc *AuthUseCaseImpl) RegisterAdmin(ctx context.Context, in RegisterInput) (*models.User, error) {
	email, first, last, err := validateRegister(in)
	if err != nil {
		return nil, err
	}
	// Проверка админ-токена выполняется ПОСЛЕ валидации полей (как раньше).
	provided := normalizeToken(in.AdminToken)
	if subtle.ConstantTimeCompare([]byte(provided), []byte(uc.adminToken)) != 1 {
		return nil, newErr(ErrCodeForbidden, messages.InvalidAdminToken)
	}
	return uc.createUserWithHash(ctx, email, in.Password, models.RoleAdmin, first, last)
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
	if err == nil && user.Status == models.StatusActive {
		isValidUser = true
	}

	// При невалидном пользователе сравниваем с фиктивным хешем, чтобы время
	// ответа не отличалось от случая «пользователь существует».
	hashToCompare := DummyHash
	if isValidUser {
		hashToCompare = []byte(user.PasswordHash)
	}
	passwordErr := bcrypt.CompareHashAndPassword(hashToCompare, []byte(in.Password))
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
func (uc *AuthUseCaseImpl) issueSession(ctx context.Context, user *models.User) (*TokenPair, error) {
	if user == nil || user.Status != models.StatusActive {
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

// Refresh выполняет ротацию refresh-токена:
//   - pair != nil, ok == true, err == nil -> успех: установить новые cookie, 200;
//   - ok == false, err == nil             -> отклонить: 401 + сброс cookie;
//   - err != nil                          -> внутренняя ошибка: 500 + сброс cookie.
//
// Replay-атака (повторное использование отозванного токена) приводит к отзыву
// всех сессий пользователя и отклонению (401).
func (uc *AuthUseCaseImpl) Refresh(ctx context.Context, in RefreshInput) (pair *TokenPair, ok bool, err error) {
	const reject = false
	const accepted = true

	if in.RawRefreshToken == "" {
		return nil, reject, nil
	}
	subject, err := uc.issuer.ParseRefresh(in.RawRefreshToken)
	if err != nil {
		return nil, reject, nil
	}
	id, err := domain.UUIDFromString(subject)
	if err != nil {
		return nil, reject, nil
	}

	var issued *TokenPair
	_, err = uc.tokens.Rotate(ctx, HashToken(in.RawRefreshToken), id, func(user *models.User) (string, time.Time, error) {
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
			return nil, reject, nil
		case errors.Is(err, domain.ErrNotFound), errors.Is(err, domain.ErrInactiveTokenUser):
			if errors.Is(err, domain.ErrInactiveTokenUser) {
				log.Printf("security_event=refresh_denied_inactive_user user_id=%s", id.String())
			}
			return nil, reject, nil
		default:
			log.Printf("event=refresh_rotation_failed user_id=%s error_type=%T", id.String(), err)
			return nil, accepted, wrapErr(ErrCodeInternal, messages.FailedToIssueTokens, err)
		}
	}
	return issued, accepted, nil
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
