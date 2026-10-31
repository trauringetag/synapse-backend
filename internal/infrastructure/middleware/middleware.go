package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/delivery/http/response"
	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/security"
	"github.com/trauringetag/synapse-backend/internal/messages"
)

type ctxKey string

const userKey ctxKey = "user"

type Principal struct {
	ID    uuid.UUID
	Email string
	Role  string
}

func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(userKey).(*Principal)
	return p, ok
}

func CacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

func JSONContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

type UserLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// ClientPlatform возвращает платформу клиента из заголовка X-Client-Platform.
// Допустимые значения: "web", "mobile" (регистр не важен, пробелы обрезаются).
// Если заголовок отсутствует или невалиден — возвращается "web" (полная
// обратная совместимость с существующими веб-клиентами).
//
// ВАЖНО: заголовок определяет ТОЛЬКО формат ответа (cookie vs JSON-токены).
// Он никогда не влияет на CSRF/Origin-проверки: безопасность определяется
// фактическим способом аутентификации запроса (см. IsBearerAuth). Это защита
// от подделки заголовка злоумышленником с фишингового сайта.
func ClientPlatform(r *http.Request) string {
	v := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Client-Platform")))
	switch v {
	case "web", "mobile":
		return v
	default:
		return "web"
	}
}

// IsBearerAuth возвращает true, если запрос использует Bearer-аутентификацию
// (заголовок Authorization: Bearer <token>, схема case-insensitive).
//
// Именно этот детектор определяет необходимость CSRF/Origin-проверок, а НЕ
// заголовок X-Client-Platform: CSRF возможен только там, где браузер сам
// отправляет cookie; запрос без cookie (чистый Bearer) CSRF-неуязвим.
func IsBearerAuth(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	return len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix)
}

// extractAccessToken извлекает access-токен из запроса с чётким приоритетом
// источников (никакого смешивания):
//   - Приоритет 1: Authorization: Bearer <token> — мобильные/серверные клиенты.
//     Если заголовок Authorization присутствует, но схема не Bearer (Basic,
//     Token, Digest и т.д.) или токен пуст — ошибка (позже -> 401). Cookie при
//     этом игнорируются: два источника в одном запросе не используются.
//   - Приоритет 2: HttpOnly cookie access_token — веб-клиенты.
//
// Значение токена никогда не логируется и не попадает в текст ошибки.
func extractAccessToken(r *http.Request) (string, error) {
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		const prefix = "Bearer "
		if len(authHeader) > len(prefix) && strings.EqualFold(authHeader[:len(prefix)], prefix) {
			token := strings.TrimSpace(authHeader[len(prefix):])
			if token == "" {
				return "", errors.New("empty bearer token")
			}
			return token, nil
		}
		// Неизвестная схема (Basic, Token, Digest и т.д.) — отклоняем.
		return "", errors.New("unsupported authorization scheme")
	}
	// Приоритет 2: Cookie (веб-клиенты).
	return auth.ReadCookie(r, auth.AccessCookie)
}

func Authenticate(cfg *config.Config, users UserLookup) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Двойной источник токена: Bearer (приоритет) либо cookie.
			// Дальнейшая проверка идентична для обоих источников: подпись,
			// iss=synapse-backend, aud=access, exp, sub как UUID, статус active.
			raw, err := extractAccessToken(r)
			if err != nil || raw == "" {
				response.Error(w, http.StatusUnauthorized, messages.AuthorizationRequired, nil)
				return
			}
			claims, err := auth.Parse(cfg, raw, "access")
			if err != nil {
				response.Error(w, http.StatusUnauthorized, messages.InvalidOrExpiredAccessToken, nil)
				return
			}
			id, err := uuid.Parse(claims.Subject)
			if err != nil || id == uuid.Nil {
				response.Error(w, http.StatusUnauthorized, messages.InvalidSubjectToken, nil)
				return
			}
			user, err := users.GetByID(r.Context(), id)
			if err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					response.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
					return
				}
				response.Error(w, http.StatusServiceUnavailable, messages.AuthenticationUnavailable, nil)
				return
			}
			if user.Status != domain.StatusActive {
				response.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
				return
			}
			p := &Principal{ID: user.ID, Email: user.Email, Role: user.Role}
			ctx := context.WithValue(r.Context(), userKey, p)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ContextWithUser(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, userKey, p)
}

func RequireRoles(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		allowed[role] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := FromContext(r.Context())
			if !ok {
				response.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
				return
			}
			if _, ok := allowed[p.Role]; !ok {
				response.Error(w, http.StatusForbidden, messages.InsufficientPermissions, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireUserOrAdmin(next http.Handler) http.Handler {
	return RequireRoles(domain.RoleUser, domain.RoleAdmin)(next)
}

func RequireAdmin(next http.Handler) http.Handler {
	return RequireRoles(domain.RoleAdmin)(next)
}

const MaxJSONBodyBytes int64 = 1 << 20

func LimitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			r.Body = http.MaxBytesReader(w, r.Body, MaxJSONBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimitStore — локальный порт хранилища счётчиков лимитов запросов.
// Единственный источник правды — domain.RateLimitStore
// (internal/domain/rate_limit_store.go); здесь объявлен type-алиас, чтобы
// middleware зависел только от контракта домена и не знал о реализации БД.
// Инфраструктурная реализация — persistence.RateLimitRepository.
type RateLimitStore = domain.RateLimitStore

// RateLimit возвращает middleware ограничения частоты запросов, использующий
// переданный порт store.Increment для учёта попаданий в окне window.
func RateLimit(store RateLimitStore, limit int, window time.Duration, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limit < 1 || window <= 0 || store == nil || keyFn == nil {
				response.Error(w, http.StatusServiceUnavailable, messages.AuthenticationUnavailable, nil)
				return
			}
			key := keyFn(r)
			if key == "" {
				key = "unknown"
			}
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			count, err := store.Increment(ctx, key, window)
			if err != nil {
				response.Error(w, http.StatusServiceUnavailable, messages.AuthenticationUnavailable, nil)
				return
			}
			if count > limit {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
				response.Error(w, http.StatusTooManyRequests, "Слишком много запросов", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func loginEmail(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, MaxJSONBodyBytes+1))
	r.Body.Close()
	r.Body = io.NopCloser(strings.NewReader(string(b)))
	if err != nil || int64(len(b)) > MaxJSONBodyBytes {
		return ""
	}
	var body struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(b, &body) != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(body.Email))
}

func AccountIPKey(r *http.Request) string {
	return "login:" + ClientIP(r) + ":" + loginEmail(r)
}

func IPKey(r *http.Request) string { return "ip:" + ClientIP(r) }

// RefreshKey строит ключ rate limiter для POST /refresh одинаково для обоих
// типов клиентов: хешируется (SHA-256, без значения токена в ключе/логах)
// фактический носитель refresh-токена — Bearer-заголовок (мобильные/серверные
// клиенты), иначе cookie refresh_token (веб). При отсутствии обоих используется
// IP, чтобы лимитер не ломался (например, при токене только в JSON-теле).
func RefreshKey(r *http.Request) string {
	raw := bearerRefreshCredential(r)
	if raw == "" {
		if c, err := r.Cookie("refresh_token"); err == nil && c.Value != "" {
			raw = c.Value
		}
	}
	if raw == "" {
		return "refresh:" + ClientIP(r)
	}
	h := sha256.Sum256([]byte(raw))
	return "refresh:" + base64.RawURLEncoding.EncodeToString(h[:])
}

// bearerRefreshCredential возвращает refresh-токен из Authorization: Bearer ...
// (без пробелов по краям) либо пустую строку. Значение никогда не логируется.
func bearerRefreshCredential(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// RequireAllowedOrigin возвращает middleware проверки разрешённого источника.
// Как и CSRF, привязан к фактическому способу аутентификации (IsBearerAuth),
// а не к заголовку X-Client-Platform: Origin проверяется только для
// cookie-запросов; чистые Bearer-запросы (мобильные/серверные клиенты)
// Origin не отправляют, а CSRF для них в принципе невозможен.
func RequireAllowedOrigin(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Bearer token — проверка Origin не нужна (независимо от
			// платформы): фактический credential — заголовок, Origin для
			// него не определяет безопасность.
			if IsBearerAuth(r) {
				next.ServeHTTP(w, r)
				return
			}
			// Запрос без cookie (нативный мобильный/серверный анонимный
			// вызов) Origin не отправляет и browser-credential не несёт —
			// проверка не требуется. При наличии ЛЮБОЙ cookie проверка
			// обязательна, независимо от заявленного X-Client-Platform
			// (защита от подделки заголовка).
			if !hasAnyCookie(r) {
				next.ServeHTTP(w, r)
				return
			}
			origin := requestOrigin(r)
			if !isAllowedOrigin(cfg, origin) {
				log.Printf("security_event=invalid_origin origin=%q ip=%s path=%s",
					origin, ClientIP(r), r.URL.Path)
				response.Error(w, http.StatusForbidden, messages.InvalidOrigin, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isAllowedOrigin(cfg *config.Config, origin string) bool {
	if origin == "" {
		return false
	}
	for _, configured := range cfg.CORSOrigins {
		if origin == strings.TrimRight(strings.TrimSpace(configured), "/") {
			return true
		}
	}
	return false
}

func requestOrigin(r *http.Request) string {
	origin := strings.TrimRight(strings.TrimSpace(r.Header.Get("Origin")), "/")
	if origin == "" {
		ref := r.Header.Get("Referer")
		if u, err := url.Parse(ref); err == nil && u.Scheme != "" && u.Host != "" {
			origin = u.Scheme + "://" + u.Host
		}
	}
	return origin
}

// CSRF возвращает middleware CSRF-защиты для изменяющих запросов.
//
// КЛЮЧЕВОЕ ПРАВИЛО БЕЗОПАСНОСТИ: необходимость проверки определяется
// фактическим способом аутентификации (IsBearerAuth), а НЕ заголовком
// X-Client-Platform. Если бы CSRF отключался по заголовку, злоумышленник с
// фишингового сайта мог бы отправить запрос с cookie жертвы и поддельным
// X-Client-Platform: mobile и обошёл бы защиту. Здесь же: браузер всегда
// отправит cookie -> IsBearerAuth == false -> CSRF проверяется, независимо от
// того, какую платформу заявил клиент.
//
//   - Safe-методы (GET/HEAD/OPTIONS) — пропускаются без проверок.
//   - Bearer-запросы (Authorization: Bearer ...) — CSRF не нужен: мобильные
//     и серверные клиенты не подвержены CSRF (нет авторизации через cookie).
//   - Cookie-запросы — обязательны разрешённый Origin и совпадающий
//     HMAC-подписанный CSRF-токен (cookie csrf_token + заголовок X-CSRF-Token).
func CSRF(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			// Приоритет 1: чистый Bearer — фактическая аутентификация идёт
			// заголовком (Authenticate игнорирует cookie при наличии Bearer),
			// credential не берётся из cookie -> CSRF не нужен.
			if IsBearerAuth(r) {
				next.ServeHTTP(w, r)
				return
			}
			// Приоритет 2: запрос вообще без cookie (нативные мобильные и
			// серверные анонимные вызовы login/register/logout с refresh из
			// тела). Браузерная CSRF-атака невозможна без cookie: ни один
			// credential браузер молча не приложит к чужому origin. Как
			// только в запросе появляется ЛЮБАЯ cookie (в т.ч. csrf_token),
			// включается полный цикл Origin + CSRF — независимо от того,
			// какую платформу заявил клиент в X-Client-Platform. Подделка
			// заголовка злоумышленником с фишингового сайта не помогает:
			// браузер жертвы всегда отправит cookie, и проверка состоится.
			if !hasAnyCookie(r) {
				next.ServeHTTP(w, r)
				return
			}
			// Cookie-based запросы — обязательная проверка Origin + CSRF
			// (даже если клиент заявил X-Client-Platform: mobile — это защита
			// от подделки заголовка).
			origin := requestOrigin(r)
			if !isAllowedOrigin(cfg, origin) {
				response.Error(w, http.StatusForbidden, messages.InvalidOrigin, nil)
				return
			}
			c, err := r.Cookie("csrf_token")
			token := r.Header.Get("X-CSRF-Token")
			if err != nil || token == "" || !auth.ValidCSRF(cfg.JWTSecret, c.Value) || !hmac.Equal([]byte(token), []byte(c.Value)) {
				response.Error(w, http.StatusForbidden, messages.InvalidCSRFToken, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// hasAnyCookie — наличие хотя бы одной cookie в запросе. Факт наличия
// cookie (а не заявленная платформа) определяет подверженность запроса
// CSRF-атаке.
func hasAnyCookie(r *http.Request) bool { return len(r.Cookies()) > 0 }

// isSafeMethod — методы, не изменяющие состояние (RFC 9110, 9.2.1).
func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// validCSRF — локальная обёртка над security.ValidCSRF для использования
// в тестах middleware (проверка HMAC-подписи CSRF-токена).
func validCSRF(secret []byte, token string) bool { return auth.ValidCSRF(secret, token) }

// IssueCSRF — реэкспорт генератора CSRF-токенов из пакета security.
// Реализация переехала в infrastructure/security (csrf.go), чтобы слой
// use-case и HTTP-обработчики могли получать токен без цикла импортов
// middleware -> security -> middleware.
func IssueCSRF(secret []byte) (string, error) { return auth.IssueCSRF(secret) }

func AccountGlobalKey(r *http.Request) string {
	email := loginEmail(r)
	if email == "" {
		return "login_global:invalid:" + ClientIP(r)
	}
	return "login_global:" + email
}

func UserKey(r *http.Request) string {
	p, ok := FromContext(r.Context())
	if !ok {
		return IPKey(r)
	}
	return "user:" + p.ID.String()
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}
