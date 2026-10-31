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

// rateBucketVersion — версия схемы ключей api_rate_limits. Формат bucket_key:
//
//	rl:<route_policy>:<version>:<hmac(идентификатор)>
//
// Смена версии (или политики) гарантированно разобщает старые и новые окна
// в таблице: rl:register:v1:... и rl:logout:v1:... — независимые счётчики.
const rateBucketVersion = "v1"

// Политики маршрутов (route_policy). Каждая политика — отдельный bucket,
// поэтому исчерпание лимита на одном маршруте никогда не блокирует другой
// (в частности 100 попыток на /register не влияют на /logout того же IP).
const (
	PolicyRegister      = "register"
	PolicyLoginIP       = "login_ip"
	PolicyLoginAccount  = "login_account"
	PolicyLoginFailed   = "login_failed"
	PolicyRefresh       = "refresh"
	PolicyLogout        = "logout"
	PolicyAuthenticated = "authenticated"
)

// hmacID — HMAC-SHA256 от идентификатора отдельным ключом конфигурации
// (RATE_LIMIT_HMAC_KEY). Результат — base64url без padding: email/IP никогда
// не попадают в таблицу api_rate_limits в открытом виде (защита PII).
func hmacID(key []byte, id string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// bucketKey собирает канонический ключ хранилища: rl:<policy>:<version>:<hash>.
// Если ключ HMAC не настроен, используется fallback-префикс legacy:<policy>:
// (уникален на уровне таблицы, но НЕ применяется в роутере — там всегда
// требуется cfg.RateLimitHMACKey; fail-closed покрыт проверкой store/limit).
func bucketKey(hmacKey []byte, policy, rawID string) string {
	if len(hmacKey) == 0 {
		return "legacy:" + policy + ":" + rawID
	}
	return "rl:" + policy + ":" + rateBucketVersion + ":" + hmacID(hmacKey, rawID)
}

// statusRecorder перехватывает код ответа, чтобы limiter c реакцией на
// результат запроса (onOutcome) мог отличить неудачную аутентификацию (401)
// от успешной (2xx). Реализует http.Flusher для совместимости со стримингом.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// RateLimitOption — необязательное поведение лимитера (реакция на исход).
type RateLimitOption func(*rateLimitConfig)

type rateLimitConfig struct {
	// onOutcome вызывается после обработки запроса с финальным HTTP-статусом.
	// Возвращаемое действие указывает, что сделать со счётчиком этого ключа.
	onOutcome func(status int) outcomeAction
}

type outcomeAction int

const (
	outcomeNone outcomeAction = iota
	// outcomeReset — сбросить счётчик (успешный вход обнуляет ошибки входа).
	outcomeReset
	// outcomeRelease — вычесть засчитанный hit (неудачная попытка не должна
	// потреблять общий per-IP бюджет, пока включён учёт только по ошибкам).
	outcomeRelease
)

// OnFailedStatus — опция «учёт только по неудачам» для пред-фильтра запросов
// (например, общий per-IP бюджет login_ip): засчитанный increment откатывается
// (decrement/release), если финальный статус НЕ входит в список failed.
// Типичный вызов: OnFailedStatus(http.StatusUnauthorized) — hit потребляется
// только при 401 (неверные учётные данные); успешные (200), валидационные
// (400) и запрещённые (403) ответы счётчик не тратят. Обратный вызов cb
// (может быть nil) получает факт неудачи и статус — на нём роутер строит
// составной ключ login_failed.
func OnFailedStatus(cb func(failed bool, status int), failedStatuses ...int) RateLimitOption {
	return func(c *rateLimitConfig) {
		c.onOutcome = func(status int) outcomeAction {
			failed := len(failedStatuses) == 0 // без списка: любой ответ считается неудачей
			for _, s := range failedStatuses {
				if status == s {
					failed = true
					break
				}
			}
			if cb != nil {
				cb(failed, status)
			}
			if !failed {
				return outcomeRelease
			}
			return outcomeNone
		}
	}
}

// ResetOnSuccess — опция «сброс при успехе»: финальный статус 2xx удаляет
// окно текущего ключа (успешный вход обнуляет счётчик неудачных попыток).
func ResetOnSuccess() RateLimitOption {
	return func(c *rateLimitConfig) {
		c.onOutcome = func(status int) outcomeAction {
			if status >= 200 && status < 300 {
				return outcomeReset
			}
			return outcomeNone
		}
	}
}

// RateLimit возвращает middleware ограничения частоты запросов, использующий
// переданный порт store.Increment для учёта попаданий в окне window.
//
// Опции onOutcome позволяют строить политики «только неудачные попытки»:
//   - decrement при не-неудачном статусе (OnFailedStatus) — лимит по IP/аккаунту
//     тратится только на реальные промахи аутентификации;
//   - reset при 2xx (ResetOnSuccess) — успешный вход обнуляет счётчик неудач.
func RateLimit(store RateLimitStore, limit int, window time.Duration, keyFn func(*http.Request) string, opts ...RateLimitOption) func(http.Handler) http.Handler {
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
			cfgRL := &rateLimitConfig{}
			for _, o := range opts {
				o(cfgRL)
			}
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			res, err := store.Increment(ctx, key, window)
			if err != nil {
				response.Error(w, http.StatusServiceUnavailable, messages.AuthenticationUnavailable, nil)
				return
			}
			if res.Count > limit {
				// Retry-After = ОСТАВШЕЕСЯ время до сброса окна (секунды),
				// а не вся длина окна: клиент узнаёт, когда именно откроется
				// следующее фиксированное окно (reset_at). Минимум 1 секунда.
				retry := int64(time.Until(res.ResetAt).Round(time.Second).Seconds())
				if retry < 1 {
					retry = 1
				}
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retry))
				response.Error(w, http.StatusTooManyRequests, "Слишком много запросов", nil)
				return
			}
			if cfgRL.onOutcome == nil {
				next.ServeHTTP(w, r)
				return
			}
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			switch cfgRL.onOutcome(rec.status) {
			case outcomeReset:
				sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer scancel()
				_ = store.Reset(sctx, key)
			case outcomeRelease:
				sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer scancel()
				// best-effort decrement засчитанного hit (см. releaseIncrement).
				_ = releaseIncrement(sctx, store, key, window)
			}
		})
	}
}

// releaseIncrement — «вычет» одного hit из текущего окна. Реализуется через
// необязательный интерфейс с методом Release (его предоставляет
// persistence.RateLimitRepository — атомарный UPDATE hits = hits - 1 с
// удалением строки при достижении нуля). Если хранилище метода не
// поддерживает, выполняется Reset ключа: консервативнее (окно обнуляется),
// но для anti-lockout политик безопасно — счётчики ведутся только по
// реальным попыткам/неудачам.
func releaseIncrement(ctx context.Context, store RateLimitStore, key string, window time.Duration) error {
	if rel, ok := store.(interface {
		Release(ctx context.Context, key string, window time.Duration) error
	}); ok {
		return rel.Release(ctx, key, window)
	}
	return store.Reset(ctx, key)
}

// LoginFailureCounter — post-фильтр политики login_failed для POST /login:
// увеличивает счётчик hmac(ip|email) ТОЛЬКО когда внутренний обработчик
// вернул 401 (неверные учётные данные). Успешный вход (2xx) сбрасывает этот
// счётчик полностью (ResetOnSuccess) — легитимного пользователя нельзя
// заблокировать накопленными ранее ошибками (защита от account lockout DoS).
// При превышении лимита неудач отвечает 429 + Retry-After (оставшееся до
// сброса окна). Ошибки хранилища — fail-closed (503), как и RateLimit.
func LoginFailureCounter(store RateLimitStore, limit int, window time.Duration, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limit < 1 || window <= 0 || store == nil || keyFn == nil {
				response.Error(w, http.StatusServiceUnavailable, messages.AuthenticationUnavailable, nil)
				return
			}
			key := keyFn(r)
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			res, err := store.Increment(ctx, key, window)
			cancel()
			if err != nil {
				response.Error(w, http.StatusServiceUnavailable, messages.AuthenticationUnavailable, nil)
				return
			}
			if res.Count > limit {
				retry := int64(time.Until(res.ResetAt).Round(time.Second).Seconds())
				if retry < 1 {
					retry = 1
				}
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retry))
				response.Error(w, http.StatusTooManyRequests, "Слишком много запросов", nil)
				return
			}
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			switch {
			case rec.status >= 200 && rec.status < 300:
				// Успешная аутентификация: сброс счётчика неудач (decrement
				// до нуля = удаление окна).
				sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer scancel()
				_ = store.Reset(sctx, key)
			case rec.status == http.StatusUnauthorized:
				// Неудачная аутентификация: hit остаётся засчитанным.
			default:
				// Любой другой исход (400/403/500...) не является промахом
				// аутентификации — возвращаем засчитанный hit.
				sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer scancel()
				_ = releaseIncrement(sctx, store, key, window)
			}
		})
	}
}

// SEC-05: заголовки, позволяющие переопределить клиентский адрес. Читаются
// ТОЛЬКО если сам запрос пришёл от доверенного прокси (Config.TrustedProxies).
var (
	trueClientIPEndpoint = http.CanonicalHeaderKey("True-Client-IP")
	xRealIPEndpoint      = http.CanonicalHeaderKey("X-Real-IP")
	xForwardedForEndpoin = http.CanonicalHeaderKey("X-Forwarded-For")
)

// trustedProxy — элемент whitelist'а: точный IP или CIDR-сеть.
type trustedProxy struct {
	ip   net.IP
	netw *net.IPNet
}

// parseTrustedProxies конвертирует строки конфига (точные IP или CIDR) в
// матчеры. Некорректные значения игнорируются (шумный fail-fast здесь не
// требуется: недоверенный прокси просто не попадёт в whitelist).
func parseTrustedProxies(entries []string) ([]trustedProxy, error) {
	out := make([]trustedProxy, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			_, n, err := net.ParseCIDR(e)
			if err != nil {
				continue
			}
			out = append(out, trustedProxy{netw: n})
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			continue
		}
		out = append(out, trustedProxy{ip: ip})
	}
	return out, nil
}

// hostOf извлекает хост из RemoteAddr вида "ip:port" (IPv6 в скобках).
func hostOf(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}

// isTrustedProxy проверяет, входит ли хост RemoteAddr в whitelist.
func isTrustedProxy(remoteAddr string, parsed []trustedProxy) bool {
	if len(parsed) == 0 {
		return false
	}
	ip := net.ParseIP(hostOf(strings.TrimSpace(remoteAddr)))
	if ip == nil {
		return false
	}
	for _, tp := range parsed {
		if tp.netw != nil {
			if tp.netw.Contains(ip) {
				return true
			}
			continue
		}
		if tp.ip.Equal(ip) {
			return true
		}
	}
	return false
}

// clientIPFromHeaders вычисляет адрес клиента из заголовков прокси:
// True-Client-IP → X-Real-IP → первый элемент X-Forwarded-For. Пустая строка,
// если ничего валидного не найдено.
func clientIPFromHeaders(h http.Header) string {
	v := h.Get(trueClientIPEndpoint)
	if v == "" {
		v = h.Get(xRealIPEndpoint)
	}
	if v == "" {
		if xff := h.Get(xForwardedForEndpoin); xff != "" {
			if i := strings.Index(xff, ","); i >= 0 {
				xff = xff[:i]
			}
			v = xff
		}
	}
	v = strings.TrimSpace(v)
	if v == "" || net.ParseIP(v) == nil {
		return ""
	}
	return v
}

// RealIPFromTrustedProxies — безопасная замена chimw.RealIP (SEC-05):
// заголовки X-Forwarded-For / X-Real-IP / True-Client-IP применяются только
// когда запрос пришёл от прокси из whitelist cfg.TrustedProxies. Иначе
// используется фактический r.RemoteAddr — подделкой заголовка нельзя ни
// обходить rate-limiting по IP, ни «подменить» источник события.
//
// Обновляется r.RemoteAddr: все последующие middleware (Logger, RateLimit
// через ClientIP) читают именно его.
func RealIPFromTrustedProxies(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		parsed, _ := parseTrustedProxies(cfg.TrustedProxies)
		fn := func(w http.ResponseWriter, r *http.Request) {
			if len(parsed) > 0 && isTrustedProxy(r.RemoteAddr, parsed) {
				if rip := clientIPFromHeaders(r.Header); rip != "" {
					r.RemoteAddr = rip
				}
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
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

// KeyPolicy — конфигурация генератора ключей rate-limit: отдельный HMAC-ключ
// для хеширования PII (cfg.RateLimitHMACKey) и имя политики маршрута,
// входящее в bucket_key. Разные политики => разные buckets даже при одинаковом
// идентификаторе (IP/email): /register и /logout одного IP не пересекаются.
type KeyPolicy struct {
	HMACKey []byte
	Policy  string
}

// NewKeyPolicy создаёт генератор ключей для политики policy с ключом hmacKey.
func NewKeyPolicy(hmacKey []byte, policy string) KeyPolicy {
	return KeyPolicy{HMACKey: hmacKey, Policy: policy}
}

// Key возвращает bucket-ключ rl:<policy>:<version>:<hmac(rawID)> для сырого
// идентификатора (IP, email, токен-хеш, user id). Пустой rawID допустим:
// он также хешируется — в БД не попадает ничего, кроме HMAC-дайджеста.
func (p KeyPolicy) Key(rawID string) string {
	return bucketKey(p.HMACKey, p.Policy, rawID)
}

// AccountIPKey — ключ лимитера POST /login по связке IP+email (политика
// login_ip). Email никогда не кладётся в ключ открытым текстом: он входит
// только как входные данные HMAC-SHA256 (см. KeyPolicy).
func AccountIPKey(cfg *config.Config) func(*http.Request) string {
	p := NewKeyPolicy(cfg.RateLimitHMACKey, PolicyLoginIP)
	return func(r *http.Request) string {
		return p.Key(ClientIP(r) + "|" + loginEmail(r))
	}
}

// IPKey — общий per-IP ключ (историческое API): политика "ip", идентификатор
// — IP, всё под HMAC. Маршруты login/register/logout применяют
// специализированные политики ниже; IPKey покрыт тестами RealIP.
func IPKey(cfg *config.Config) func(*http.Request) string {
	p := NewKeyPolicy(cfg.RateLimitHMACKey, "ip")
	return func(r *http.Request) string { return p.Key(ClientIP(r)) }
}

// RegisterKey — изолированный per-IP лимит POST /register (политика register).
// Не пересекается ни с /login, ни с /logout: 100 попыток регистрации с одного
// IP исчерпывают только bucket rl:register:v1:<hmac(ip)>.
func RegisterKey(cfg *config.Config) func(*http.Request) string {
	p := NewKeyPolicy(cfg.RateLimitHMACKey, PolicyRegister)
	return func(r *http.Request) string { return p.Key(ClientIP(r)) }
}

// LogoutKey — изолированный per-IP лимит POST /logout (политика logout).
func LogoutKey(cfg *config.Config) func(*http.Request) string {
	p := NewKeyPolicy(cfg.RateLimitHMACKey, PolicyLogout)
	return func(r *http.Request) string { return p.Key(ClientIP(r)) }
}

// LoginFailedKey — ключ счётчика «только неудачные попытки» для POST /login
// (политика login_failed): hmac(ip|email). Инкремент происходит ТОЛЬКО когда
// внутренний обработчик вернул 401 (неверные учётные данные) — см.
// LoginFailureCounter в router. Успешный вход сбрасывает этот счётчик
// (ResetOnSuccess), поэтому легитимного пользователя нельзя заблокировать
// накопленными ошибками (account lockout DoS).
func LoginFailedKey(cfg *config.Config) func(*http.Request) string {
	p := NewKeyPolicy(cfg.RateLimitHMACKey, PolicyLoginFailed)
	return func(r *http.Request) string {
		return p.Key(ClientIP(r) + "|" + loginEmail(r))
	}
}

// RefreshKey строит ключ rate limiter для POST /refresh одинаково для обоих
// типов клиентов: хешируется (SHA-256, без значения токена в ключе/логах)
// фактический носитель refresh-токена — Bearer-заголовок (мобильные/серверные
// клиенты), иначе cookie refresh_token (веб). При отсутствии обоих используется
// IP. Итог дополнительно проходит через HMAC политики refresh: в таблице —
// только дайджест вида rl:refresh:v1:<hmac(...)>.
func RefreshKey(cfg *config.Config) func(*http.Request) string {
	p := NewKeyPolicy(cfg.RateLimitHMACKey, PolicyRefresh)
	return func(r *http.Request) string {
		raw := bearerRefreshCredential(r)
		if raw == "" {
			if c, err := r.Cookie("refresh_token"); err == nil && c.Value != "" {
				raw = c.Value
			}
		}
		if raw == "" {
			return p.Key("ip|" + ClientIP(r))
		}
		h := sha256.Sum256([]byte(raw))
		return p.Key(base64.RawURLEncoding.EncodeToString(h[:]))
	}
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

// AccountGlobalKey — глобальный (независимый от IP) лимит на аккаунт по email
// для POST /login (политика login_account). Защита от брутфорса одного
// аккаунта с разных IP; email хранится только как HMAC-дайджест.
func AccountGlobalKey(cfg *config.Config) func(*http.Request) string {
	p := NewKeyPolicy(cfg.RateLimitHMACKey, PolicyLoginAccount)
	return func(r *http.Request) string {
		email := loginEmail(r)
		if email == "" {
			// Невалидное/отсутствующее email: отдельный bucket на IP, чтобы
			// мусорные запросы не сливались в один общий счётчик.
			return p.Key("invalid|" + ClientIP(r))
		}
		return p.Key(email)
	}
}

// UserKey — per-user лимит для аутентифицированных маршрутов (политика
// authenticated); при отсутствии Principal — изолированный bucket на IP.
func UserKey(cfg *config.Config) func(*http.Request) string {
	p := NewKeyPolicy(cfg.RateLimitHMACKey, PolicyAuthenticated)
	ip := NewKeyPolicy(cfg.RateLimitHMACKey, "ip")
	return func(r *http.Request) string {
		principal, ok := FromContext(r.Context())
		if !ok {
			return ip.Key(ClientIP(r))
		}
		return p.Key(principal.ID.String())
	}
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}
