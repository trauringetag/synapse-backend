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

func Authenticate(cfg *config.Config, users UserLookup) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := auth.ReadCookie(r, auth.AccessCookie)
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
func RefreshKey(r *http.Request) string {
	c, e := r.Cookie("refresh_token")
	if e != nil {
		return "refresh:" + ClientIP(r)
	}
	h := sha256.Sum256([]byte(c.Value))
	return "refresh:" + base64.RawURLEncoding.EncodeToString(h[:])
}

func RequireAllowedOrigin(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := requestOrigin(r)
			if !isAllowedOrigin(cfg, origin) {
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

func CSRF(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
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
