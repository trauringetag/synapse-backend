package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/auth"
	"github.com/trauringetag/synapse-backend/internal/config"
	"github.com/trauringetag/synapse-backend/internal/httputil"
	"github.com/trauringetag/synapse-backend/internal/messages"
	"github.com/trauringetag/synapse-backend/internal/models"
	"github.com/trauringetag/synapse-backend/internal/repository"
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

func Authenticate(cfg *config.Config, users *repository.UserRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := auth.ReadCookie(r, auth.AccessCookie)
			if err != nil || raw == "" {
				httputil.Error(w, http.StatusUnauthorized, messages.AuthorizationRequired, nil)
				return
			}
			claims, err := auth.Parse(cfg, raw, "access")
			if err != nil {
				httputil.Error(w, http.StatusUnauthorized, messages.InvalidOrExpiredAccessToken, nil)
				return
			}
			id, err := uuid.Parse(claims.Subject)
			if err != nil || id == uuid.Nil {
				httputil.Error(w, http.StatusUnauthorized, messages.InvalidSubjectToken, nil)
				return
			}
			user, err := users.GetByID(r.Context(), id)
			if err != nil {
				if errors.Is(err, repository.ErrNotFound) {
					httputil.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
					return
				}
				httputil.Error(w, http.StatusServiceUnavailable, messages.AuthenticationUnavailable, nil)
				return
			}
			if user.Status != models.StatusActive {
				httputil.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
				return
			}
			p := &Principal{ID: user.ID, Email: user.Email, Role: user.Role}
			ctx := context.WithValue(r.Context(), userKey, p)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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
				httputil.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
				return
			}
			if _, ok := allowed[p.Role]; !ok {
				httputil.Error(w, http.StatusForbidden, messages.InsufficientPermissions, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireUserOrAdmin(next http.Handler) http.Handler {
	return RequireRoles(models.RoleUser, models.RoleAdmin)(next)
}

func RequireAdmin(next http.Handler) http.Handler {
	return RequireRoles(models.RoleAdmin)(next)
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

func RateLimit(pool *pgxpool.Pool, limit int, window time.Duration, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key == "" {
				key = "unknown"
			}
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			var count int
			err := pool.QueryRow(ctx, `INSERT INTO api_rate_limits (bucket_key, window_start, hits) VALUES ($1, to_timestamp(floor(extract(epoch from now()) / $2) * $2), 1) ON CONFLICT (bucket_key) DO UPDATE SET window_start = CASE WHEN api_rate_limits.window_start + ($2 * interval '1 second') <= now() THEN EXCLUDED.window_start ELSE api_rate_limits.window_start END, hits = CASE WHEN api_rate_limits.window_start + ($2 * interval '1 second') <= now() THEN 1 ELSE api_rate_limits.hits + 1 END RETURNING hits`, key, int(window.Seconds())).Scan(&count)
			if err != nil {
				httputil.Error(w, http.StatusServiceUnavailable, messages.AuthenticationUnavailable, nil)
				return
			}
			if count > limit {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
				httputil.Error(w, http.StatusTooManyRequests, "Слишком много запросов", nil)
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
func AccountIPKey(r *http.Request) string {
	var body struct {
		Email string `json:"email"`
	}
	if r.Body != nil {
		b, readErr := io.ReadAll(io.LimitReader(r.Body, MaxJSONBodyBytes+1))
		r.Body.Close()
		if readErr != nil || int64(len(b)) > MaxJSONBodyBytes {
			if int64(len(b)) <= MaxJSONBodyBytes {
				b = append(b, ' ')
			}
		}
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		_ = json.Unmarshal(b, &body)
	}
	return "login:" + ClientIP(r) + ":" + strings.ToLower(strings.TrimSpace(body.Email))
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
				httputil.Error(w, http.StatusForbidden, messages.InvalidOrigin, nil)
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
				httputil.Error(w, http.StatusForbidden, messages.InvalidOrigin, nil)
				return
			}
			c, err := r.Cookie("csrf_token")
			token := r.Header.Get("X-CSRF-Token")
			if err != nil || token == "" || !validCSRF(cfg.JWTSecret, c.Value) || !hmac.Equal([]byte(token), []byte(c.Value)) {
				httputil.Error(w, http.StatusForbidden, messages.InvalidCSRFToken, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
func IssueCSRF(secret []byte) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(b)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(nonce))
	return nonce + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func validCSRF(secret []byte, token string) bool {
	p := strings.Split(token, ".")
	if len(p) != 2 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(p[0]))
	return hmac.Equal(sig, mac.Sum(nil))
}
