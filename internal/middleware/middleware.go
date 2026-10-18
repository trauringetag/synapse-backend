package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/auth"
	"github.com/trauringetag/synapse-backend/internal/config"
	"github.com/trauringetag/synapse-backend/internal/httputil"
	"github.com/trauringetag/synapse-backend/internal/models"
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

func Authenticate(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := auth.ReadCookie(r, auth.AccessCookie)
			if err != nil || raw == "" {
				httputil.Error(w, http.StatusUnauthorized, "Необходима авторизация для получения доступа")
				return
			}
			claims, err := auth.Parse(cfg, raw, "access")
			if err != nil {
				httputil.Error(w, http.StatusUnauthorized, "Недействительный или просроченный токен доступа")
				return
			}
			id, err := uuid.Parse(claims.Subject)
			if err != nil {
				httputil.Error(w, http.StatusUnauthorized, "Недопустимый токен субъекта")
				return
			}
			p := &Principal{ID: id, Email: claims.Email, Role: claims.Role}
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
				httputil.Error(w, http.StatusUnauthorized, "Не авторизован")
				return
			}
			if _, ok := allowed[p.Role]; !ok {
				httputil.Error(w, http.StatusForbidden, "Недостаточно прав")
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
