package router

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/trauringetag/synapse-backend/internal/delivery/http/handler"
	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/middleware"
	"github.com/trauringetag/synapse-backend/internal/usecase"
)

// New собирает HTTP-транспорт: готовые use-case'ы (созданные в main.go —
// Composition Root) инъецируются в тонкие HTTP-обработчики.
// last — порт пользователей, необходимый middleware аутентификации для
// проверки статуса/роли по access-токену (это транспортный слой, не handlers).
// rateLimitStore — порт domain.RateLimitStore (реализация — persistence.
// RateLimitRepository): middleware лимитов запросов работает только через
// него, без прямых SQL-запросов и зависимостей от пула БД.
func New(cfg *config.Config, authUC usecase.AuthUseCase, userUC usecase.UserUseCase, last middleware.UserLookup, rateLimitStore domain.RateLimitStore, openAPI []byte) http.Handler {
	authH := handler.NewAuthHandler(cfg, authUC)
	userH := handler.NewUserHandler(userUC)

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.JSONContentType)
	r.Use(middleware.LimitBody)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.CORSOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "X-Admin-Token", "X-Request-ID", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "OK"}`))
	})
	r.Get("/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(openAPI)
	})
	r.Get("/docs", handler.SwaggerUI())
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs", http.StatusFound)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(middleware.CacheControl)
		r.With(middleware.RequireAllowedOrigin(cfg)).Get("/csrf", authH.CSRFToken)
		r.Group(func(r chi.Router) {
			r.Use(middleware.CSRF(cfg))
			r.With(middleware.RateLimit(rateLimitStore, cfg.RegisterRateLimit, time.Hour, middleware.IPKey)).Post("/register", authH.Register)
			r.With(middleware.RateLimit(rateLimitStore, cfg.RegisterRateLimit, time.Hour, middleware.IPKey)).Post("/register-admin", authH.RegisterAdmin)
			r.With(middleware.RateLimit(rateLimitStore, cfg.LoginRateLimit, 15*time.Minute, middleware.AccountIPKey)).
				With(middleware.RateLimit(rateLimitStore, cfg.LoginRateLimit, time.Hour, middleware.AccountGlobalKey)).
				Post("/login", authH.Login)
			r.With(middleware.RateLimit(rateLimitStore, cfg.RefreshRateLimit, time.Minute, middleware.RefreshKey)).Post("/refresh", authH.Refresh)
			r.With(middleware.RateLimit(rateLimitStore, cfg.LogoutRateLimit, time.Minute, middleware.IPKey)).
				Post("/logout", authH.Logout)

			r.Group(func(r chi.Router) {
				r.Use(middleware.Authenticate(cfg, last))
				r.Use(middleware.RateLimit(rateLimitStore, cfg.AuthenticatedRateLimit, time.Minute, middleware.UserKey))
				r.With(middleware.RequireUserOrAdmin).Get("/users/me", userH.Me)
				r.With(middleware.RequireUserOrAdmin).Put("/users/me", userH.PutMe)
				r.With(middleware.RequireUserOrAdmin).Patch("/users/me", userH.PatchMe)

				r.Group(func(r chi.Router) {
					r.Use(middleware.RequireAdmin)
					r.Get("/users", userH.List)
					r.Post("/users", userH.Create)
					r.Get("/users/{id}", userH.GetByID)
					r.Put("/users/{id}", userH.Put)
					r.Patch("/users/{id}", userH.Patch)
					r.Delete("/users/{id}", userH.Delete)
				})
			})
		})
	})

	return r
}
