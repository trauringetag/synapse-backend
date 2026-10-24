package router

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/trauringetag/synapse-backend/internal/config"
	"github.com/trauringetag/synapse-backend/internal/handler"
	"github.com/trauringetag/synapse-backend/internal/middleware"
	"github.com/trauringetag/synapse-backend/internal/repository"
)

func New(cfg *config.Config, users *repository.UserRepository, tokens *repository.TokenRepository, pool *pgxpool.Pool, openAPI []byte) http.Handler {
	authH := handler.NewAuthHandler(cfg, users, tokens)
	userH := handler.NewUserHandler(users)

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
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
			r.With(middleware.RateLimit(pool, cfg.RegisterRateLimit, time.Hour, middleware.IPKey)).Post("/register", authH.Register)
			r.With(middleware.RateLimit(pool, cfg.RegisterRateLimit, time.Hour, middleware.IPKey)).Post("/register-admin", authH.RegisterAdmin)
			r.With(middleware.RateLimit(pool, cfg.LoginRateLimit, 15*time.Minute, middleware.AccountIPKey)).Post("/login", authH.Login)
			r.With(middleware.RateLimit(pool, cfg.RefreshRateLimit, time.Minute, middleware.RefreshKey)).Post("/refresh", authH.Refresh)
			r.Post("/logout", authH.Logout)

			r.Group(func(r chi.Router) {
				r.Use(middleware.Authenticate(cfg, users))
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
