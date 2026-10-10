package main

import (
	"context"
	
	"fmt"
	"log"
	"net/http"
	"os"

	"synapse-backend/internal/database"
	"synapse-backend/internal/handlers"
	"synapse-backend/internal/middleware"
	"synapse-backend/internal/repository"

	"github.com/joho/godotenv"
)

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowedOrigins := map[string]bool{
			"http://localhost:5173": true,
			"http://localhost:3000": true,
		}
		allowOrigin := "http://localhost:5173"
		if allowedOrigins[origin] {
			allowOrigin = origin
		}
		w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Secret")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Файл .env не найден, используем переменные окружения ОС")
	}

	middleware.InitJWT()

	connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("POSTGRES_DB"),
	)

	pool, err := database.NewPool(connString)
	if err != nil {
		log.Fatalf("Ошибка подключения к БД: %v", err)
	}
	defer pool.Close()

	if err := database.RunMigrations(pool); err != nil {
		log.Fatalf("Ошибка применения миграций: %v", err)
	}

	userRepo := repository.NewUserRepository(pool)
	h := handlers.NewHandlers(userRepo)
	authHandlers := handlers.NewAuthHandlers(userRepo)

	checkTokenVersion := func(ctx context.Context, userID int, version int) bool {
		currentVersion, err := userRepo.GetTokenVersion(ctx, userID)
		if err != nil {
			return false
		}
		return currentVersion == version
	}

	mux := http.NewServeMux()
	
	// Публичные эндпоинты
	mux.HandleFunc("POST /auth/register", authHandlers.Register)
	mux.HandleFunc("POST /auth/login", authHandlers.Login)
	mux.HandleFunc("POST /auth/refresh", authHandlers.Refresh)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.HandleFunc("POST /auth/register-admin", authHandlers.RegisterAdmin)

	// Защищённые эндпоинты
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("GET /users", h.GetUsers)
	protectedMux.HandleFunc("POST /users", h.CreateUser)
	protectedMux.HandleFunc("DELETE /users/{id}", h.DeleteUser)
	protectedMux.HandleFunc("GET /users/me", h.GetMe)
	protectedMux.HandleFunc("POST /auth/logout", authHandlers.Logout)

	mux.Handle("/", middleware.JWTMiddleware(protectedMux, checkTokenVersion))

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Сервер успешно запущен: http://localhost:%s", port)

	if err := http.ListenAndServe(":"+port, corsMiddleware(mux)); err != nil {
		log.Fatalf("Сервер упал: %v", err)
	}
}