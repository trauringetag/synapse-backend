package main

import (
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

// corsMiddleware разрешает запросы с фронтенда
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173") // Адрес Vite по умолчанию
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Admin-Secret")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("️Файл .env не найден, используем переменные окружения ОС")
	}

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

	mux := http.NewServeMux()

	// Публичные эндпоинты (без защиты)
	mux.HandleFunc("POST /auth/register", authHandlers.Register)
	mux.HandleFunc("POST /auth/login", authHandlers.Login)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Создание админа — защищено секретным ключом из .env (не JWT)
	mux.HandleFunc("POST /auth/register-admin", authHandlers.RegisterAdmin)

	// Защищённые эндпоинты (требуют JWT)
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("GET /users", h.GetUsers)
	protectedMux.HandleFunc("POST /users", h.CreateUser)
	protectedMux.HandleFunc("DELETE /users/{id}", h.DeleteUser)

	mux.Handle("/", middleware.JWTMiddleware(protectedMux))

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Сервер успешно запущен: http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, corsMiddleware(mux)); err != nil {
		log.Fatalf("💥 Сервер упал: %v", err)
	}
}
