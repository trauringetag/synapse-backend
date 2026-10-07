package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"golang-rest-api/internal/database"
	"golang-rest-api/internal/handlers"
	"golang-rest-api/internal/middleware"
	"golang-rest-api/internal/repository"

	"github.com/joho/godotenv"
)

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
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Сервер упал: %v", err)
	}
}
