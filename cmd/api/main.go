package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"golang-rest-api/internal/database"
	"golang-rest-api/internal/handlers"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Файл .env не найден, используем переменные окружения ОС")
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
		log.Fatalf("Ошибка миграций: %v", err)
	}

	h := &handlers.Handlers{DB: pool}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /users", h.GetUsers)
	mux.HandleFunc("POST /users", h.CreateUser)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Сервер запущен на порту :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Сервер умер: %v", err)
	}
}
