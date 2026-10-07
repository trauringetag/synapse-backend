package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"golang-rest-api/internal/database"
	"golang-rest-api/internal/handlers"
	"golang-rest-api/internal/repository"

	"github.com/joho/godotenv"
)

func main() {
	// 1. Загружаем переменные окружения
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️ Файл .env не найден, используем переменные окружения ОС")
	}

	// 2. Формируем строку подключения к БД
	connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("POSTGRES_DB"),
	)

	// 3. Подключаемся к базе данных
	pool, err := database.NewPool(connString)
	if err != nil {
		log.Fatalf("❌ Ошибка подключения к БД: %v", err)
	}
	// Гарантируем закрытие пула при завершении работы приложения
	defer pool.Close()

	// 4. Применяем миграции (создаем таблицы, если их нет)
	if err := database.RunMigrations(pool); err != nil {
		log.Fatalf("❌ Ошибка применения миграций: %v", err)
	}

	// 5. Инициализируем слой данных (Repository)
	// Теперь хендлеры не знают про pool, они знают только про интерфейс UserRepository
	userRepo := repository.NewUserRepository(pool)

	// 6. Инициализируем хендлеры, передавая им репозиторий (Dependency Injection)
	h := handlers.NewHandlers(userRepo)

	// 7. Настраиваем HTTP-роутер (используем возможности Go 1.22+)
	mux := http.NewServeMux()

	mux.HandleFunc("GET /users", h.GetUsers)
	mux.HandleFunc("POST /users", h.CreateUser)
	mux.HandleFunc("DELETE /users/{id}", h.DeleteUser)

	// Простой эндпоинт для проверки работоспособности (Health Check)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// 8. Запускаем сервер
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Сервер успешно запущен и слушает порт :%s", port)

	// http.ListenAndServe блокирует выполнение, пока сервер работает
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Сервер упал: %v", err)
	}
}
