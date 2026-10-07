package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"golang-rest-api/internal/middleware"
	"golang-rest-api/internal/repository"
)

// Handlers хранит зависимости, необходимые для обработки HTTP-запросов.
// Зависит от интерфейса, а не от конкретной реализации БД.
type Handlers struct {
	userRepo repository.UserRepository
}

// NewHandlers создает новый экземпляр хендлеров
func NewHandlers(userRepo repository.UserRepository) *Handlers {
	return &Handlers{
		userRepo: userRepo,
	}
}

// --- Вспомогательные функции для унифицированных ответов ---

func respondJSON(w http.ResponseWriter, status int, payload any) {

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false) // Сохраняем кириллицу без экранирования
	if err := encoder.Encode(payload); err != nil {
		// Если не смогли закодировать JSON, это уже критическая ошибка сервера
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

// --- HTTP Хендлеры ---

func (h *Handlers) GetUsers(w http.ResponseWriter, r *http.Request) {

	claims := middleware.GetClaimsFromContext(r.Context())
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Не удалось получить данные пользователя из токена")
		return
	}

	var users []repository.User
	var err error

	if claims.Role == "admin" {
		// Админ видит всех
		users, err = h.userRepo.GetAll(r.Context())
	} else {
		// Обычный пользователь видит только себя
		user, err := h.userRepo.GetByID(r.Context(), claims.UserID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Ошибка при получении данных пользователя")
			return
		}
		users = []repository.User{*user}
	}

	if err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка сервера при получении списка пользователей")
		return
	}

	respondJSON(w, http.StatusOK, users)
}

func (h *Handlers) CreateUser(w http.ResponseWriter, r *http.Request) {

	claims := middleware.GetClaimsFromContext(r.Context())
	if claims == nil || claims.Role != "admin" {
		respondError(w, http.StatusForbidden, "Только администратор может создавать пользователей")
		return
	}

	var u repository.User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		respondError(w, http.StatusBadRequest, "Неверный формат JSON в теле запроса")
		return
	}

	if u.FirstName == "" || u.LastName == "" || u.Email == "" {
		respondError(w, http.StatusBadRequest, "Поля first_name, last_name и email являются обязательными")
		return
	}

	if err := h.userRepo.Create(r.Context(), &u); err != nil {
		respondError(w, http.StatusBadRequest, "Ошибка при создании пользователя. Возможно, такой email уже существует")
		return
	}

	respondJSON(w, http.StatusCreated, u)
}

func (h *Handlers) DeleteUser(w http.ResponseWriter, r *http.Request) {

	claims := middleware.GetClaimsFromContext(r.Context())
	if claims == nil || claims.Role != "admin" {
		respondError(w, http.StatusForbidden, "Только администратор может удалять пользователей")
		return
	}

	idStr := r.PathValue("id")
	if idStr == "" {
		respondError(w, http.StatusBadRequest, "ID пользователя не указан в URL")
		return
	}

	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		respondError(w, http.StatusBadRequest, "Неверный формат ID (должно быть положительное число)")
		return
	}

	if id == claims.UserID {
		respondError(w, http.StatusBadRequest, "Администратор не может удалить сам себя")
		return
	}

	deleted, err := h.userRepo.Delete(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка сервера при удалении пользователя")
		return
	}

	if !deleted {
		respondError(w, http.StatusNotFound, "Пользователь с таким ID не найден")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "Пользователь успешно удален"})
}
