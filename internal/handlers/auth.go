package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang-rest-api/internal/middleware"
	"golang-rest-api/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandlers struct {
	userRepo repository.UserRepository
}

func NewAuthHandlers(userRepo repository.UserRepository) *AuthHandlers {
	return &AuthHandlers{userRepo: userRepo}
}

func (h *AuthHandlers) Register(w http.ResponseWriter, r *http.Request) {
	var input struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Password  string `json:"password"`
		Role      string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondError(w, http.StatusBadRequest, "Неверный формат JSON")
		return
	}

	if input.FirstName == "" || input.LastName == "" || input.Email == "" || input.Password == "" {
		respondError(w, http.StatusBadRequest, "Все поля обязательны для заполнения")
		return
	}

	if len(input.Password) < 6 {
		respondError(w, http.StatusBadRequest, "Пароль должен содержать минимум 6 символов")
		return
	}

	if input.Role != "" && input.Role != "admin" && input.Role != "user" {
		respondError(w, http.StatusBadRequest, "Роль должна быть 'admin' или 'user'")
		return
	}

	user := &repository.User{
		FirstName:    input.FirstName,
		LastName:     input.LastName,
		Email:        input.Email,
		PasswordHash: input.Password, // Репозиторий сам захэширует
		Role:         input.Role,
	}

	if err := h.userRepo.Create(r.Context(), user); err != nil {
		respondError(w, http.StatusBadRequest, "Ошибка при регистрации. Возможно, email уже используется")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "Пользователь успешно зарегистрирован",
		"user_id": user.ID,
		"role":    user.Role,
	})
}

func (h *AuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondError(w, http.StatusBadRequest, "Неверный формат JSON")
		return
	}

	if input.Email == "" || input.Password == "" {
		respondError(w, http.StatusBadRequest, "Email и пароль обязательны")
		return
	}

	user, err := h.userRepo.FindByEmail(r.Context(), input.Email)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Неверный email или пароль")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		respondError(w, http.StatusUnauthorized, "Неверный email или пароль")
		return
	}

	expirationHours, _ := strconv.Atoi(os.Getenv("JWT_EXPIRATION_HOURS"))
	if expirationHours == 0 {
		expirationHours = 24
	}

	claims := &middleware.Claims{
		UserID: user.ID,
		Email:  user.Email,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(expirationHours))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка при создании токена")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"token": tokenString,
		"role":  user.Role,
	})
}
