package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"synapse-backend/internal/middleware"
	"synapse-backend/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func respondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func respondJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

func setRefreshTokenCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	isSecure := os.Getenv("COOKIE_SECURE") == "true"
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token,
		Expires:  expiresAt,
		Path:     "/",
		HttpOnly: true, // Запрещает доступ через JavaScript (защита от XSS)
		Secure:   isSecure, // Требует HTTPS (включайте true в .env для продакшена)
		SameSite: http.SameSiteStrictMode, // Защита от CSRF-атак
	})
}

func clearRefreshTokenCookie(w http.ResponseWriter) {
	isSecure := os.Getenv("COOKIE_SECURE") == "true"
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Unix(0, 0), // Мгновенное истечение срока действия
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

type AuthHandlers struct {
	userRepo repository.UserRepository
}

func NewAuthHandlers(userRepo repository.UserRepository) *AuthHandlers {
	return &AuthHandlers{userRepo: userRepo}
}

func generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (h *AuthHandlers) Register(w http.ResponseWriter, r *http.Request) {
	var input struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Password  string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondError(w, http.StatusBadRequest, "Неверный формат JSON")
		return
	}

	if input.FirstName == "" || input.LastName == "" || input.Email == "" || input.Password == "" {
		respondError(w, http.StatusBadRequest, "Все поля обязательны для заполнения")
		return
	}

	if len(input.Password) < 8 {
		respondError(w, http.StatusBadRequest, "Пароль должен содержать минимум 8 символов")
		return
	}

	user := &repository.User{
		FirstName:    input.FirstName,
		LastName:     input.LastName,
		Email:        input.Email,
		PasswordHash: input.Password,
		Role:         "user",
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

func (h *AuthHandlers) RegisterAdmin(w http.ResponseWriter, r *http.Request) {
	adminSecret := os.Getenv("ADMIN_SECRET_KEY")
	if adminSecret == "" {
		adminSecret = "super-secret-admin-key-change-in-production"
	}

	reqSecret := r.Header.Get("X-Admin-Secret")
	if reqSecret != adminSecret {
		respondError(w, http.StatusForbidden, "Доступ запрещен: неверный секретный ключ")
		return
	}

	var input struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Email     string `json:"email"`
		Password  string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondError(w, http.StatusBadRequest, "Неверный формат JSON")
		return
	}

	if input.FirstName == "" || input.LastName == "" || input.Email == "" || input.Password == "" {
		respondError(w, http.StatusBadRequest, "Все поля обязательны для заполнения")
		return
	}

	if len(input.Password) < 8 {
		respondError(w, http.StatusBadRequest, "Пароль должен содержать минимум 8 символов")
		return
	}

	user := &repository.User{
		FirstName:    input.FirstName,
		LastName:     input.LastName,
		Email:        input.Email,
		PasswordHash: input.Password,
		Role:         "admin",
	}

	if err := h.userRepo.Create(r.Context(), user); err != nil {
		respondError(w, http.StatusBadRequest, "Ошибка при регистрации администратора. Возможно, email уже используется")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "Администратор успешно зарегистрирован",
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

	user.TokenVersion++
	if err := h.userRepo.IncrementTokenVersion(r.Context(), user.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка сервера при обновлении сессии")
		return
	}

	accessClaims := &middleware.Claims{
		UserID:       user.ID,
		Email:        user.Email,
		Role:         user.Role,
		TokenVersion: user.TokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(middleware.JWTSecret)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка при создании токена доступа")
		return
	}

	refreshTokenStr, err := generateRefreshToken()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка при создании токена обновления")
		return
	}
	refreshExpiresAt := time.Now().Add(7 * 24 * time.Hour)
	if err := h.userRepo.UpdateRefreshToken(r.Context(), user.ID, refreshTokenStr, refreshExpiresAt); err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка сервера при сохранении сессии")
		return
	}

	setRefreshTokenCookie(w, refreshTokenStr, refreshExpiresAt)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": accessTokenString,
		"role":         user.Role,
		"user": map[string]interface{}{
			"id":         user.ID,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"email":      user.Email,
		},
	})
}

func (h *AuthHandlers) Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil || cookie.Value == "" {
		respondError(w, http.StatusUnauthorized, "Токен обновления отсутствует")
		return
	}
	refreshTokenStr := cookie.Value

	user, err := h.userRepo.FindByRefreshToken(r.Context(), refreshTokenStr)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "Недействительный токен обновления")
		return
	}
	if time.Now().After(user.RefreshTokenExpiresAt) {
		respondError(w, http.StatusUnauthorized, "Срок действия токена обновления истек")
		return
	}

	newRefreshTokenStr, err := generateRefreshToken()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка при создании токена обновления")
		return
	}
	newRefreshExpiresAt := time.Now().Add(7 * 24 * time.Hour)
	if err := h.userRepo.UpdateRefreshToken(r.Context(), user.ID, newRefreshTokenStr, newRefreshExpiresAt); err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка сервера при обновлении сессии")
		return
	}

	setRefreshTokenCookie(w, newRefreshTokenStr, newRefreshExpiresAt)

	accessClaims := &middleware.Claims{
		UserID:       user.ID,
		Email:        user.Email,
		Role:         user.Role,
		TokenVersion: user.TokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(middleware.JWTSecret)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка при создании токена доступа")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": accessTokenString,
	})
}

func (h *AuthHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaimsFromContext(r.Context())
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Не авторизован")
		return
	}

	if err := h.userRepo.ClearRefreshToken(r.Context(), claims.UserID); err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка сервера при выходе из системы")
		return
	}

	if err := h.userRepo.IncrementTokenVersion(r.Context(), claims.UserID); err != nil {
		respondError(w, http.StatusInternalServerError, "Ошибка сервера при выходе из системы")
		return
	}

	clearRefreshTokenCookie(w)

	respondJSON(w, http.StatusOK, map[string]string{"message": "Успешный выход из системы"})
}