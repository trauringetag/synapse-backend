package handler

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/trauringetag/synapse-backend/internal/auth"
	"github.com/trauringetag/synapse-backend/internal/config"
	"github.com/trauringetag/synapse-backend/internal/httputil"
	"github.com/trauringetag/synapse-backend/internal/models"
	"github.com/trauringetag/synapse-backend/internal/repository"
)

type AuthHandler struct {
	cfg    *config.Config
	users  *repository.UserRepository
	tokens *repository.TokenRepository
}

func NewAuthHandler(cfg *config.Config, users *repository.UserRepository, tokens *repository.TokenRepository) *AuthHandler {
	return &AuthHandler{cfg: cfg, users: users, tokens: tokens}
}

type registerRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	AdminToken string `json:"admin_token"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type messageResponse struct {
	Message string `json:"message"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	h.registerWithRole(w, r, models.RoleUser, false)
}

func (h *AuthHandler) RegisterAdmin(w http.ResponseWriter, r *http.Request) {
	h.registerWithRole(w, r, models.RoleAdmin, true)
}

func (h *AuthHandler) registerWithRole(w http.ResponseWriter, r *http.Request, role string, requireAdminToken bool) {
	var req registerRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "Некорректное тело JSON")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	firstName := strings.TrimSpace(req.FirstName)
	lastName := strings.TrimSpace(req.LastName)
	if email == "" || !strings.Contains(email, "@") {
		httputil.Error(w, http.StatusBadRequest, "Необходим действительный адрес электронной почты")
		return
	}
	if len(req.Password) < 8 {
		httputil.Error(w, http.StatusBadRequest, "Пароль должен содержать не менее 8 символов")
		return
	}
	if firstName == "" || lastName == "" {
		httputil.Error(w, http.StatusBadRequest, "Необходимо указать имя и фамилию")
		return
	}
	if requireAdminToken {
		provided := strings.TrimSpace(req.AdminToken)
		if provided == "" {
			provided = strings.TrimSpace(r.Header.Get("X-Admin-Token"))
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(h.cfg.AdminRegisterToken)) != 1 {
			httputil.Error(w, http.StatusForbidden, "Недействительный токен регистрации администратора")
			return
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось хешировать пароль")
		return
	}
	user, err := h.users.Create(r.Context(), email, string(hash), role, firstName, lastName)
	if err == repository.ErrConflict {
		httputil.Error(w, http.StatusConflict, "Электронная почта уже зарегистрирована")
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось создать пользователя")
		return
	}
	httputil.JSON(w, http.StatusCreated, user)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "Некорректное тело JSON")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	user, err := h.users.GetByEmail(r.Context(), email)
	if err != nil {
		httputil.Error(w, http.StatusUnauthorized, "Неверный email или пароль")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		httputil.Error(w, http.StatusUnauthorized, "Неверный email или пароль")
		return
	}
	if err := h.issueSession(w, r, user); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось выпустить токены")
		return
	}
	httputil.JSON(w, http.StatusOK, map[string]any{
		"message": "В системе",
		"user":    user,
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	raw, err := auth.ReadCookie(r, auth.RefreshCookie)
	if err != nil || raw == "" {
		httputil.Error(w, http.StatusUnauthorized, "Отсутствует cookie-файл токена обновления")
		return
	}
	claims, err := auth.Parse(h.cfg, raw, "refresh")
	if err != nil {
		httputil.Error(w, http.StatusUnauthorized, "Недействительный или просроченный токен обновления")
		return
	}
	hash := auth.HashToken(raw)
	stored, err := h.tokens.GetActive(r.Context(), hash)
	if err != nil || stored.Revoked || time.Now().After(stored.ExpiresAt) {
		httputil.Error(w, http.StatusUnauthorized, "Токен обновления отозван или неизвестен")
		return
	}
	_ = h.tokens.Revoke(r.Context(), hash)

	id, err := repository.UUIDFromString(claims.Subject)
	if err != nil {
		httputil.Error(w, http.StatusUnauthorized, "Недопустимый токен субъекта")
		return
	}
	user, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		httputil.Error(w, http.StatusUnauthorized, "Пользователь не найден")
		return
	}
	if err := h.issueSession(w, r, user); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось выпустить токены")
		return
	}
	httputil.JSON(w, http.StatusOK, messageResponse{Message: "Токены обновлены"})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if raw, err := auth.ReadCookie(r, auth.RefreshCookie); err == nil && raw != "" {
		_ = h.tokens.Revoke(r.Context(), auth.HashToken(raw))
	}
	auth.ClearTokenCookies(w, h.cfg)
	httputil.JSON(w, http.StatusOK, messageResponse{Message: "Вышли из системы"})
}

func (h *AuthHandler) issueSession(w http.ResponseWriter, r *http.Request, user *models.User) error {
	pair, err := auth.IssuePair(h.cfg, user.ID, user.Email, user.Role)
	if err != nil {
		return err
	}
	if err := h.tokens.Store(r.Context(), user.ID, auth.HashToken(pair.RefreshToken), pair.RefreshExp); err != nil {
		return err
	}
	auth.SetTokenCookies(w, h.cfg, pair)
	return nil
}
