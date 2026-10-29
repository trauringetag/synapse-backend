package handler

// Тонкий HTTP-слой аутентификации: обработчики только декодируют запрос,
// вызывают метод use-case (internal/usecase) и формируют HTTP-ответ.
// Вся бизнес-логика — валидация, bcrypt, JWT-ротация, CSRF, проверка ролей
// и статусов — перенесена в слой use-case.

import (
	"net/http"

	"github.com/trauringetag/synapse-backend/internal/delivery/http/response"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	auth "github.com/trauringetag/synapse-backend/internal/infrastructure/security"
	"github.com/trauringetag/synapse-backend/internal/messages"
	"github.com/trauringetag/synapse-backend/internal/usecase"
)

type AuthHandler struct {
	cfg *config.Config
	uc  usecase.AuthUseCase
}

func NewAuthHandler(cfg *config.Config, uc usecase.AuthUseCase) *AuthHandler {
	return &AuthHandler{cfg: cfg, uc: uc}
}

type registerRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type messageResponse struct {
	Message string `json:"message"`
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := response.Decode(r, &req); err != nil {
		response.DecodeError(w, err)
		return
	}
	user, err := h.uc.Register(r.Context(), usecase.RegisterInput{
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		respondError(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, user)
}

func (h *AuthHandler) RegisterAdmin(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := response.Decode(r, &req); err != nil {
		response.DecodeError(w, err)
		return
	}
	user, err := h.uc.RegisterAdmin(r.Context(), usecase.RegisterInput{
		Email:      req.Email,
		Password:   req.Password,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		AdminToken: r.Header.Get("X-Admin-Token"),
	})
	if err != nil {
		respondError(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, user)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := response.Decode(r, &req); err != nil {
		response.DecodeError(w, err)
		return
	}
	res, err := h.uc.Login(r.Context(), usecase.LoginInput{Email: req.Email, Password: req.Password})
	if err != nil {
		respondError(w, err)
		return
	}
	setTokenCookies(w, h.cfg, res.Pair)
	response.JSON(w, http.StatusOK, map[string]any{
		"message": messages.AuthorizationSuccessful,
		"user":    res.User,
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	raw, _ := auth.ReadCookie(r, auth.RefreshCookie)
	pair, ok, err := h.uc.Refresh(r.Context(), usecase.RefreshInput{RawRefreshToken: raw})
	if err != nil {
		auth.ClearTokenCookies(w, h.cfg)
		respondError(w, err)
		return
	}
	if !ok {
		auth.ClearTokenCookies(w, h.cfg)
		response.Error(w, http.StatusUnauthorized, messages.InvalidOrExpiredRefreshToken, nil)
		return
	}
	setTokenCookies(w, h.cfg, pair)
	response.JSON(w, http.StatusOK, messageResponse{Message: messages.TokensRefreshed})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	raw, cookieErr := auth.ReadCookie(r, auth.RefreshCookie)
	if err := h.uc.Logout(r.Context(), usecase.LogoutInput{
		RawRefreshToken: raw,
		HasCookie:       cookieErr == nil && raw != "",
	}); err != nil {
		auth.ClearTokenCookies(w, h.cfg)
		respondError(w, err)
		return
	}
	auth.ClearTokenCookies(w, h.cfg)
	response.JSON(w, http.StatusOK, messageResponse{Message: messages.LoggedOut})
}

func (h *AuthHandler) CSRFToken(w http.ResponseWriter, r *http.Request) {
	res, err := h.uc.IssueCSRF()
	if err != nil {
		respondError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    res.Token,
		Path:     "/api/v1/",
		Secure:   h.cfg.CookieSecure,
		HttpOnly: false,
		SameSite: h.cfg.CookieSameSite,
		MaxAge:   3600,
	})
	response.JSON(w, http.StatusOK, map[string]string{"csrf_token": res.Token})
}

// setTokenCookies — единственный мост между DTO слоя use-case (usecase.TokenPair)
// и инфраструктурным форматом cookie (auth.Pair). Это деталь транспорта,
// поэтому живёт в HTTP-слое.
func setTokenCookies(w http.ResponseWriter, cfg *config.Config, pair *usecase.TokenPair) {
	if pair == nil {
		return
	}
	auth.SetTokenCookies(w, cfg, &auth.Pair{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		AccessExp:    pair.AccessExp,
		RefreshExp:   pair.RefreshExp,
	})
}
