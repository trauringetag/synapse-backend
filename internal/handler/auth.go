package handler

import (
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/trauringetag/synapse-backend/internal/auth"
	"github.com/trauringetag/synapse-backend/internal/config"
	"github.com/trauringetag/synapse-backend/internal/httputil"
	"github.com/trauringetag/synapse-backend/internal/messages"
	"github.com/trauringetag/synapse-backend/internal/middleware"
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
	h.registerWithRole(w, r, models.RoleUser, false)
}

func (h *AuthHandler) RegisterAdmin(w http.ResponseWriter, r *http.Request) {
	h.registerWithRole(w, r, models.RoleAdmin, true)
}

func (h *AuthHandler) registerWithRole(w http.ResponseWriter, r *http.Request, role string, requireAdminToken bool) {

	var req registerRequest

	if err := httputil.Decode(r, &req); err != nil {
		httputil.DecodeError(w, err)
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	firstName := strings.TrimSpace(req.FirstName)
	lastName := strings.TrimSpace(req.LastName)

	errors := make(map[string][]string)
	if email == "" || !strings.Contains(email, "@") {
		errors["email"] = []string{messages.InvalidEmail}
	}
	if len(email) > 255 {
		errors["email"] = []string{messages.InvalidEmail}
	}
	if len(req.Password) < 8 || len(req.Password) > 72 {
		errors["password"] = []string{messages.PasswordTooShort}
	}
	if len(firstName) > 255 {
		errors["first_name"] = []string{messages.FirstNameRequired}
	}
	if firstName == "" {
		errors["first_name"] = []string{messages.FirstNameRequired}
	}
	if len(lastName) > 255 {
		errors["last_name"] = []string{messages.LastNameRequired}
	}
	if lastName == "" {
		errors["last_name"] = []string{messages.LastNameRequired}
	}
	if len(errors) > 0 {
		httputil.Error(w, http.StatusBadRequest, messages.CheckRequiredFields, errors)
		return
	}

	if requireAdminToken {
		provided := strings.TrimSpace(r.Header.Get("X-Admin-Token"))
		if subtle.ConstantTimeCompare([]byte(provided), []byte(h.cfg.AdminRegisterToken)) != 1 {
			httputil.Error(w, http.StatusForbidden, messages.InvalidAdminToken, nil)
			return
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToHashPassword, nil)
		return
	}
	user, err := h.users.Create(r.Context(), email, string(hash), role, firstName, lastName)
	if err == repository.ErrConflict {
		httputil.Error(w, http.StatusConflict, messages.EmailAlreadyUsed, nil)
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToCreateUser, nil)
		return
	}
	httputil.JSON(w, http.StatusCreated, user)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.DecodeError(w, err)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if len(email) > 255 || len(req.Password) > 72 {
		httputil.Error(w, http.StatusBadRequest, messages.InvalidJSONBody, nil)
		return
	}
	user, err := h.users.GetByEmail(r.Context(), email)
	var isValidUser bool
	if err == nil && user.Status == models.StatusActive {
		isValidUser = true
	}
	var hashToCompare []byte
	if isValidUser {
		hashToCompare = []byte(user.PasswordHash)
	} else {
		hashToCompare = []byte("$2a$10$Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5Q5")
	}
	passwordErr := bcrypt.CompareHashAndPassword(hashToCompare, []byte(req.Password))
	if !isValidUser || passwordErr != nil {
		httputil.Error(w, http.StatusUnauthorized, messages.InvalidCredentials, nil)
		return
	}
	if err := h.issueSession(w, r, user); err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToIssueTokens, nil)
		return
	}
	httputil.JSON(w, http.StatusOK, map[string]any{
		"message": messages.AuthorizationSuccessful,
		"user":    user,
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	reject := func() {
		auth.ClearTokenCookies(w, h.cfg)
		httputil.Error(w, http.StatusUnauthorized, messages.InvalidOrExpiredRefreshToken, nil)
	}
	raw, err := auth.ReadCookie(r, auth.RefreshCookie)
	if err != nil || raw == "" {
		reject()
		return
	}
	claims, err := auth.Parse(h.cfg, raw, "refresh")
	if err != nil {
		reject()
		return
	}
	id, err := repository.UUIDFromString(claims.Subject)
	if err != nil {
		reject()
		return
	}
	var pair *auth.Pair
	_, err = h.tokens.Rotate(r.Context(), auth.HashToken(raw), id, func(user *models.User) (string, time.Time, error) {
		var issueErr error
		pair, issueErr = auth.IssuePair(h.cfg, user.ID, user.Email, user.Role)
		if issueErr != nil {
			return "", time.Time{}, issueErr
		}
		return auth.HashToken(pair.RefreshToken), pair.RefreshExp, nil
	})
	if err != nil {
		auth.ClearTokenCookies(w, h.cfg)
		if errors.Is(err, repository.ErrRefreshTokenReplay) {
			log.Printf("security_event=refresh_token_reuse user_id=%s", id.String())
			httputil.Error(w, http.StatusUnauthorized, messages.InvalidOrExpiredRefreshToken, nil)
			return
		}
		if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInactiveTokenUser) {
			if errors.Is(err, repository.ErrInactiveTokenUser) {
				log.Printf("security_event=refresh_denied_inactive_user user_id=%s", id.String())
			}
			httputil.Error(w, http.StatusUnauthorized, messages.InvalidOrExpiredRefreshToken, nil)
			return
		}
		log.Printf("event=refresh_rotation_failed user_id=%s error_type=%T", id.String(), err)
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToIssueTokens, nil)
		return
	}
	auth.SetTokenCookies(w, h.cfg, pair)
	httputil.JSON(w, http.StatusOK, messageResponse{Message: messages.TokensRefreshed})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	raw, cookieErr := auth.ReadCookie(r, auth.RefreshCookie)
	if cookieErr == nil && raw != "" {
		if err := h.tokens.Revoke(r.Context(), auth.HashToken(raw)); err != nil {
			log.Printf("event=logout_refresh_revoke_failed error_type=%T", err)
			auth.ClearTokenCookies(w, h.cfg)
			httputil.Error(w, http.StatusInternalServerError, messages.FailedToRevokeRefreshToken, nil)
			return
		}
	}
	auth.ClearTokenCookies(w, h.cfg)
	httputil.JSON(w, http.StatusOK, messageResponse{Message: messages.LoggedOut})
}

func (h *AuthHandler) issueSession(w http.ResponseWriter, r *http.Request, user *models.User) error {
	if user == nil || user.Status != models.StatusActive {
		return repository.ErrNotFound
	}
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

func (h *AuthHandler) CSRFToken(w http.ResponseWriter, r *http.Request) {
	token, err := middleware.IssueCSRF(h.cfg.JWTSecret)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToPrepareCSRFProtection, nil)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: token, Path: "/api/v1/", Secure: h.cfg.CookieSecure, HttpOnly: false, SameSite: h.cfg.CookieSameSite, MaxAge: 3600})
	httputil.JSON(w, http.StatusOK, map[string]string{"csrf_token": token})
}
