package handler

import (
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/trauringetag/synapse-backend/internal/delivery/http/response"
	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/domain/models"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/middleware"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/security"
	"github.com/trauringetag/synapse-backend/internal/messages"
)

var dummyHash []byte

func init() {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte("dummy-password-for-timing-attack-protection"),
		bcrypt.DefaultCost,
	)
	if err != nil {
		dummyHash = []byte("$2a$10$SomeHashThatWillNeverMatchAnyPassword12345678901234")
	} else {
		dummyHash = hash
	}
}

type AuthHandler struct {
	cfg    *config.Config
	users  UserStore
	tokens TokenStore
}

func NewAuthHandler(cfg *config.Config, users UserStore, tokens TokenStore) *AuthHandler {
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

	if err := response.Decode(r, &req); err != nil {
		response.DecodeError(w, err)
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
		response.Error(w, http.StatusBadRequest, messages.CheckRequiredFields, errors)
		return
	}

	if requireAdminToken {
		provided := strings.TrimSpace(r.Header.Get("X-Admin-Token"))
		if subtle.ConstantTimeCompare([]byte(provided), []byte(h.cfg.AdminRegisterToken)) != 1 {
			response.Error(w, http.StatusForbidden, messages.InvalidAdminToken, nil)
			return
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		response.Error(w, http.StatusInternalServerError, messages.FailedToHashPassword, nil)
		return
	}
	user, err := h.users.Create(r.Context(), email, string(hash), role, firstName, lastName)
	if err == domain.ErrConflict {
		response.Error(w, http.StatusConflict, messages.EmailAlreadyUsed, nil)
		return
	}
	if err != nil {
		response.Error(w, http.StatusInternalServerError, messages.FailedToCreateUser, nil)
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
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if len(email) > 255 || len(req.Password) > 72 {
		response.Error(w, http.StatusBadRequest, messages.InvalidJSONBody, nil)
		return
	}
	user, err := h.users.GetByEmail(r.Context(), email)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		response.Error(w, http.StatusServiceUnavailable, messages.AuthenticationUnavailable, nil)
		return
	}
	var isValidUser bool
	if err == nil && user.Status == models.StatusActive {
		isValidUser = true
	}
	var hashToCompare []byte
	if isValidUser {
		hashToCompare = []byte(user.PasswordHash)
	} else {
		hashToCompare = dummyHash
	}
	passwordErr := bcrypt.CompareHashAndPassword(hashToCompare, []byte(req.Password))
	if !isValidUser || passwordErr != nil {
		response.Error(w, http.StatusUnauthorized, messages.InvalidCredentials, nil)
		return
	}
	if err := h.issueSession(w, r, user); err != nil {
		response.Error(w, http.StatusInternalServerError, messages.FailedToIssueTokens, nil)
		return
	}
	response.JSON(w, http.StatusOK, map[string]any{
		"message": messages.AuthorizationSuccessful,
		"user":    user,
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	reject := func() {
		auth.ClearTokenCookies(w, h.cfg)
		response.Error(w, http.StatusUnauthorized, messages.InvalidOrExpiredRefreshToken, nil)
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
	id, err := domain.UUIDFromString(claims.Subject)
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
		if errors.Is(err, domain.ErrRefreshTokenReplay) {
			log.Printf("security_event=refresh_token_reuse user_id=%s", id.String())
			if revokeErr := h.tokens.RevokeAllForUser(r.Context(), id); revokeErr != nil {
				log.Printf("event=revoke_all_sessions_failed user_id=%s error=%v", id.String(), revokeErr)
			}
			auth.ClearTokenCookies(w, h.cfg)
			response.Error(w, http.StatusUnauthorized, messages.InvalidOrExpiredRefreshToken, nil)
			return
		}
		if errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrInactiveTokenUser) {
			if errors.Is(err, domain.ErrInactiveTokenUser) {
				log.Printf("security_event=refresh_denied_inactive_user user_id=%s", id.String())
			}
			response.Error(w, http.StatusUnauthorized, messages.InvalidOrExpiredRefreshToken, nil)
			return
		}
		log.Printf("event=refresh_rotation_failed user_id=%s error_type=%T", id.String(), err)
		response.Error(w, http.StatusInternalServerError, messages.FailedToIssueTokens, nil)
		return
	}
	auth.SetTokenCookies(w, h.cfg, pair)
	response.JSON(w, http.StatusOK, messageResponse{Message: messages.TokensRefreshed})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	raw, cookieErr := auth.ReadCookie(r, auth.RefreshCookie)
	if cookieErr == nil && raw != "" {
		if err := h.tokens.Revoke(r.Context(), auth.HashToken(raw)); err != nil {
			log.Printf("event=logout_refresh_revoke_failed error_type=%T", err)
			auth.ClearTokenCookies(w, h.cfg)
			response.Error(w, http.StatusInternalServerError, messages.FailedToRevokeRefreshToken, nil)
			return
		}
	}
	auth.ClearTokenCookies(w, h.cfg)
	response.JSON(w, http.StatusOK, messageResponse{Message: messages.LoggedOut})
}

func (h *AuthHandler) issueSession(w http.ResponseWriter, r *http.Request, user *models.User) error {
	if user == nil || user.Status != models.StatusActive {
		return domain.ErrNotFound
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
		response.Error(w, http.StatusInternalServerError, messages.FailedToPrepareCSRFProtection, nil)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: token, Path: "/api/v1/", Secure: h.cfg.CookieSecure, HttpOnly: false, SameSite: h.cfg.CookieSameSite, MaxAge: 3600})
	response.JSON(w, http.StatusOK, map[string]string{"csrf_token": token})
}
