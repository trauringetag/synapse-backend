package handler

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/trauringetag/synapse-backend/internal/httputil"
	"github.com/trauringetag/synapse-backend/internal/messages"
	"github.com/trauringetag/synapse-backend/internal/middleware"
	"github.com/trauringetag/synapse-backend/internal/models"
	"github.com/trauringetag/synapse-backend/internal/repository"
)

type UserHandler struct {
	users  UserStore
	tokens TokenStore
}

func NewUserHandler(users UserStore, tokens TokenStore) *UserHandler {
	return &UserHandler{users: users, tokens: tokens}
}

type putUserRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role"`
	Status    string `json:"status"`
}

type patchUserRequest struct {
	Email     *string `json:"email"`
	Password  *string `json:"password"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Status    *string `json:"status"`
}

func (h *UserHandler) Me(w http.ResponseWriter, r *http.Request) {
	p, ok := middleware.FromContext(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
		return
	}
	user, err := h.users.GetByID(r.Context(), p.ID)
	if err != nil {
		httputil.Error(w, http.StatusNotFound, messages.UserNotFound, nil)
		return
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := 1
	limit := 10
	validationErrors := make(map[string][]string)
	if pageStr := q.Get("page"); pageStr != "" {
		var err error
		page, err = strconv.Atoi(pageStr)
		if err != nil || page < 1 {
			validationErrors["page"] = []string{messages.InvalidPageValue}
		}
	}
	if limitStr := q.Get("limit"); limitStr != "" {
		var err error
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit < 1 || limit > 100 {
			validationErrors["limit"] = []string{messages.InvalidLimitValue}
		}
	}
	if len(validationErrors) > 0 {
		httputil.Error(w, http.StatusBadRequest, messages.InvalidPageLimitParams, validationErrors)
		return
	}
	role := strings.ToLower(strings.TrimSpace(q.Get("role")))
	if role != "" && role != models.RoleUser && role != models.RoleAdmin {
		httputil.Error(w, http.StatusBadRequest, messages.InvalidParameterValue, map[string][]string{"role": {messages.RoleInvalidValue}})
		return
	}
	status := strings.ToLower(strings.TrimSpace(q.Get("status")))
	if status != "" && status != models.StatusActive && status != models.StatusInactive {
		httputil.Error(w, http.StatusBadRequest, messages.InvalidParameterValue, map[string][]string{"status": {messages.StatusInvalidValue}})
		return
	}
	search := strings.TrimSpace(q.Get("search"))
	if len(search) > 200 {
		httputil.Error(w, http.StatusBadRequest, messages.InvalidParameterValue, nil)
		return
	}
	result, err := h.users.List(r.Context(), repository.UserListFilter{Page: page, Limit: limit, Search: search, Role: role, Status: status})
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToGetUsersList, nil)
		return
	}
	httputil.JSON(w, http.StatusOK, result)
}

func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req putUserRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.DecodeError(w, err)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	first := strings.TrimSpace(req.FirstName)
	last := strings.TrimSpace(req.LastName)
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if email == "" || !strings.Contains(email, "@") || first == "" || last == "" || len(req.Password) < 8 {
		httputil.Error(w, http.StatusBadRequest, messages.CheckRequiredFields, map[string][]string{
			"email":      {messages.InvalidEmail},
			"first_name": {messages.FirstNameRequired},
			"last_name":  {messages.LastNameRequired},
			"password":   {messages.PasswordTooShort}})
		return
	}
	if role == "" {
		role = models.RoleUser
	}
	if role != models.RoleUser && role != models.RoleAdmin {
		httputil.Error(w, http.StatusBadRequest, messages.InvalidParameterValue, map[string][]string{"role": {messages.RoleInvalidValue}})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToHashPassword, nil)
		return
	}
	user, err := h.users.Create(r.Context(), email, string(hash), role, first, last)
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

func (h *UserHandler) PutMe(w http.ResponseWriter, r *http.Request) {
	p, ok := middleware.FromContext(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
		return
	}
	var req struct {
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := httputil.Decode(r, &req); err != nil {
		httputil.DecodeError(w, err)
		return
	}
	email, first, last := strings.ToLower(strings.TrimSpace(req.Email)), strings.TrimSpace(req.FirstName), strings.TrimSpace(req.LastName)
	if email == "" || !strings.Contains(email, "@") || first == "" || last == "" {
		httputil.Error(w, http.StatusBadRequest, messages.CheckRequiredFields, map[string][]string{
			"email":      {messages.InvalidEmail},
			"first_name": {messages.FirstNameRequired},
			"last_name":  {messages.LastNameRequired}})
		return
	}
	user, err := h.users.ReplaceProfile(r.Context(), p.ID, email, first, last)
	if err == repository.ErrConflict {
		httputil.Error(w, http.StatusConflict, messages.EmailAlreadyUsed, nil)
		return
	}
	if err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, messages.UserNotFound, nil)
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToUpdateUser, nil)
		return
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) PatchMe(w http.ResponseWriter, r *http.Request) {
	p, ok := middleware.FromContext(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
		return
	}
	var req struct {
		Email     *string `json:"email"`
		FirstName *string `json:"first_name"`
		LastName  *string `json:"last_name"`
	}
	if err := httputil.Decode(r, &req); err != nil {
		httputil.DecodeError(w, err)
		return
	}
	if req.Email == nil && req.FirstName == nil && req.LastName == nil {
		httputil.Error(w, http.StatusBadRequest, messages.EmptyUpdateData, map[string][]string{"body": {messages.SpecifyAtLeastOneField}})
		return
	}
	var email, first, last *string
	if req.Email != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Email))
		if v == "" || !strings.Contains(v, "@") {
			httputil.Error(w, http.StatusBadRequest, messages.CheckRequiredFields, map[string][]string{"email": {messages.InvalidEmail}})
			return
		}
		email = &v
	}
	if req.FirstName != nil {
		v := strings.TrimSpace(*req.FirstName)
		if v == "" {
			httputil.Error(w, http.StatusBadRequest, messages.CheckRequiredFields, map[string][]string{"first_name": {messages.FirstNameRequired}})
			return
		}
		first = &v
	}
	if req.LastName != nil {
		v := strings.TrimSpace(*req.LastName)
		if v == "" {
			httputil.Error(w, http.StatusBadRequest, messages.CheckRequiredFields, map[string][]string{"last_name": {messages.LastNameRequired}})
			return
		}
		last = &v
	}
	user, err := h.users.Update(r.Context(), p.ID, email, first, last, nil, nil)
	if err == repository.ErrConflict {
		httputil.Error(w, http.StatusConflict, messages.EmailAlreadyUsed, nil)
		return
	}
	if err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, messages.UserNotFound, nil)
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToUpdateUser, nil)
		return
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id, err := repository.UUIDFromString(chi.URLParam(r, "id"))
	if err != nil {
		httputil.Error(w, http.StatusBadRequest, messages.InvalidUserID, nil)
		return
	}
	user, err := h.users.GetByID(r.Context(), id)
	if err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, messages.UserNotFound, nil)
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToGetUser, nil)
		return
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) Put(w http.ResponseWriter, r *http.Request) {
	id, err := repository.UUIDFromString(chi.URLParam(r, "id"))
	if err != nil {
		httputil.Error(w, http.StatusBadRequest, messages.InvalidUserID, nil)
		return
	}
	var req putUserRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.DecodeError(w, err)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	firstName := strings.TrimSpace(req.FirstName)
	lastName := strings.TrimSpace(req.LastName)
	status := strings.ToLower(strings.TrimSpace(req.Status))
	errors := make(map[string][]string)
	if email == "" || !strings.Contains(email, "@") {
		errors["email"] = []string{messages.InvalidEmail}
	}
	if len(req.Password) < 8 {
		errors["password"] = []string{messages.PasswordTooShort}
	}
	if firstName == "" {
		errors["first_name"] = []string{messages.FirstNameRequired}
	}
	if lastName == "" {
		errors["last_name"] = []string{messages.LastNameRequired}
	}
	if status != models.StatusActive && status != models.StatusInactive {
		errors["status"] = []string{messages.StatusInvalidValue}
	}
	if len(errors) > 0 {
		httputil.Error(w, http.StatusBadRequest, messages.CheckRequiredFields, errors)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToHashPassword, nil)
		return
	}
	user, err := h.users.Replace(r.Context(), id, email, firstName, lastName, string(hash), status)
	if err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, messages.UserNotFound, nil)
		return
	}
	if err == repository.ErrConflict {
		httputil.Error(w, http.StatusConflict, messages.EmailAlreadyUsed, nil)
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToUpdateUser, nil)
		return
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) Patch(w http.ResponseWriter, r *http.Request) {
	id, err := repository.UUIDFromString(chi.URLParam(r, "id"))
	if err != nil {
		httputil.Error(w, http.StatusBadRequest, messages.InvalidUserID, nil)
		return
	}
	var req patchUserRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.DecodeError(w, err)
		return
	}
	var email, firstName, lastName, passwordHash, status *string
	if req.Email != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Email))
		if v == "" || !strings.Contains(v, "@") {
			httputil.Error(w, http.StatusBadRequest, messages.CheckRequiredFields, map[string][]string{"email": {messages.InvalidEmail}})
			return
		}
		email = &v
	}
	if req.FirstName != nil {
		v := strings.TrimSpace(*req.FirstName)
		if v == "" {
			httputil.Error(w, http.StatusBadRequest, messages.CheckRequiredFields, map[string][]string{"first_name": {messages.FirstNameRequired}})
			return
		}
		firstName = &v
	}
	if req.LastName != nil {
		v := strings.TrimSpace(*req.LastName)
		if v == "" {
			httputil.Error(w, http.StatusBadRequest, messages.CheckRequiredFields, map[string][]string{"last_name": {messages.LastNameRequired}})
			return
		}
		lastName = &v
	}
	if req.Status != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Status))
		if v != models.StatusActive && v != models.StatusInactive {
			httputil.Error(w, http.StatusBadRequest, messages.InvalidParameterValue, map[string][]string{"status": {messages.StatusInvalidValue}})
			return
		}
		status = &v
	}
	if req.Password != nil {
		if len(*req.Password) < 8 {
			httputil.Error(w, http.StatusBadRequest, messages.CheckRequiredFields, map[string][]string{"password": {messages.PasswordTooShort}})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			httputil.Error(w, http.StatusInternalServerError, messages.FailedToHashPassword, nil)
			return
		}
		s := string(hash)
		passwordHash = &s
	}
	user, err := h.users.Update(r.Context(), id, email, firstName, lastName, passwordHash, status)
	if err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, messages.UserNotFound, nil)
		return
	}
	if err == repository.ErrConflict {
		httputil.Error(w, http.StatusConflict, messages.EmailAlreadyUsed, nil)
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToUpdateUser, nil)
		return
	}
	if passwordHash != nil {
		if revokeErr := h.tokens.RevokeAllForUser(r.Context(), id); revokeErr != nil {
			log.Printf("event=revoke_all_sessions_failed user_id=%s error=%v", id.String(), revokeErr)
		}
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := repository.UUIDFromString(chi.URLParam(r, "id"))
	if err != nil {
		httputil.Error(w, http.StatusBadRequest, messages.InvalidUserID, nil)
		return
	}

	principal, ok := middleware.FromContext(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
		return
	}
	if principal.ID == id {
		httputil.Error(w, http.StatusForbidden, messages.AdminCannotDeleteSelf, nil)
		return
	}

	if err := h.users.Delete(r.Context(), id); err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, messages.UserNotFound, nil)
		return
	} else if err == repository.ErrProtected {
		httputil.Error(w, http.StatusForbidden, messages.CannotDeleteAdminAccount, nil)
		return
	} else if err != nil {
		httputil.Error(w, http.StatusInternalServerError, messages.FailedToDeleteUser, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
