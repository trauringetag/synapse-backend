package handler

// Тонкий HTTP-слой управления пользователями: обработчики только разбирают
// запрос (тело, query, path-параметры, контекст аутентификации), вызывают
// метод use-case и формируют HTTP-ответ. Валидация полей, нормализация,
// хеширование паролей, проверка ролей/статусов и отзыв сессий — в internal/usecase.

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/trauringetag/synapse-backend/internal/delivery/http/response"
	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/middleware"
	"github.com/trauringetag/synapse-backend/internal/messages"
	"github.com/trauringetag/synapse-backend/internal/usecase"
)

type UserHandler struct {
	uc usecase.UserUseCase
}

func NewUserHandler(uc usecase.UserUseCase) *UserHandler {
	return &UserHandler{uc: uc}
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
		response.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
		return
	}
	user, err := h.uc.GetMe(r.Context(), p.ID)
	if err != nil {
		respondError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, user)
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
		response.Error(w, http.StatusBadRequest, messages.InvalidPageLimitParams, validationErrors)
		return
	}
	result, err := h.uc.List(r.Context(), usecase.ListUsersInput{
		Page:   page,
		Limit:  limit,
		Search: strings.TrimSpace(q.Get("search")),
		Role:   strings.TrimSpace(q.Get("role")),
		Status: strings.TrimSpace(q.Get("status")),
	})
	if err != nil {
		respondError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, result)
}

func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req putUserRequest
	if err := response.Decode(r, &req); err != nil {
		response.DecodeError(w, err)
		return
	}
	user, err := h.uc.Create(r.Context(), usecase.CreateUserInput{
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Role:      req.Role,
	})
	if err != nil {
		respondError(w, err)
		return
	}
	response.JSON(w, http.StatusCreated, user)
}

func (h *UserHandler) PutMe(w http.ResponseWriter, r *http.Request) {
	p, ok := middleware.FromContext(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
		return
	}
	var req struct {
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := response.Decode(r, &req); err != nil {
		response.DecodeError(w, err)
		return
	}
	user, err := h.uc.ReplaceProfile(r.Context(), usecase.ReplaceProfileInput{
		UserID:    p.ID,
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		respondError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) PatchMe(w http.ResponseWriter, r *http.Request) {
	p, ok := middleware.FromContext(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
		return
	}
	var req struct {
		Email     *string `json:"email"`
		FirstName *string `json:"first_name"`
		LastName  *string `json:"last_name"`
	}
	if err := response.Decode(r, &req); err != nil {
		response.DecodeError(w, err)
		return
	}
	user, err := h.uc.UpdateOwnProfile(r.Context(), usecase.UpdateOwnProfileInput{
		UserID:    p.ID,
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		respondError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id, err := domain.UUIDFromString(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, messages.InvalidUserID, nil)
		return
	}
	user, err := h.uc.GetByID(r.Context(), id)
	if err != nil {
		respondError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) Put(w http.ResponseWriter, r *http.Request) {
	id, err := domain.UUIDFromString(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, messages.InvalidUserID, nil)
		return
	}
	var req putUserRequest
	if err := response.Decode(r, &req); err != nil {
		response.DecodeError(w, err)
		return
	}
	user, err := h.uc.AdminReplace(r.Context(), usecase.AdminReplaceUserInput{
		ID:        id,
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Status:    req.Status,
	})
	if err != nil {
		respondError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) Patch(w http.ResponseWriter, r *http.Request) {
	id, err := domain.UUIDFromString(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, messages.InvalidUserID, nil)
		return
	}
	var req patchUserRequest
	if err := response.Decode(r, &req); err != nil {
		response.DecodeError(w, err)
		return
	}
	user, err := h.uc.AdminUpdate(r.Context(), usecase.AdminUpdateUserInput{
		ID:        id,
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Status:    req.Status,
	})
	if err != nil {
		respondError(w, err)
		return
	}
	response.JSON(w, http.StatusOK, user)
}

// DeleteMe — самоудаление (физическое удаление, hard delete) текущего пользователя:
// DELETE /api/v1/users/me. Требует валидный access_token и CSRF-пару
// (state-changing запрос защищается middleware.CSRF на уровне роутера).
// Успех — 204 No Content; все refresh-токены пользователя отзываются.
func (h *UserHandler) DeleteMe(w http.ResponseWriter, r *http.Request) {
	p, ok := middleware.FromContext(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
		return
	}
	if err := h.uc.DeleteMe(r.Context(), p.ID); err != nil {
		respondError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := domain.UUIDFromString(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, http.StatusBadRequest, messages.InvalidUserID, nil)
		return
	}
	principal, ok := middleware.FromContext(r.Context())
	if !ok {
		response.Error(w, http.StatusUnauthorized, messages.Unauthorized, nil)
		return
	}
	if err := h.uc.Delete(r.Context(), usecase.DeleteUserInput{
		TargetID:    id,
		PrincipalID: principal.ID,
	}); err != nil {
		respondError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
