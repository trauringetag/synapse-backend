package handler

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/trauringetag/synapse-backend/internal/httputil"
	"github.com/trauringetag/synapse-backend/internal/middleware"
	"github.com/trauringetag/synapse-backend/internal/models"
	"github.com/trauringetag/synapse-backend/internal/repository"
)

type UserHandler struct {
	users *repository.UserRepository
}

func NewUserHandler(users *repository.UserRepository) *UserHandler {
	return &UserHandler{users: users}
}

type putUserRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role"`
}

type patchUserRequest struct {
	Email     *string `json:"email"`
	Password  *string `json:"password"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Role      *string `json:"role"`
}

func (h *UserHandler) Me(w http.ResponseWriter, r *http.Request) {
	p, ok := middleware.FromContext(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "Несанкционированный доступ")
		return
	}
	user, err := h.users.GetByID(r.Context(), p.ID)
	if err != nil {
		httputil.Error(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	users, err := h.users.List(r.Context())
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось получить список пользователей")
		return
	}
	httputil.JSON(w, http.StatusOK, users)
}

func (h *UserHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id, err := repository.UUIDFromString(chi.URLParam(r, "id"))
	if err != nil {
		httputil.Error(w, http.StatusBadRequest, "Неверный идентификатор пользователя")
		return
	}
	user, err := h.users.GetByID(r.Context(), id)
	if err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось получить пользователя")
		return
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) Put(w http.ResponseWriter, r *http.Request) {
	id, err := repository.UUIDFromString(chi.URLParam(r, "id"))
	if err != nil {
		httputil.Error(w, http.StatusBadRequest, "Неверный идентификатор пользователя")
		return
	}
	var req putUserRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "Некорректное тело JSON")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	firstName := strings.TrimSpace(req.FirstName)
	lastName := strings.TrimSpace(req.LastName)
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if email == "" || !strings.Contains(email, "@") || firstName == "" || lastName == "" || len(req.Password) < 8 {
		httputil.Error(w, http.StatusBadRequest, "Необходимо указать адрес электронной почты, имя, фамилию и пароль (минимум 8 символов)")
		return
	}
	if role != models.RoleUser && role != models.RoleAdmin {
		httputil.Error(w, http.StatusBadRequest, "Роль должна быть user или admin")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось хешировать пароль")
		return
	}
	user, err := h.users.Replace(r.Context(), id, email, firstName, lastName, role, string(hash))
	if err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	if err == repository.ErrConflict {
		httputil.Error(w, http.StatusConflict, "Адрес электронной почты уже используется")
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось обновить пользователя")
		return
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) Patch(w http.ResponseWriter, r *http.Request) {
	id, err := repository.UUIDFromString(chi.URLParam(r, "id"))
	if err != nil {
		httputil.Error(w, http.StatusBadRequest, "Неверный идентификатор пользователя")
		return
	}
	var req patchUserRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "Некорректное тело JSON")
		return
	}
	var email, firstName, lastName, role, passwordHash *string
	if req.Email != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Email))
		if v == "" || !strings.Contains(v, "@") {
			httputil.Error(w, http.StatusBadRequest, "Необходим действительный адрес электронной почты")
			return
		}
		email = &v
	}
	if req.FirstName != nil {
		v := strings.TrimSpace(*req.FirstName)
		if v == "" {
			httputil.Error(w, http.StatusBadRequest, "Имя не может быть пустым")
			return
		}
		firstName = &v
	}
	if req.LastName != nil {
		v := strings.TrimSpace(*req.LastName)
		if v == "" {
			httputil.Error(w, http.StatusBadRequest, "Фамилия не может быть пустой")
			return
		}
		lastName = &v
	}
	if req.Role != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Role))
		if v != models.RoleUser && v != models.RoleAdmin {
			httputil.Error(w, http.StatusBadRequest, "Роль должна быть user или admin.")
			return
		}
		role = &v
	}
	if req.Password != nil {
		if len(*req.Password) < 8 {
			httputil.Error(w, http.StatusBadRequest, "Пароль должен содержать не менее 8 символов")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			httputil.Error(w, http.StatusInternalServerError, "Не удалось хешировать пароль")
			return
		}
		s := string(hash)
		passwordHash = &s
	}
	user, err := h.users.Update(r.Context(), id, email, firstName, lastName, role, passwordHash)
	if err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	if err == repository.ErrConflict {
		httputil.Error(w, http.StatusConflict, "Адрес электронной почты уже используется")
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось обновить пользователя")
		return
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := repository.UUIDFromString(chi.URLParam(r, "id"))
	if err != nil {
		httputil.Error(w, http.StatusBadRequest, "Неверный идентификатор пользователя")
		return
	}
	if err := h.users.Delete(r.Context(), id); err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, "Пользователь не найден")
		return
	} else if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось удалить пользователя")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
