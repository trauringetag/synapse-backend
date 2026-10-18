package handler

import (
	"net/http"
	"strconv"
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
	Status    string `json:"status"`
}

type patchUserRequest struct {
	Email     *string `json:"email"`
	Password  *string `json:"password"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Role      *string `json:"role"`
	Status    *string `json:"status"`
}

func (h *UserHandler) Me(w http.ResponseWriter, r *http.Request) {
	p, ok := middleware.FromContext(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "Не авторизован")
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
	q := r.URL.Query()
	page, errPage := strconv.Atoi(q.Get("page"))
	if q.Get("page") == "" {
		page = 1
	}
	limit, errLimit := strconv.Atoi(q.Get("limit"))
	if q.Get("limit") == "" {
		limit = 10
	}
	if errPage != nil || errLimit != nil || page < 1 || limit < 1 || limit > 100 {
		httputil.ValidationError(w, http.StatusBadRequest, "Параметры page и limit должны быть положительными числами; limit не более 100", map[string][]string{"page": {"Должно быть положительным числом"}, "limit": {"Должно быть от 1 до 100"}})
		return
	}
	role := strings.ToLower(strings.TrimSpace(q.Get("role")))
	if role != "" && role != models.RoleUser && role != models.RoleAdmin {
		httputil.ValidationError(w, http.StatusBadRequest, "Недопустимая роль", map[string][]string{"role": {"Допустимые значения: user, admin"}})
		return
	}
	status := strings.ToLower(strings.TrimSpace(q.Get("status")))
	if status != "" && status != models.StatusActive && status != models.StatusInactive {
		httputil.ValidationError(w, http.StatusBadRequest, "Недопустимый статус", map[string][]string{"status": {"Допустимые значения: active, inactive"}})
		return
	}
	result, err := h.users.List(r.Context(), repository.UserListFilter{Page: page, Limit: limit, Search: strings.TrimSpace(q.Get("search")), Role: role, Status: status})
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось получить список пользователей")
		return
	}
	httputil.JSON(w, http.StatusOK, result)
}

func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req putUserRequest
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "Некорректное тело JSON")
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	first := strings.TrimSpace(req.FirstName)
	last := strings.TrimSpace(req.LastName)
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if email == "" || !strings.Contains(email, "@") || first == "" || last == "" || len(req.Password) < 8 {
		httputil.ValidationError(w, http.StatusBadRequest, "Проверьте обязательные поля пользователя", map[string][]string{"email": {"Укажите действительный email"}, "first_name": {"Имя обязательно"}, "last_name": {"Фамилия обязательна"}, "password": {"Пароль должен содержать не менее 8 символов"}})
		return
	}
	if role == "" {
		role = models.RoleUser
	}
	if role != models.RoleUser && role != models.RoleAdmin {
		httputil.ValidationError(w, http.StatusBadRequest, "Недопустимая роль", map[string][]string{"role": {"Допустимые значения: user, admin"}})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось хешировать пароль")
		return
	}
	user, err := h.users.Create(r.Context(), email, string(hash), role, first, last)
	if err == repository.ErrConflict {
		httputil.Error(w, http.StatusConflict, "Адрес электронной почты уже используется")
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось создать пользователя")
		return
	}
	httputil.JSON(w, http.StatusCreated, user)
}

func (h *UserHandler) PutMe(w http.ResponseWriter, r *http.Request) {
	p, ok := middleware.FromContext(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "Не авторизован")
		return
	}
	var req struct {
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "Некорректное тело JSON")
		return
	}
	email, first, last := strings.ToLower(strings.TrimSpace(req.Email)), strings.TrimSpace(req.FirstName), strings.TrimSpace(req.LastName)
	if email == "" || !strings.Contains(email, "@") || first == "" || last == "" {
		httputil.ValidationError(w, http.StatusBadRequest, "Email, имя и фамилия обязательны", map[string][]string{"email": {"Укажите действительный email"}, "first_name": {"Имя обязательно"}, "last_name": {"Фамилия обязательна"}})
		return
	}
	user, err := h.users.ReplaceProfile(r.Context(), p.ID, email, first, last)
	if err == repository.ErrConflict {
		httputil.Error(w, http.StatusConflict, "Адрес электронной почты уже используется")
		return
	}
	if err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось обновить профиль")
		return
	}
	httputil.JSON(w, http.StatusOK, user)
}

func (h *UserHandler) PatchMe(w http.ResponseWriter, r *http.Request) {
	p, ok := middleware.FromContext(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "Не авторизован")
		return
	}
	var req struct {
		Email     *string `json:"email"`
		FirstName *string `json:"first_name"`
		LastName  *string `json:"last_name"`
	}
	if err := httputil.Decode(r, &req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "Некорректное тело JSON")
		return
	}
	if req.Email == nil && req.FirstName == nil && req.LastName == nil {
		httputil.ValidationError(w, http.StatusBadRequest, "Не переданы поля для обновления", map[string][]string{"body": {"Укажите хотя бы одно поле"}})
		return
	}
	var email, first, last *string
	if req.Email != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Email))
		if v == "" || !strings.Contains(v, "@") {
			httputil.ValidationError(w, http.StatusBadRequest, "Недопустимый email", map[string][]string{"email": {"Укажите действительный email"}})
			return
		}
		email = &v
	}
	if req.FirstName != nil {
		v := strings.TrimSpace(*req.FirstName)
		if v == "" {
			httputil.ValidationError(w, http.StatusBadRequest, "Имя не может быть пустым", map[string][]string{"first_name": {"Имя не может быть пустым"}})
			return
		}
		first = &v
	}
	if req.LastName != nil {
		v := strings.TrimSpace(*req.LastName)
		if v == "" {
			httputil.ValidationError(w, http.StatusBadRequest, "Фамилия не может быть пустой", map[string][]string{"last_name": {"Фамилия не может быть пустой"}})
			return
		}
		last = &v
	}
	user, err := h.users.Update(r.Context(), p.ID, email, first, last, nil, nil, nil)
	if err == repository.ErrConflict {
		httputil.Error(w, http.StatusConflict, "Адрес электронной почты уже используется")
		return
	}
	if err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, "Пользователь не найден")
		return
	}
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось обновить профиль")
		return
	}
	httputil.JSON(w, http.StatusOK, user)
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
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if email == "" || !strings.Contains(email, "@") || firstName == "" || lastName == "" || len(req.Password) < 8 {
		httputil.Error(w, http.StatusBadRequest, "Необходимо указать адрес электронной почты, имя, фамилию и пароль (минимум 8 символов)")
		return
	}
	if role != models.RoleUser && role != models.RoleAdmin {
		httputil.Error(w, http.StatusBadRequest, "Роль должна быть user или admin")
		return
	}
	if status != models.StatusActive && status != models.StatusInactive {
		httputil.Error(w, http.StatusBadRequest, "Статус должен быть active или inactive")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось хешировать пароль")
		return
	}
	user, err := h.users.Replace(r.Context(), id, email, firstName, lastName, role, string(hash), status)
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
	var email, firstName, lastName, role, passwordHash, status *string
	if req.Email != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Email))
		if v == "" || !strings.Contains(v, "@") {
			httputil.Error(w, http.StatusBadRequest, "Указан некорректный адрес электронной почты")
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
	if req.Status != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Status))
		if v != models.StatusActive && v != models.StatusInactive {
			httputil.ValidationError(w, http.StatusBadRequest, "Недопустимый статус", map[string][]string{"status": {"Допустимые значения: active, inactive"}})
			return
		}
		status = &v
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
	user, err := h.users.Update(r.Context(), id, email, firstName, lastName, role, passwordHash, status)
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

	principal, ok := middleware.FromContext(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "Не авторизован")
		return
	}
	if principal.ID == id {
		httputil.Error(w, http.StatusForbidden, "Администратор не может удалить собственную учетную запись")
		return
	}

	if err := h.users.Delete(r.Context(), id); err == repository.ErrNotFound {
		httputil.Error(w, http.StatusNotFound, "Пользователь не найден")
		return
	} else if err == repository.ErrProtected {
		httputil.Error(w, http.StatusForbidden, "Нельзя удалить учетную запись администратора")
		return
	} else if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "Не удалось удалить пользователя")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
