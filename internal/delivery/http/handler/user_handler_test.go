package handler

// Полное покрытие unit-тестами модуля управления пользователями: профиль /users/me,
// админские CRUD-операции, пагинация/фильтры/поиск, сброс сессий при смене пароля
// и атаки (вертикальная эскалация прав, IDOR, mass assignment, самоудаление админа).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/domain/models"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/middleware"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/security"
	"github.com/trauringetag/synapse-backend/internal/messages"
)

// nilCtx — контекст по умолчанию для вызовов хранилища в тестах.
func nilCtx() context.Context { return context.Background() }

// newUserHandler собирает хендлер пользователей на свежем моке.
func newUserHandler() (*UserHandler, *mockStore) {
	store := newMockStore()
	return NewUserHandler(newUserUC(store)), store
}

// asPrincipal превращает пользователя в Principal из middleware.
func asPrincipal(u *models.User) *middleware.Principal {
	return &middleware.Principal{ID: u.ID, Email: u.Email, Role: u.Role}
}

// withUser кладет Principal в контекст запроса (эмуляция пройденного Authenticate).
func withUser(req *http.Request, p *middleware.Principal) *http.Request {
	return req.WithContext(middleware.ContextWithUser(req.Context(), p))
}

// withChiID добавляет URL-параметр {id} маршрута chi.
func withChiID(req *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// expectedInvalidPaginationParams динамически вычисляет по query-строке, какие
// параметры нарушают контракт API и потому обязаны присутствовать в details:
//   - page:  целое >= 1 (если параметр не передан — валиден, значение по умолчанию 1);
//   - limit: целое в диапазоне [1, 100] (не передан — валиден, по умолчанию 10).
//
// Тест опирается на контракт, а не на реализацию хендлера, поэтому переживет
// любые внутренние рефакторинги List.
func expectedInvalidPaginationParams(t *testing.T, rawQuery string) []string {
	t.Helper()
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatalf("Не удалось разобрать query %q: %v", rawQuery, err)
	}
	var want []string
	if v := q.Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err != nil || n < 1 {
			want = append(want, "page")
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 100 {
			want = append(want, "limit")
		}
	}
	return want
}

// assertDetailsExact проверяет, что details содержит РОВНО указанный набор ключей:
// все ожидаемые присутствуют и нет лишних. Это важно после доработки хендлера
// («выводится только по переданным невалидным полям»): лишние ключи — тоже ошибка.
// Вызов без полей означает «details должен быть пустым/отсутствовать».
func assertDetailsExact(t *testing.T, rec *httptest.ResponseRecorder, fields ...string) {
	t.Helper()
	var body struct {
		Details map[string][]string `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Не удалось декодировать ответ: %v; body = %s", err, rec.Body.String())
	}
	wantSet := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		wantSet[f] = struct{}{}
		if _, ok := body.Details[f]; !ok {
			t.Errorf("В details отсутствует ключ %q; body = %s", f, rec.Body.String())
		}
	}
	for fact := range body.Details {
		if _, ok := wantSet[fact]; !ok {
			t.Errorf("Лишний ключ %q в details; body = %s", fact, rec.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------
// /users/me — ПРОФИЛЬ ТЕКУЩЕГО ПОЛЬЗОВАТЕЛЯ
// ---------------------------------------------------------------------------

// TestMe_Success и TestMe_Unauthenticated: профиль доступен только аутентифицированным.
func TestMe(t *testing.T) {
	t.Run("Успех: пользователь видит собственный профиль без хеша пароля", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "me@example.com", "StrongPass123", models.RoleUser)

		req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil), asPrincipal(u))
		rec := httptest.NewRecorder()
		h.Me(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
		}
		var got models.User
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if got.ID != u.ID || got.Email != u.Email {
			t.Errorf("Получен чужой профиль: %+v", got)
		}
		if strings.Contains(rec.Body.String(), "password") {
			t.Error("Хеш пароля не должен присутствовать в ответе")
		}
	})

	t.Run("Без Principal в контексте -> 401", func(t *testing.T) {
		h, _ := newUserHandler()
		rec := httptest.NewRecorder()
		h.Me(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Статус = %d, ожидается: 401", rec.Code)
		}
	})

	t.Run("Пользователь удален из БД, но токен живой -> 404", func(t *testing.T) {
		h, _ := newUserHandler()
		ghost := &middleware.Principal{ID: uuid.New(), Email: "ghost@example.com", Role: models.RoleUser}
		req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil), ghost)
		rec := httptest.NewRecorder()
		h.Me(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("Статус = %d, ожидается: 404", rec.Code)
		}
	})
}

// TestPutMe — полная замена собственного профиля (PUT /users/me).
func TestPutMe(t *testing.T) {
	t.Run("Успешная замена email, имени и фамилии", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "old@example.com", "StrongPass123", models.RoleUser)

		body := map[string]string{"email": "new@example.com", "first_name": "New", "last_name": "Name"}
		req := withUser(postJSON("/api/v1/users/me", body), asPrincipal(u))
		rec := httptest.NewRecorder()
		h.PutMe(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
		}
		got, _ := store.GetByID(nilCtx(), u.ID)
		if got.Email != "new@example.com" || got.FirstName != "New" || got.LastName != "Name" {
			t.Errorf("Профиль не обновлен: %+v", got)
		}
	})

	t.Run("Валидация: битый email и пустые имена -> 400 с details", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "me@example.com", "StrongPass123", models.RoleUser)

		cases := []struct {
			field string
			body  map[string]string
		}{
			{field: "email", body: map[string]string{"email": "no-at", "first_name": "A", "last_name": "B"}},
			{field: "first_name", body: map[string]string{"email": "x@y.z", "first_name": "", "last_name": "B"}},
			{field: "last_name", body: map[string]string{"email": "x@y.z", "first_name": "A", "last_name": ""}},
		}
		for _, c := range cases {
			req := withUser(postJSON("/api/v1/users/me", c.body), asPrincipal(u))
			rec := httptest.NewRecorder()
			h.PutMe(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("Статус = %d, ожидается: 400; body = %s", rec.Code, rec.Body.String())
			}
			assertDetail(t, rec, c.field)
		}
	})

	t.Run("Конфликт: чужой занятый email -> 409", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "me@example.com", "StrongPass123", models.RoleUser)
		seedUser(t, store, "taken@example.com", "StrongPass123", models.RoleUser)

		body := map[string]string{"email": "taken@example.com", "first_name": "A", "last_name": "B"}
		req := withUser(postJSON("/api/v1/users/me", body), asPrincipal(u))
		rec := httptest.NewRecorder()
		h.PutMe(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("Статус = %d, ожидается: 409", rec.Code)
		}
	})

	// Атака (mass assignment / privilege escalation): пользователь пытается
	// повысить себе роль или деактивировать себя через /users/me.
	t.Run("Атака: поля role и status отклоняются на уровне декодирования", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "me@example.com", "StrongPass123", models.RoleUser)

		for _, extra := range []string{`"role":"admin"`, `"status":"inactive"`} {
			raw := `{"email":"me@example.com","first_name":"A","last_name":"B",` + extra + `}`
			req := httptest.NewRequest(http.MethodPut, "/api/v1/users/me", strings.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			req = withUser(req, asPrincipal(u))
			rec := httptest.NewRecorder()
			h.PutMe(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("Статус = %d, ожидается: 400 для поля %s", rec.Code, extra)
			}
			got, _ := store.GetByID(nilCtx(), u.ID)
			if got.Role != models.RoleUser || got.Status != models.StatusActive {
				t.Errorf("Роль/статус изменились: %+v", got)
			}
		}
	})
}

// TestPatchMe — частичное обновление собственного профиля (PATCH /users/me).
func TestPatchMe(t *testing.T) {
	t.Run("Успех: обновление только имени", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "me@example.com", "StrongPass123", models.RoleUser)

		req := withUser(postJSON("/api/v1/users/me", map[string]string{"first_name": "Only"}), asPrincipal(u))
		rec := httptest.NewRecorder()
		h.PatchMe(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
		}
		got, _ := store.GetByID(nilCtx(), u.ID)
		if got.FirstName != "Only" || got.Email != u.Email {
			t.Errorf("Частичное обновление затронуло лишние поля: %+v", got)
		}
	})

	t.Run("Пустое тело -> 400 с подсказкой", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "me@example.com", "StrongPass123", models.RoleUser)

		req := withUser(postJSON("/api/v1/users/me", map[string]string{}), asPrincipal(u))
		rec := httptest.NewRecorder()
		h.PatchMe(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Статус = %d, ожидается: 400", rec.Code)
		}
		assertMessage(t, rec, messages.EmptyUpdateData)
	})

	t.Run("Невалидный email в PATCH -> 400", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "me@example.com", "StrongPass123", models.RoleUser)

		req := withUser(postJSON("/api/v1/users/me", map[string]string{"email": "bad"}), asPrincipal(u))
		rec := httptest.NewRecorder()
		h.PatchMe(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Статус = %d, ожидается: 400", rec.Code)
		}
		assertDetail(t, rec, "email")
	})

	t.Run("Конфликт email -> 409", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "me@example.com", "StrongPass123", models.RoleUser)
		seedUser(t, store, "taken@example.com", "StrongPass123", models.RoleUser)

		req := withUser(postJSON("/api/v1/users/me", map[string]string{"email": "taken@example.com"}), asPrincipal(u))
		rec := httptest.NewRecorder()
		h.PatchMe(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("Статус = %d, ожидается: 409", rec.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// АДМИНСКИЙ БЛОК: LIST / CREATE / GET / PUT / PATCH / DELETE
// ---------------------------------------------------------------------------

// TestList — пагинация, фильтры role/status, поиск и валидация параметров.
func TestList(t *testing.T) {
	// seedList наполняет хранилище детерминированным набором пользователей.
	seedList := func(store *mockStore, n int) {
		for i := 0; i < n; i++ {
			role := models.RoleUser
			if i%5 == 0 {
				role = models.RoleAdmin
			}
			seedUser(t, store, "user"+string(rune('a'+i))+"@example.com", "StrongPass123", role)
		}
	}

	t.Run("Успех: значения по умолчанию page = 1, limit = 10", func(t *testing.T) {
		h, store := newUserHandler()
		seedList(store, 12)

		rec := httptest.NewRecorder()
		h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200", rec.Code)
		}
		var res domain.UserListResult
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if len(res.Items) != 10 || res.Total != 12 || res.Page != 1 {
			t.Errorf("Пагинация по умолчанию: items = %d, total = %d, page = %d", len(res.Items), res.Total, res.Page)
		}
	})

	t.Run("Пагинация: вторая и третья страницы", func(t *testing.T) {
		h, store := newUserHandler()
		seedList(store, 25)

		rec := httptest.NewRecorder()
		h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users?page=2&limit=10", nil))
		var res domain.UserListResult
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if len(res.Items) != 10 || res.TotalPages != 3 {
			t.Errorf("Страница 2: items = %d, totalPages = %d", len(res.Items), res.TotalPages)
		}

		rec = httptest.NewRecorder()
		h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users?page=3&limit=10", nil))
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if len(res.Items) != 5 {
			t.Errorf("Страница 3: items = %d, ожидается: 5", len(res.Items))
		}
	})

	t.Run("Невалидные параметры пагинации -> 400 с details только по невалидным полям", func(t *testing.T) {
		h, _ := newUserHandler()

		// Набор query-вариантов: невалиден только page, только limit и оба сразу.
		queries := []string{
			"?page=0",         // невалиден только page
			"?page=-2",        // невалиден только page (отрицательный)
			"?page=abc",       // невалиден только page (не число)
			"?limit=0",        // невалиден только limit
			"?limit=101",      // невалиден только limit (выше верхней границы)
			"?limit=xyz",      // невалиден только limit (не число)
			"?page=0&limit=0", // невалидны оба
			"?page=abc&limit=xyz",
			"?page=2&limit=101", // page валиден, limit невалиден
			"?page=-1&limit=50", // page невалиден, limit валиден
		}

		for _, q := range queries {
			t.Run(q, func(t *testing.T) {
				rec := httptest.NewRecorder()
				h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users"+q, nil))

				if rec.Code != http.StatusBadRequest {
					t.Fatalf("Query %q: статус = %d, ожидается: 400; body = %s", q, rec.Code, rec.Body.String())
				}

				// Ожидаемый набор ключей выводится динамически из самой query-строки.
				want := expectedInvalidPaginationParams(t, strings.TrimPrefix(q, "?"))
				if len(want) == 0 {
					t.Fatalf("Query %q по построению должна быть невалидной", q)
				}
				// Проверяем точное совпадение множества ключей: ни пропусков, ни лишних.
				assertDetailsExact(t, rec, want...)
			})
		}
	})

	t.Run("Валидные параметры пагинации -> 200 и пустой details", func(t *testing.T) {
		h, _ := newUserHandler()
		for _, q := range []string{"", "?page=1", "?limit=100", "?page=2&limit=1", "?page=1&limit=100"} {
			rec := httptest.NewRecorder()
			h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users"+q, nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("Query %q: статус = %d, ожидается: 200; body = %s", q, rec.Code, rec.Body.String())
			}
			// При успехе details не должен содержать ни одного ключа.
			assertDetailsExact(t, rec)
		}
	})

	t.Run("Фильтр role: валидный и невалидный", func(t *testing.T) {
		h, store := newUserHandler()
		seedList(store, 10)

		rec := httptest.NewRecorder()
		h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users?role=admin&limit=100", nil))
		var res domain.UserListResult
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		for _, it := range res.Items {
			if it.Role != models.RoleAdmin {
				t.Errorf("Фильтр role сломан: %+v", it)
			}
		}
		if res.Total == 0 {
			t.Error("Фильтр role = admin не нашел ни одного администратора")
		}

		rec = httptest.NewRecorder()
		h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users?role=superadmin", nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Статус = %d, ожидается: 400 для role = superadmin", rec.Code)
		}
		assertDetail(t, rec, "role")
	})

	t.Run("Фильтр status: валидный и невалидный", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "active@example.com", "StrongPass123", models.RoleUser)
		blocked := seedUser(t, store, "blocked@example.com", "StrongPass123", models.RoleUser)
		blocked.Status = models.StatusInactive

		rec := httptest.NewRecorder()
		h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users?status=inactive", nil))
		var res domain.UserListResult
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if res.Total != 1 || res.Items[0].Email != "blocked@example.com" {
			t.Errorf("Фильтр status = inactive: %+v", res.Items)
		}

		rec = httptest.NewRecorder()
		h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users?status=banned", nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Статус = %d, ожидается: 400 для status = banned", rec.Code)
		}
		assertDetail(t, rec, "status")
		_ = u
	})

	t.Run("Поиск по подстроке и ограничение длины поиска", func(t *testing.T) {
		h, store := newUserHandler()
		seedUser(t, store, "findme@example.com", "StrongPass123", models.RoleUser)
		seedUser(t, store, "other@example.com", "StrongPass123", models.RoleUser)

		rec := httptest.NewRecorder()
		h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users?search=findme", nil))
		var res domain.UserListResult
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if res.Total != 1 || res.Items[0].Email != "findme@example.com" {
			t.Errorf("Поиск: %+v", res.Items)
		}

		rec = httptest.NewRecorder()
		h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users?search="+strings.Repeat("x", 201), nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Статус = %d, ожидается: 400 для search длиннее 200", rec.Code)
		}
	})
}

// TestCreate — создание пользователей администратором (POST /users).
func TestCreate(t *testing.T) {
	t.Run("Успех: создание обычного пользователя и администратора", func(t *testing.T) {
		h, store := newUserHandler()

		rec := httptest.NewRecorder()
		h.Create(rec, postJSON("/api/v1/users", map[string]string{
			"email": "new@example.com", "password": "StrongPass123",
			"first_name": "N", "last_name": "U",
		}))
		if rec.Code != http.StatusCreated {
			t.Fatalf("Статус = %d, ожидается: 201; body = %s", rec.Code, rec.Body.String())
		}
		var u models.User
		_ = json.Unmarshal(rec.Body.Bytes(), &u)
		if u.Role != models.RoleUser {
			t.Errorf("Роль по умолчанию = %q, ожидается: user", u.Role)
		}

		rec = httptest.NewRecorder()
		h.Create(rec, postJSON("/api/v1/users", map[string]string{
			"email": "boss@example.com", "password": "StrongPass123",
			"first_name": "B", "last_name": "S", "role": "admin",
		}))
		if rec.Code != http.StatusCreated {
			t.Fatalf("Статус = %d, ожидается: 201; body = %s", rec.Code, rec.Body.String())
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &u)
		if u.Role != models.RoleAdmin {
			t.Errorf("Явная роль admin не применена: %q", u.Role)
		}
		_ = store
	})

	t.Run("Валидация обязательных полей -> 400 с полным набором details", func(t *testing.T) {
		h, _ := newUserHandler()
		rec := httptest.NewRecorder()
		h.Create(rec, postJSON("/api/v1/users", map[string]string{"email": "x@y.z"}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Статус = %d, ожидается: 400", rec.Code)
		}
		for _, f := range []string{"email", "first_name", "last_name", "password"} {
			assertDetail(t, rec, f)
		}
	})

	t.Run("Недопустимая роль -> 400", func(t *testing.T) {
		h, _ := newUserHandler()
		rec := httptest.NewRecorder()
		h.Create(rec, postJSON("/api/v1/users", map[string]string{
			"email": "x@y.z", "password": "StrongPass123",
			"first_name": "A", "last_name": "B", "role": "root",
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Статус = %d, ожидается: 400", rec.Code)
		}
		assertDetail(t, rec, "role")
	})

	t.Run("Дубликат email -> 409", func(t *testing.T) {
		h, store := newUserHandler()
		seedUser(t, store, "dup@example.com", "StrongPass123", models.RoleUser)

		rec := httptest.NewRecorder()
		h.Create(rec, postJSON("/api/v1/users", map[string]string{
			"email": "dup@example.com", "password": "StrongPass123",
			"first_name": "A", "last_name": "B",
		}))
		if rec.Code != http.StatusConflict {
			t.Fatalf("Статус = %d, ожидается: 409", rec.Code)
		}
		assertMessage(t, rec, messages.EmailAlreadyUsed)
	})
}

// TestGetByID — чтение пользователя по идентификатору.
func TestGetByID(t *testing.T) {
	t.Run("Успех", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "one@example.com", "StrongPass123", models.RoleUser)

		req := withChiID(httptest.NewRequest(http.MethodGet, "/api/v1/users/"+u.ID.String(), nil), u.ID.String())
		rec := httptest.NewRecorder()
		h.GetByID(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200", rec.Code)
		}
	})

	t.Run("Невалидный UUID -> 400", func(t *testing.T) {
		h, _ := newUserHandler()
		req := withChiID(httptest.NewRequest(http.MethodGet, "/api/v1/users/not-a-uuid", nil), "not-a-uuid")
		rec := httptest.NewRecorder()
		h.GetByID(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Статус = %d, ожидается: 400", rec.Code)
		}
		assertMessage(t, rec, messages.InvalidUserID)
	})

	t.Run("Пользователь не найден -> 404", func(t *testing.T) {
		h, _ := newUserHandler()
		id := uuid.New().String()
		req := withChiID(httptest.NewRequest(http.MethodGet, "/api/v1/users/"+id, nil), id)
		rec := httptest.NewRecorder()
		h.GetByID(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("Статус = %d, ожидается: 404", rec.Code)
		}
		assertMessage(t, rec, messages.UserNotFound)
	})
}

// TestPut — полная замена карточки пользователя администратором (PUT /users/{id}).
func TestPut(t *testing.T) {
	fullBody := func() map[string]string {
		return map[string]string{
			"email": "put@example.com", "password": "StrongPass123",
			"first_name": "P", "last_name": "U", "status": "active",
		}
	}

	t.Run("Успешная полная замена, включая статус", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "old@example.com", "StrongPass123", models.RoleUser)

		body := fullBody()
		body["status"] = "inactive"
		req := withChiID(postJSON("/api/v1/users/"+u.ID.String(), body), u.ID.String())
		rec := httptest.NewRecorder()
		h.Put(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
		}
		got, _ := store.GetByID(nilCtx(), u.ID)
		if got.Email != "put@example.com" || got.Status != models.StatusInactive {
			t.Errorf("Замена не применена: %+v", got)
		}
	})

	t.Run("Status обязателен: отсутствие -> 400", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "old@example.com", "StrongPass123", models.RoleUser)
		body := fullBody()
		delete(body, "status")

		req := withChiID(postJSON("/api/v1/users/"+u.ID.String(), body), u.ID.String())
		rec := httptest.NewRecorder()
		h.Put(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Статус = %d, ожидается: 400", rec.Code)
		}
		assertDetail(t, rec, "status")
	})

	t.Run("Набор ошибок валидации -> 400", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "old@example.com", "StrongPass123", models.RoleUser)

		cases := []struct {
			field  string
			mutate func(map[string]string)
		}{
			{field: "email", mutate: func(b map[string]string) { b["email"] = "" }},
			{field: "password", mutate: func(b map[string]string) { b["password"] = "short" }},
			{field: "first_name", mutate: func(b map[string]string) { b["first_name"] = "  " }},
			{field: "last_name", mutate: func(b map[string]string) { b["last_name"] = "" }},
			{field: "status", mutate: func(b map[string]string) { b["status"] = "deleted" }},
		}
		for _, c := range cases {
			body := fullBody()
			c.mutate(body)
			req := withChiID(postJSON("/api/v1/users/"+u.ID.String(), body), u.ID.String())
			rec := httptest.NewRecorder()
			h.Put(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("Поле %s: статус = %d, ожидается: 400", c.field, rec.Code)
			}
			assertDetail(t, rec, c.field)
		}
	})

	t.Run("Атака: поле role в PUT игнорируется (роль через PUT не меняется)", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "old@example.com", "StrongPass123", models.RoleUser)

		raw := `{"email":"put@example.com","password":"StrongPass123","first_name":"P",` +
			`"last_name":"U","status":"active","role":"admin"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/users/"+u.ID.String(), strings.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req = withChiID(req, u.ID.String())
		rec := httptest.NewRecorder()
		h.Put(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
		}
		got, _ := store.GetByID(nilCtx(), u.ID)
		if got.Role != models.RoleUser {
			t.Errorf("Роль изменилась через PUT: %q", got.Role)
		}
	})

	t.Run("Несуществующий пользователь -> 404, конфликт email -> 409", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "one@example.com", "StrongPass123", models.RoleUser)
		seedUser(t, store, "taken@example.com", "StrongPass123", models.RoleUser)

		missing := uuid.New().String()
		req := withChiID(postJSON("/api/v1/users/"+missing, fullBody()), missing)
		rec := httptest.NewRecorder()
		h.Put(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("404: статус = %d", rec.Code)
		}

		body := fullBody()
		body["email"] = "taken@example.com"
		req = withChiID(postJSON("/api/v1/users/"+u.ID.String(), body), u.ID.String())
		rec = httptest.NewRecorder()
		h.Put(rec, req)
		if rec.Code != http.StatusConflict {
			t.Errorf("409: статус = %d", rec.Code)
		}
	})
}

// TestPatch — частичное обновление администратором (PATCH /users/{id}).
func TestPatch(t *testing.T) {
	t.Run("Успех: точечная смена статуса", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "p@example.com", "StrongPass123", models.RoleUser)

		req := withChiID(postJSON("/api/v1/users/"+u.ID.String(), map[string]string{"status": "inactive"}), u.ID.String())
		rec := httptest.NewRecorder()
		h.Patch(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
		}
		got, _ := store.GetByID(nilCtx(), u.ID)
		if got.Status != models.StatusInactive {
			t.Errorf("Статус не обновлен: %+v", got)
		}
	})

	t.Run("Смена пароля отзывает ВСЕ сессии пользователя", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "p@example.com", "OldPass12345", models.RoleUser)

		// Имитируем две активные сессии (два refresh-токена в хранилище).
		for i := 0; i < 2; i++ {
			_ = store.Store(nilCtx(), u.ID, auth.HashToken("session-token-"+string(rune('a'+i))), time.Now().Add(time.Hour))
		}

		req := withChiID(postJSON("/api/v1/users/"+u.ID.String(), map[string]string{"password": "BrandNewPass1"}), u.ID.String())
		rec := httptest.NewRecorder()
		h.Patch(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
		}
		// Все сессии погашены (требование версии 1.0.17).
		store.mu.Lock()
		for _, tk := range store.tokens {
			if tk.UserID == u.ID && !tk.Revoked {
				t.Errorf("Сессия не отозвана после смены пароля: %s", tk.TokenHash[:8])
			}
		}
		store.mu.Unlock()
		// Новый пароль действительно работает (хеш пересоздан).
		got, _ := store.GetByID(nilCtx(), u.ID)
		if err := bcrypt.CompareHashAndPassword([]byte(got.PasswordHash), []byte("BrandNewPass1")); err != nil {
			t.Errorf("Хеш нового пароля некорректен: %v", err)
		}
	})

	t.Run("Валидация: невалидные status и password -> 400", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "p@example.com", "StrongPass123", models.RoleUser)

		req := withChiID(postJSON("/api/v1/users/"+u.ID.String(), map[string]string{"status": "banned"}), u.ID.String())
		rec := httptest.NewRecorder()
		h.Patch(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Status: статус = %d, ожидается: 400", rec.Code)
		}
		assertDetail(t, rec, "status")

		req = withChiID(postJSON("/api/v1/users/"+u.ID.String(), map[string]string{"password": "short"}), u.ID.String())
		rec = httptest.NewRecorder()
		h.Patch(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Password: статус = %d, ожидается: 400", rec.Code)
		}
		assertDetail(t, rec, "password")
	})

	t.Run("Атака: смена роли через PATCH отклоняется (Unknown field)", func(t *testing.T) {
		h, store := newUserHandler()
		u := seedUser(t, store, "p@example.com", "StrongPass123", models.RoleUser)

		req := withChiID(postJSON("/api/v1/users/"+u.ID.String(), map[string]string{"role": "admin"}), u.ID.String())
		rec := httptest.NewRecorder()
		h.Patch(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("Статус = %d, ожидается: 400", rec.Code)
		}
		got, _ := store.GetByID(nilCtx(), u.ID)
		if got.Role != models.RoleUser {
			t.Errorf("Роль изменилась через PATCH: %q", got.Role)
		}
	})

	t.Run("Несуществующий пользователь -> 404", func(t *testing.T) {
		h, _ := newUserHandler()
		missing := uuid.New().String()
		req := withChiID(postJSON("/api/v1/users/"+missing, map[string]string{"status": "active"}), missing)
		rec := httptest.NewRecorder()
		h.Patch(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("Статус = %d, ожидается: 404", rec.Code)
		}
	})
}

// TestDelete — удаление пользователей администратором (DELETE /users/{id}).
func TestDelete(t *testing.T) {
	t.Run("Успех: удаление обычного пользователя -> 204", func(t *testing.T) {
		h, store := newUserHandler()
		admin := seedUser(t, store, "admin@example.com", "StrongPass123", models.RoleAdmin)
		victim := seedUser(t, store, "victim@example.com", "StrongPass123", models.RoleUser)

		req := withUser(withChiID(httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+victim.ID.String(), nil), victim.ID.String()), asPrincipal(admin))
		rec := httptest.NewRecorder()
		h.Delete(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("Статус = %d, ожидается: 204; body = %s", rec.Code, rec.Body.String())
		}
		if _, err := store.GetByID(nilCtx(), victim.ID); err == nil {
			t.Error("Пользователь должен быть удален из хранилища")
		}
	})

	t.Run("Атака/защита: администратор не может удалить сам себя -> 403", func(t *testing.T) {
		h, store := newUserHandler()
		admin := seedUser(t, store, "admin@example.com", "StrongPass123", models.RoleAdmin)

		req := withUser(withChiID(httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+admin.ID.String(), nil), admin.ID.String()), asPrincipal(admin))
		rec := httptest.NewRecorder()
		h.Delete(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("Статус = %d, ожидается: 403", rec.Code)
		}
		assertMessage(t, rec, messages.AdminCannotDeleteSelf)
	})

	t.Run("Защита: учетную запись администратора удалить нельзя -> 403", func(t *testing.T) {
		h, store := newUserHandler()
		admin1 := seedUser(t, store, "admin1@example.com", "StrongPass123", models.RoleAdmin)
		admin2 := seedUser(t, store, "admin2@example.com", "StrongPass123", models.RoleAdmin)

		req := withUser(withChiID(httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+admin2.ID.String(), nil), admin2.ID.String()), asPrincipal(admin1))
		rec := httptest.NewRecorder()
		h.Delete(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("Статус = %d, ожидается: 403", rec.Code)
		}
		assertMessage(t, rec, messages.CannotDeleteAdminAccount)
	})

	t.Run("Несуществующий пользователь -> 404, битый UUID -> 400, без Principal -> 401", func(t *testing.T) {
		h, store := newUserHandler()
		admin := seedUser(t, store, "admin@example.com", "StrongPass123", models.RoleAdmin)

		missing := uuid.New().String()
		req := withUser(withChiID(httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+missing, nil), missing), asPrincipal(admin))
		rec := httptest.NewRecorder()
		h.Delete(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("404: статус = %d", rec.Code)
		}

		req = withUser(withChiID(httptest.NewRequest(http.MethodDelete, "/api/v1/users/bad", nil), "bad"), asPrincipal(admin))
		rec = httptest.NewRecorder()
		h.Delete(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("400: статус = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		h.Delete(rec, withChiID(httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+missing, nil), missing))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("401: статус = %d", rec.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// RBAC: ВЕРТИКАЛЬНАЯ ЭСКАЛАЦИЯ И IDOR ЧЕРЕЗ ПОЛНУЮ ЦЕПОЧКУ MIDDLEWARE
// ---------------------------------------------------------------------------

// TestRBAC_AdminEndpoints — атака «вертикальная эскалация»: обычный пользователь
// с ВАЛИДНЫМ access-токеном пытается вызвать админские эндпоинты. Цепочка
// Authenticate -> RequireAdmin обязана вернуть 403, без токена — 401.
func TestRBAC_AdminEndpoints(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewUserHandler(newUserUC(store))

	user := seedUser(t, store, "user@example.com", "StrongPass123", models.RoleUser)
	admin := seedUser(t, store, "admin@example.com", "StrongPass123", models.RoleAdmin)
	userPair, _ := auth.IssuePair(cfg, user.ID, user.Email, user.Role)
	adminPair, _ := auth.IssuePair(cfg, admin.ID, admin.Email, admin.Role)

	adminChain := middleware.Authenticate(cfg, store)(middleware.RequireAdmin(http.HandlerFunc(h.List)))

	t.Run("Обычный пользователь с валидным токеном -> 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users?page=1&limit=100", nil)
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: userPair.AccessToken})
		rec := httptest.NewRecorder()
		adminChain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("Статус = %d, ожидается: 403; body = %s", rec.Code, rec.Body.String())
		}
		assertMessage(t, rec, messages.InsufficientPermissions)
	})

	t.Run("Администратор с валидным токеном -> 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users?page=1&limit=100", nil)
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: adminPair.AccessToken})
		rec := httptest.NewRecorder()
		adminChain.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("Запрос без токена -> 401", func(t *testing.T) {
		rec := httptest.NewRecorder()
		adminChain.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/users?page=1&limit=100", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Статус = %d, ожидается: 401", rec.Code)
		}
	})
}

// TestRBAC_IDOR — атака IDOR: пользователь с валидным токеном обращается к чужой
// карточке через админский маршрут /users/{id}; доступ к собственному /users/me остается.
func TestRBAC_IDOR(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewUserHandler(newUserUC(store))

	user := seedUser(t, store, "user@example.com", "StrongPass123", models.RoleUser)
	victim := seedUser(t, store, "victim@example.com", "StrongPass123", models.RoleUser)
	userPair, _ := auth.IssuePair(cfg, user.ID, user.Email, user.Role)

	t.Run("Чужая карточка через админский маршрут -> 403", func(t *testing.T) {
		chain := middleware.Authenticate(cfg, store)(middleware.RequireAdmin(http.HandlerFunc(h.GetByID)))
		req := withChiID(httptest.NewRequest(http.MethodGet, "/api/v1/users/"+victim.ID.String(), nil), victim.ID.String())
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: userPair.AccessToken})
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("Статус = %d, ожидается: 403", rec.Code)
		}
	})

	t.Run("Собственный профиль через /users/me -> 200", func(t *testing.T) {
		chain := middleware.Authenticate(cfg, store)(middleware.RequireUserOrAdmin(http.HandlerFunc(h.Me)))
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: userPair.AccessToken})
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
		}
		var got models.User
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if got.ID != user.ID {
			t.Error("Пользователь получил чужой профиль")
		}
	})
}

// TestAdminFullFlow — позитивный сценарий работы администратора: вход -> список ->
// создание -> блокировка (PATCH status) -> удаление созданного пользователя.
func TestAdminFullFlow(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	authH := NewAuthHandler(cfg, newAuthUC(cfg, store))
	userH := NewUserHandler(newUserUC(store))
	admin := seedUser(t, store, "admin@example.com", "StrongPass123", models.RoleAdmin)
	adminPair, _ := auth.IssuePair(cfg, admin.ID, admin.Email, admin.Role)

	withAdmin := func(req *http.Request) *http.Request {
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: adminPair.AccessToken})
		return req
	}
	chain := func(next http.HandlerFunc) http.Handler {
		return middleware.Authenticate(cfg, store)(middleware.RequireAdmin(next))
	}

	// 1. Список пользователей содержит администратора.
	rec := httptest.NewRecorder()
	chain(userH.List).ServeHTTP(rec, withAdmin(httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("List: статус = %d", rec.Code)
	}

	// 2. Создание пользователя.
	rec = httptest.NewRecorder()
	chain(userH.Create).ServeHTTP(rec, withAdmin(postJSON("/api/v1/users", map[string]string{
		"email": "staff@example.com", "password": "StrongPass123",
		"first_name": "S", "last_name": "T",
	})))
	if rec.Code != http.StatusCreated {
		t.Fatalf("Create: статус = %d; body = %s", rec.Code, rec.Body.String())
	}
	var created models.User
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// 3. Блокировка пользователя (PATCH status=inactive).
	rec = httptest.NewRecorder()
	req := withChiID(postJSON("/api/v1/users/"+created.ID.String(), map[string]string{"status": "inactive"}), created.ID.String())
	chain(userH.Patch).ServeHTTP(rec, withAdmin(req))
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH: статус = %d; body = %s", rec.Code, rec.Body.String())
	}
	blocked, _ := store.GetByID(nilCtx(), created.ID)
	if blocked.Status != models.StatusInactive {
		t.Errorf("Статус после блокировки = %q", blocked.Status)
	}

	// 4. Заблокированный пользователь больше не может войти.
	rec = httptest.NewRecorder()
	authH.Login(rec, postJSON("/api/v1/login", map[string]string{"email": "staff@example.com", "password": "StrongPass123"}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Вход заблокированного: статус = %d, ожидается: 401", rec.Code)
	}

	// 5. Удаление пользователя.
	rec = httptest.NewRecorder()
	delReq := withChiID(httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+created.ID.String(), nil), created.ID.String())
	delReq = withUser(delReq, asPrincipal(admin))
	userH.Delete(rec, delReq)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE: статус = %d, ожидается: 204", rec.Code)
	}
	_ = bytes.MinRead // заглушка не нужна; импорт bytes используется postJSON в auth_test.go
}
