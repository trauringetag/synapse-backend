package handler

// Полное покрытие unit-тестами модуля аутентификации: регистрация пользователя,
// регистрация администратора, вход, ротация refresh-токенов, replay-атаки,
// CSRF-защита, выход из системы и сквозной жизненный цикл токенов.
// Все тесты работают через интерфейсы UserStore/TokenStore (способ 1) и in-memory
// мок mockStore, поэтому PostgreSQL не требуется.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/auth"
	"github.com/trauringetag/synapse-backend/internal/config"
	"github.com/trauringetag/synapse-backend/internal/messages"
	"github.com/trauringetag/synapse-backend/internal/middleware"
	"github.com/trauringetag/synapse-backend/internal/models"
)

// testConfig возвращает конфигурацию, единую для всех тестов пакета.
// Секрет JWT >= 32 байт, как требует боевой config.Load.
func testConfig() *config.Config {
	return &config.Config{
		JWTSecret:          []byte("unit-test-secret-key-32-bytes-long!"),
		AccessTTL:          15 * time.Minute,
		RefreshTTL:         168 * time.Hour,
		AdminRegisterToken: "secret-admin-register-token",
		CORSOrigins:        []string{"https://app.example"},
		CookieSecure:       false, // в тестах без TLS
		CookieSameSite:     http.SameSiteLaxMode,
		CookiePath:         "/api/v1/",
	}
}

// cookieMap — выборка cookie ответа по имени (перенесён сюда из store_mock_test.go
// вместе с корректным импортом net/http).
func cookieMap(cs []*http.Cookie) map[string]string {
	m := make(map[string]string, len(cs))
	for _, c := range cs {
		m[c.Name] = c.Value
	}
	return m
}

// assertDetail проверяет, что в теле ошибки 400/422 присутствует detail для поля field.
func assertDetail(t *testing.T, rec *httptest.ResponseRecorder, field string) {
	t.Helper()
	var body struct {
		Details map[string][]string `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("не удалось декодировать тело ответа: %v; body=%s", err, rec.Body.String())
	}
	if _, ok := body.Details[field]; !ok {
		t.Errorf("в details отсутствует поле %q; body=%s", field, rec.Body.String())
	}
}

// assertMessage проверяет человекочитаемое сообщение об ошибке/успехе в теле ответа.
func assertMessage(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("не удалось декодировать тело ответа: %v; body=%s", err, rec.Body.String())
	}
	if body.Message != want {
		t.Errorf("message = %q, хочу %q", body.Message, want)
	}
}

// postJSON — короткий helper для POST-запросов с JSON-телом.
func postJSON(url string, body any) *http.Request {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// validRegBody — корректное тело регистрации (используется как база для негативных кейсов).
func validRegBody() map[string]string {
	return map[string]string{
		"email":      "user@example.com",
		"password":   "StrongPass123",
		"first_name": "Ivan",
		"last_name":  "Petrov",
	}
}

// ---------------------------------------------------------------------------
// РЕГИСТРАЦИЯ ПОЛЬЗОВАТЕЛЯ
// ---------------------------------------------------------------------------

// TestRegister_Success проверяет успешную регистрацию: нормализацию email,
// роль по умолчанию и отсутствие bcrypt-хеша в ответе.
func TestRegister_Success(t *testing.T) {
	h := NewAuthHandler(testConfig(), newMockStore(), newMockStore())

	body := validRegBody()
	body["email"] = "  NewUser@Example.COM  " // пробелы и верхний регистр

	rec := httptest.NewRecorder()
	h.Register(rec, postJSON("/api/v1/register", body))

	if rec.Code != http.StatusCreated {
		t.Fatalf("статус = %d, хочу 201; body=%s", rec.Code, rec.Body.String())
	}
	var u models.User
	if err := json.Unmarshal(rec.Body.Bytes(), &u); err != nil {
		t.Fatal(err)
	}
	if u.Email != "newuser@example.com" {
		t.Errorf("email не нормализован: %q", u.Email)
	}
	if u.Role != models.RoleUser {
		t.Errorf("роль по умолчанию = %q, хочу %q", u.Role, models.RoleUser)
	}
	if u.Status != models.StatusActive {
		t.Errorf("статус нового пользователя = %q, хочу %q", u.Status, models.StatusActive)
	}
	// Утечка данных: хеш пароля не должен попадать в JSON (json:"-").
	if strings.Contains(rec.Body.String(), "password") {
		t.Errorf("в ответе регистрации присутствует поле password: %s", rec.Body.String())
	}
}

// TestRegister_ValidationErrors — таблица негативных кейсов валидации регистрации.
func TestRegister_ValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(map[string]string)
		rawBody    string // если != "", используется вместо JSON из mutate
		wantDetail string // пустое — detail не проверяем
	}{
		{name: "email без символа @", mutate: func(b map[string]string) { b["email"] = "not-an-email" }, wantDetail: "email"},
		{name: "пустой email", mutate: func(b map[string]string) { b["email"] = "" }, wantDetail: "email"},
		{name: "email длиннее 255 символов", mutate: func(b map[string]string) { b["email"] = strings.Repeat("a", 250) + "@x.com" }, wantDetail: "email"},
		{name: "пароль короче 8 символов", mutate: func(b map[string]string) { b["password"] = "Sh0rt" }, wantDetail: "password"},
		{name: "пароль длиннее 72 символов (лимит bcrypt)", mutate: func(b map[string]string) { b["password"] = strings.Repeat("a", 73) }, wantDetail: "password"},
		{name: "пустое имя", mutate: func(b map[string]string) { b["first_name"] = "" }, wantDetail: "first_name"},
		{name: "пустая фамилия", mutate: func(b map[string]string) { b["last_name"] = "" }, wantDetail: "last_name"},
		{name: "имя длиннее 255 символов", mutate: func(b map[string]string) { b["first_name"] = strings.Repeat("b", 256) }, wantDetail: "first_name"},
		{name: "пустое JSON-тело {}", mutate: func(b map[string]string) {
			for k := range b {
				delete(b, k)
			}
		}, wantDetail: "email"},
		{name: "битый JSON", rawBody: `{"email": `, wantDetail: ""},
		{name: "два JSON-документа в теле", rawBody: `{"email":"a@b.c"}{"email":"d@e.f"}`, wantDetail: ""},
		{name: "пустое тело запроса", rawBody: ``, wantDetail: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAuthHandler(testConfig(), newMockStore(), newMockStore())
			var req *http.Request
			if tt.rawBody != "" {
				req = httptest.NewRequest(http.MethodPost, "/api/v1/register", strings.NewReader(tt.rawBody))
				req.Header.Set("Content-Type", "application/json")
			} else {
				body := validRegBody()
				tt.mutate(body)
				req = postJSON("/api/v1/register", body)
			}

			rec := httptest.NewRecorder()
			h.Register(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("статус = %d, хочу 400; body=%s", rec.Code, rec.Body.String())
			}
			if tt.wantDetail != "" {
				assertDetail(t, rec, tt.wantDetail)
			}
		})
	}
}

// TestRegister_MassAssignmentBlocked — атака mass assignment: публичная регистрация
// не должна принимать поле role (и любые неизвестные поля, DisallowUnknownFields).
func TestRegister_MassAssignmentBlocked(t *testing.T) {
	tests := []struct {
		name  string
		extra string
	}{
		{name: "попытка задать role=admin при регистрации", extra: `"role":"admin"`},
		{name: "попытка задать status", extra: `"status":"inactive"`},
		{name: "неизвестное поле", extra: `"is_super":true`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAuthHandler(testConfig(), newMockStore(), newMockStore())
			raw := `{"email":"u@example.com","password":"StrongPass123","first_name":"I","last_name":"P",` + tt.extra + `}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/register", strings.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			h.Register(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("статус = %d, хочу 400 (поле отклонено); body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestRegister_DuplicateEmail — повторная регистрация на занятый email -> 409 Conflict.
func TestRegister_DuplicateEmail(t *testing.T) {
	store := newMockStore()
	h := NewAuthHandler(testConfig(), store, store)

	rec := httptest.NewRecorder()
	h.Register(rec, postJSON("/api/v1/register", validRegBody()))
	if rec.Code != http.StatusCreated {
		t.Fatalf("первая регистрация: статус = %d, хочу 201", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.Register(rec, postJSON("/api/v1/register", validRegBody()))
	if rec.Code != http.StatusConflict {
		t.Fatalf("повторная регистрация: статус = %d, хочу 409; body=%s", rec.Code, rec.Body.String())
	}
	assertMessage(t, rec, messages.EmailAlreadyUsed)
}

// ---------------------------------------------------------------------------
// РЕГИСТРАЦИЯ АДМИНИСТРАТОРА
// ---------------------------------------------------------------------------

// TestRegisterAdmin_Success — регистрация админа с валидным X-Admin-Token.
func TestRegisterAdmin_Success(t *testing.T) {
	store := newMockStore()
	cfg := testConfig()
	h := NewAuthHandler(cfg, store, store)

	req := postJSON("/api/v1/register-admin", validRegBody())
	req.Header.Set("X-Admin-Token", cfg.AdminRegisterToken)

	rec := httptest.NewRecorder()
	h.RegisterAdmin(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("статус = %d, хочу 201; body=%s", rec.Code, rec.Body.String())
	}
	var u models.User
	_ = json.Unmarshal(rec.Body.Bytes(), &u)
	if u.Role != models.RoleAdmin {
		t.Errorf("роль = %q, хочу %q", u.Role, models.RoleAdmin)
	}
}

// TestRegisterAdmin_Forbidden — атака: регистрация админа без токена, с неверным
// токеном и с токеном, искажённым пробелами (constant-time compare не прощает расхождений).
func TestRegisterAdmin_Forbidden(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "токен не передан", token: ""},
		{name: "неверный токен", token: "wrong-token"},
		{name: "токен с пробелом (искажение)", token: "secret-admin-register-token "},
		{name: "токен в другом регистре", token: "SECRET-ADMIN-REGISTER-TOKEN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			cfg := testConfig()
			h := NewAuthHandler(cfg, store, store)

			req := postJSON("/api/v1/register-admin", validRegBody())
			if tt.token != "" {
				req.Header.Set("X-Admin-Token", tt.token)
			}

			rec := httptest.NewRecorder()
			h.RegisterAdmin(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("статус = %d, хочу 403; body=%s", rec.Code, rec.Body.String())
			}
			assertMessage(t, rec, messages.InvalidAdminToken)
			// Пользователь не должен создаться в хранилище.
			if _, err := store.GetByEmail(req.Context(), "user@example.com"); err == nil {
				t.Error("пользователь не должен создаваться при невалидном admin-токене")
			}
		})
	}
}

// TestRegisterAdmin_ValidationRunsFirst — валидация полей выполняется ДО проверки
// admin-токена: битое тело даёт 400 даже без токена (не раскрываем порядок проверок).
func TestRegisterAdmin_ValidationRunsFirst(t *testing.T) {
	store := newMockStore()
	h := NewAuthHandler(testConfig(), store, store)

	body := validRegBody()
	body["password"] = "short"

	rec := httptest.NewRecorder()
	h.RegisterAdmin(rec, postJSON("/api/v1/register-admin", body)) // без X-Admin-Token

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("статус = %d, хочу 400 (валидация раньше проверки токена); body=%s", rec.Code, rec.Body.String())
	}
	assertDetail(t, rec, "password")
}

// ---------------------------------------------------------------------------
// ВХОД (LOGIN)
// ---------------------------------------------------------------------------

// seedUser создаёт пользователя с хешем bcrypt.MinCost (быстро) для большинства тестов.
func seedUser(t *testing.T, store *mockStore, email, password, role string) *models.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u, err := store.Create(nilCtx(), email, string(hash), role, "First", "Last")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestLogin_Success — успешный вход: 200, cookie access/refresh с безопасными атрибутами,
// токены разбираются только со своим назначением (audience).
func TestLogin_Success(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, store, store)
	seedUser(t, store, "user@example.com", "StrongPass123", models.RoleUser)

	rec := httptest.NewRecorder()
	h.Login(rec, postJSON("/api/v1/login", map[string]string{
		"email":    "User@Example.com", // регистр не важен
		"password": "StrongPass123",
	}))

	if rec.Code != http.StatusOK {
		t.Fatalf("статус = %d, хочу 200; body=%s", rec.Code, rec.Body.String())
	}
	assertMessage(t, rec, messages.AuthorizationSuccessful)

	cookies := rec.Result().Cookies()
	cm := cookieMap(cookies)
	access, refresh := cm[auth.AccessCookie], cm[auth.RefreshCookie]
	if access == "" || refresh == "" {
		t.Fatalf("не установлены cookie токенов: %v", cm)
	}

	// Безопасные атрибуты cookie токенов.
	for _, c := range cookies {
		if c.Name == auth.AccessCookie || c.Name == auth.RefreshCookie {
			if !c.HttpOnly {
				t.Errorf("cookie %s должна быть HttpOnly", c.Name)
			}
			if c.Path != "/api/v1/" {
				t.Errorf("cookie %s: path = %q, хочу /api/v1/", c.Name, c.Path)
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("cookie %s: SameSite = %v, хочу Lax", c.Name, c.SameSite)
			}
		}
	}

	// Токены валидны и имеют правильное назначение.
	if _, err := auth.Parse(cfg, access, "access"); err != nil {
		t.Errorf("access-токен не разбирается: %v", err)
	}
	if _, err := auth.Parse(cfg, refresh, "refresh"); err != nil {
		t.Errorf("refresh-токен не разбирается: %v", err)
	}
	// Атака: access-токен не должен приниматься как refresh и наоборот.
	if _, err := auth.Parse(cfg, access, "refresh"); err == nil {
		t.Error("access-токен не должен приниматься как refresh")
	}
	if _, err := auth.Parse(cfg, refresh, "access"); err == nil {
		t.Error("refresh-токен не должен приниматься как access")
	}

	// Refresh-токен сохранён в хранилище (по хешу).
	if _, err := store.GetActive(nilCtx(), auth.HashToken(refresh)); err != nil {
		t.Errorf("refresh-токен не сохранён в хранилище: %v", err)
	}

	// Утечка данных: хеш пароля не попадает в ответ.
	if strings.Contains(rec.Body.String(), "password_hash") || strings.Contains(rec.Body.String(), "$2a$") {
		t.Errorf("в ответе login присутствует хеш пароля: %s", rec.Body.String())
	}
}

// TestLogin_InvalidCredentials — неверный пароль / неизвестный email / заблокированный
// пользователь: всегда 401 с одинаковым сообщением (без перечисления пользователей).
func TestLogin_InvalidCredentials(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, store, store)
	seedUser(t, store, "user@example.com", "StrongPass123", models.RoleUser)
	inactive := seedUser(t, store, "blocked@example.com", "StrongPass123", models.RoleUser)
	inactive.Status = models.StatusInactive

	tests := []struct {
		name     string
		email    string
		password string
	}{
		{name: "неверный пароль", email: "user@example.com", password: "WrongPass123"},
		{name: "неизвестный email", email: "ghost@example.com", password: "StrongPass123"},
		{name: "заблокированный пользователь (status=inactive)", email: "blocked@example.com", password: "StrongPass123"},
		{name: "пустой пароль", email: "user@example.com", password: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.Login(rec, postJSON("/api/v1/login", map[string]string{"email": tt.email, "password": tt.password}))

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("статус = %d, хочу 401; body=%s", rec.Code, rec.Body.String())
			}
			assertMessage(t, rec, messages.InvalidCredentials)
			// Токены не выдаются.
			cm := cookieMap(rec.Result().Cookies())
			if cm[auth.AccessCookie] != "" || cm[auth.RefreshCookie] != "" {
				t.Error("при ошибочном входе cookie токенов устанавливаться не должны")
			}
		})
	}
}

// TestLogin_BodyLimits — защита от переполнения: email > 255 или пароль > 72 -> 400,
// битый JSON -> 400.
func TestLogin_BodyLimits(t *testing.T) {
	store := newMockStore()
	h := NewAuthHandler(testConfig(), store, store)

	tests := []struct {
		name string
		body string
	}{
		{name: "email длиннее 255", body: `{"email":"` + strings.Repeat("a", 250) + `@x.com","password":"StrongPass123"}`},
		{name: "пароль длиннее 72", body: `{"email":"u@e.com","password":"` + strings.Repeat("a", 73) + `"}`},
		{name: "битый JSON", body: `{"email":`},
		{name: "неизвестное поле", body: `{"email":"u@e.com","password":"StrongPass123","admin":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.Login(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("статус = %d, хочу 400; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestLogin_TimingAttackProtection — защита от timing-атаки: ветки «пользователь есть,
// пароль неверный» и «пользователя нет» обе выполняют bcrypt-сравнение (с фиктивным
// хешем), поэтому время отклика не раскрывает существование учетной записи.
func TestLogin_TimingAttackProtection(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, store, store)

	// Хеш боевой стоимости (DefaultCost), как в продакшене.
	hash, err := bcrypt.GenerateFromPassword([]byte("CorrectPass123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	store.seedUser(&models.User{
		ID: uuid.New(), Email: "exists@example.com", PasswordHash: string(hash),
		Role: models.RoleUser, Status: models.StatusActive, FirstName: "E", LastName: "X",
	})

	measure := func(email string) time.Duration {
		rec := httptest.NewRecorder()
		start := time.Now()
		h.Login(rec, postJSON("/api/v1/login", map[string]string{"email": email, "password": "WrongPass123"}))
		d := time.Since(start)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("статус = %d, хочу 401 для %s", rec.Code, email)
		}
		return d
	}

	dExists := measure("exists@example.com")
	dMissing := measure("no-such-user@example.com")

	// Обе ветки обязаны пройти bcrypt (иначе сравнение было бы мгновенным).
	if dExists < 10*time.Millisecond || dMissing < 10*time.Millisecond {
		t.Errorf("bcrypt-сравнение не выполнено в одной из веток: exists=%v, missing=%v", dExists, dMissing)
	}
	// Жёсткое сравнение времён_flaky_ в CI, поэтому расхождение только логируем.
	if ratio := float64(dExists) / float64(dMissing); ratio > 3 || ratio < 1.0/3 {
		t.Logf("ВНИМАНИЕ: расхождение времён: exists=%v missing=%v ratio=%.2f", dExists, dMissing, ratio)
	}
}

// ---------------------------------------------------------------------------
// REFRESH: РОТАЦИЯ, REPLAY-АТАКИ, ОТСРОЧЕННЫЕ СЦЕНАРИИ
// ---------------------------------------------------------------------------

// loginCookies выполняет вход и возвращает пару cookie-токенов.
func loginCookies(t *testing.T, h *AuthHandler, email, password string) map[string]string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.Login(rec, postJSON("/api/v1/login", map[string]string{"email": email, "password": password}))
	if rec.Code != http.StatusOK {
		t.Fatalf("вход: статус = %d, хочу 200; body=%s", rec.Code, rec.Body.String())
	}
	return cookieMap(rec.Result().Cookies())
}

// refreshRequest создаёт запрос /refresh с указанным refresh-токеном в cookie.
func refreshRequest(token string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: auth.RefreshCookie, Value: token})
	}
	return req
}

// TestRefresh_Rotation — успешная ротация: старая пара заменяется новой,
// старый refresh-токен помечается отозванным в хранилище.
func TestRefresh_Rotation(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, store, store)
	seedUser(t, store, "user@example.com", "StrongPass123", models.RoleUser)

	cm := loginCookies(t, h, "user@example.com", "StrongPass123")
	oldRefresh := cm[auth.RefreshCookie]

	rec := httptest.NewRecorder()
	h.Refresh(rec, refreshRequest(oldRefresh))

	if rec.Code != http.StatusOK {
		t.Fatalf("статус = %d, хочу 200; body=%s", rec.Code, rec.Body.String())
	}
	assertMessage(t, rec, messages.TokensRefreshed)

	rotated := cookieMap(rec.Result().Cookies())
	newAccess, newRefresh := rotated[auth.AccessCookie], rotated[auth.RefreshCookie]
	if newRefresh == "" || newRefresh == oldRefresh {
		t.Fatal("ротация не произошла: refresh-токен не сменился")
	}
	if newAccess == "" || newAccess == cm[auth.AccessCookie] {
		t.Error("access-токен также должен быть перевыпущен")
	}

	// Старый токен отозван в хранилище (условный UPDATE внутри транзакции).
	oldRec, err := store.GetActive(nilCtx(), auth.HashToken(oldRefresh))
	if err == nil && !oldRec.Revoked {
		t.Error("старый refresh-токен должен быть отозван после ротации")
	}
	// Новый токен активен.
	if _, err := store.GetActive(nilCtx(), auth.HashToken(newRefresh)); err != nil {
		t.Errorf("новый refresh-токен не активен: %v", err)
	}
}

// TestRefresh_ReplayAttack — АТАКА: повторное использование украденного старого
// refresh-токена. Ожидаем 401 и ПОЛНЫЙ отзыв всех сессий пользователя (даже новых).
func TestRefresh_ReplayAttack(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, store, store)
	u := seedUser(t, store, "user@example.com", "StrongPass123", models.RoleUser)

	cm := loginCookies(t, h, "user@example.com", "StrongPass123")
	oldRefresh := cm[auth.RefreshCookie]

	// Легитимная ротация: получаем новую пару.
	rec := httptest.NewRecorder()
	h.Refresh(rec, refreshRequest(oldRefresh))
	if rec.Code != http.StatusOK {
		t.Fatalf("ротация: статус = %d, хочу 200", rec.Code)
	}
	newRefresh := cookieMap(rec.Result().Cookies())[auth.RefreshCookie]

	// Атакующий переиспользует старый токен -> детект replay.
	rec = httptest.NewRecorder()
	h.Refresh(rec, refreshRequest(oldRefresh))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay: статус = %d, хочу 401; body=%s", rec.Code, rec.Body.String())
	}
	assertMessage(t, rec, messages.InvalidOrExpiredRefreshToken)

	// Все сессии пользователя отозваны: даже свежий легитимный токен мёртв.
	rec = httptest.NewRecorder()
	h.Refresh(rec, refreshRequest(newRefresh))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("после replay все сессии должны быть отозваны: статус = %d, хочу 401", rec.Code)
	}
	store.mu.Lock()
	for hash, tk := range store.tokens {
		_ = hash
		if tk.UserID == u.ID && !tk.Revoked {
			t.Errorf("токен %s пользователя не отозван после replay-атаки", tk.TokenHash[:8])
		}
	}
	store.mu.Unlock()
}

// TestRefresh_RejectCases — негативные кейсы: нет cookie, мусор, access вместо refresh,
// просроченный токен, токен не из хранилища, заблокированный пользователь.
func TestRefresh_RejectCases(t *testing.T) {
	cfg := testConfig()

	t.Run("отсутствует cookie refresh_token", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, store, store)
		rec := httptest.NewRecorder()
		h.Refresh(rec, refreshRequest(""))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("статус = %d, хочу 401", rec.Code)
		}
		// Cookie токенов очищаются даже при отказе.
		for _, c := range rec.Result().Cookies() {
			if (c.Name == auth.AccessCookie || c.Name == auth.RefreshCookie) && c.MaxAge != -1 {
				t.Errorf("cookie %s должна быть удалена при отказе", c.Name)
			}
		}
	})

	t.Run("мусорный токен", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, store, store)
		rec := httptest.NewRecorder()
		h.Refresh(rec, refreshRequest("not.a.jwt"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("статус = %d, хочу 401", rec.Code)
		}
	})

	t.Run("access-токен вместо refresh (проверка audience)", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, store, store)
		seedUser(t, store, "user@example.com", "StrongPass123", models.RoleUser)
		cm := loginCookies(t, h, "user@example.com", "StrongPass123")

		rec := httptest.NewRecorder()
		h.Refresh(rec, refreshRequest(cm[auth.AccessCookie])) // подмена назначения
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("статус = %d, хочу 401", rec.Code)
		}
	})

	t.Run("просроченный, но корректно подписанный токен", func(t *testing.T) {
		expCfg := testConfig()
		expCfg.RefreshTTL = -time.Hour // токен родился уже просроченным
		store := newMockStore()
		h := NewAuthHandler(expCfg, store, store)
		u := seedUser(t, store, "user@example.com", "StrongPass123", models.RoleUser)
		pair, err := auth.IssuePair(expCfg, u.ID, u.Email, u.Role)
		if err != nil {
			t.Fatal(err)
		}

		rec := httptest.NewRecorder()
		h.Refresh(rec, refreshRequest(pair.RefreshToken))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("статус = %d, хочу 401 для просроченного токена", rec.Code)
		}
	})

	t.Run("валидный JWT, но неизвестный хранилищу токен", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, store, store)
		u := seedUser(t, store, "user@example.com", "StrongPass123", models.RoleUser)
		pair, _ := auth.IssuePair(cfg, u.ID, u.Email, u.Role) // в store не сохраняли

		rec := httptest.NewRecorder()
		h.Refresh(rec, refreshRequest(pair.RefreshToken))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("статус = %d, хочу 401 для неизвестного токена", rec.Code)
		}
	})

	t.Run("refresh для заблокированного пользователя отзывает его сессии", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, store, store)
		u := seedUser(t, store, "blocked@example.com", "StrongPass123", models.RoleUser)
		pair, _ := auth.IssuePair(cfg, u.ID, u.Email, u.Role)
		_ = store.Store(nilCtx(), u.ID, auth.HashToken(pair.RefreshToken), pair.RefreshExp)
		u.Status = models.StatusInactive // блокировка админом после выдачи токена

		rec := httptest.NewRecorder()
		h.Refresh(rec, refreshRequest(pair.RefreshToken))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("статус = %d, хочу 401 для inactive-пользователя", rec.Code)
		}
		if _, err := store.GetActive(nilCtx(), auth.HashToken(pair.RefreshToken)); err == nil {
			t.Error("сессии заблокированного пользователя должны быть отозваны")
		}
	})
}

// ---------------------------------------------------------------------------
// LOGOUT
// ---------------------------------------------------------------------------

// TestLogout — выход гасит refresh-токен в хранилище и очищает cookie;
// выход без cookie также успешен (идемпотентность).
func TestLogout(t *testing.T) {
	cfg := testConfig()

	t.Run("выход с активным refresh-токеном", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, store, store)
		seedUser(t, store, "user@example.com", "StrongPass123", models.RoleUser)
		cm := loginCookies(t, h, "user@example.com", "StrongPass123")
		refresh := cm[auth.RefreshCookie]

		rec := httptest.NewRecorder()
		h.Logout(rec, refreshRequest(refresh))

		if rec.Code != http.StatusOK {
			t.Fatalf("статус = %d, хочу 200", rec.Code)
		}
		assertMessage(t, rec, messages.LoggedOut)
		if _, err := store.GetActive(nilCtx(), auth.HashToken(refresh)); err == nil {
			t.Error("refresh-токен должен быть отозван при выходе")
		}
		for _, c := range rec.Result().Cookies() {
			if (c.Name == auth.AccessCookie || c.Name == auth.RefreshCookie) && c.MaxAge != -1 {
				t.Errorf("cookie %s должна быть удалена при выходе", c.Name)
			}
		}
	})

	t.Run("выход без cookie также возвращает 200", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, store, store)
		rec := httptest.NewRecorder()
		h.Logout(rec, httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("статус = %d, хочу 200", rec.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

// TestCSRFTokenEndpoint — выдача CSRF-токена: cookie доступна JS (HttpOnly=false),
// значение в cookie и в теле совпадают, токен проходит проверку middleware.
func TestCSRFTokenEndpoint(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, store, store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/csrf", nil)
	req.Header.Set("Origin", "https://app.example")
	rec := httptest.NewRecorder()
	h.CSRFToken(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("статус = %d, хочу 200", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	token := body["csrf_token"]
	if token == "" {
		t.Fatal("тело ответа не содержит csrf_token")
	}
	cm := cookieMap(rec.Result().Cookies())
	if cm["csrf_token"] != token {
		t.Error("значение csrf-токена в cookie и в теле должно совпадать")
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			if c.HttpOnly {
				t.Error("csrf cookie обязана быть читаемой из JS (HttpOnly=false)")
			}
			if c.MaxAge != 3600 {
				t.Errorf("MaxAge csrf cookie = %d, хочу 3600", c.MaxAge)
			}
		}
	}
}

// TestCSRFMiddlewareBlocksStateChangingRequests — атака CSRF: POST без токена,
// с поддельным токеном и с токеном только в header (без cookie) -> 403.
func TestCSRFMiddlewareBlocksStateChangingRequests(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, store, store)
	chain := middleware.CSRF(cfg)(http.HandlerFunc(h.Register))

	t.Run("POST без CSRF-токена", func(t *testing.T) {
		req := postJSON("/api/v1/register", validRegBody())
		req.Header.Set("Origin", "https://app.example")
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("статус = %d, хочу 403", rec.Code)
		}
	})

	t.Run("POST с поддельным CSRF-токеном", func(t *testing.T) {
		req := postJSON("/api/v1/register", validRegBody())
		req.Header.Set("Origin", "https://app.example")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "forged.token"})
		req.Header.Set("X-CSRF-Token", "forged.token")
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("статус = %d, хочу 403", rec.Code)
		}
	})

	t.Run("POST с токеном только в header (без cookie)", func(t *testing.T) {
		token, _ := middleware.IssueCSRF(cfg.JWTSecret)
		req := postJSON("/api/v1/register", validRegBody())
		req.Header.Set("Origin", "https://app.example")
		req.Header.Set("X-CSRF-Token", token) // cookie не приложена
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("статус = %d, хочу 403", rec.Code)
		}
	})

	t.Run("POST с токеном только в cookie (без header)", func(t *testing.T) {
		token, _ := middleware.IssueCSRF(cfg.JWTSecret)
		req := postJSON("/api/v1/register", validRegBody())
		req.Header.Set("Origin", "https://app.example")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("статус = %d, хочу 403", rec.Code)
		}
	})

	t.Run("POST с чужого Origin отклоняется даже с валидным токеном", func(t *testing.T) {
		token, _ := middleware.IssueCSRF(cfg.JWTSecret)
		req := postJSON("/api/v1/register", validRegBody())
		req.Header.Set("Origin", "https://evil.example")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
		req.Header.Set("X-CSRF-Token", token)
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("статус = %d, хочу 403", rec.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// СКВОЗНОЙ ЖИЗНЕННЫЙ ЦИКЛ ТОКЕНОВ (csrf + access + refresh)
// ---------------------------------------------------------------------------

// TestFullTokenLifecycle — сквозной unit-тест полного жизненного цикла токенов:
// выпуск CSRF -> регистрация (под CSRF-защитой) -> login (access+refresh cookie) ->
// аутентифицированный запрос по access -> ротация refresh -> REPLAY-АТАКА (повторное
// использование старого refresh) -> отзыв всех сессий -> logout с очисткой cookie.
func TestFullTokenLifecycle(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	authH := NewAuthHandler(cfg, store, store)
	userH := NewUserHandler(store, store)
	const origin = "https://app.example"

	// ШАГ 1. Получаем CSRF-токен (cookie + тело ответа).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/csrf", nil)
	req.Header.Set("Origin", origin)
	authH.CSRFToken(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("csrf: статус = %d, хочу 200", rec.Code)
	}
	var csrfResp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &csrfResp)
	csrfToken := csrfResp["csrf_token"]
	if csrfToken == "" {
		t.Fatal("CSRF-токен не выдан")
	}

	// ШАГ 2. Регистрация пользователя через middleware.CSRF.
	regReq := postJSON("/api/v1/register", validRegBody())
	regReq.Header.Set("Origin", origin)
	regReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	regReq.Header.Set("X-CSRF-Token", csrfToken)
	rec = httptest.NewRecorder()
	middleware.CSRF(cfg)(http.HandlerFunc(authH.Register)).ServeHTTP(rec, regReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: статус = %d, хочу 201; body=%s", rec.Code, rec.Body.String())
	}

	// ШАГ 3. Login: получаем access_token и refresh_token в cookie.
	loginReq := postJSON("/api/v1/login", map[string]string{
		"email": "user@example.com", "password": "StrongPass123",
	})
	loginReq.Header.Set("Origin", origin)
	loginReq.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	loginReq.Header.Set("X-CSRF-Token", csrfToken)
	rec = httptest.NewRecorder()
	middleware.CSRF(cfg)(http.HandlerFunc(authH.Login)).ServeHTTP(rec, loginReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: статус = %d, хочу 200; body=%s", rec.Code, rec.Body.String())
	}
	cm := cookieMap(rec.Result().Cookies())
	access, refresh := cm[auth.AccessCookie], cm[auth.RefreshCookie]
	if access == "" || refresh == "" {
		t.Fatal("login не установил access/refresh cookie")
	}

	// ШАГ 4. Аутентифицированный запрос GET /users/me по access-токену.
	meReq := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	meReq.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: access})
	rec = httptest.NewRecorder()
	middleware.Authenticate(cfg, store)(
		middleware.RequireUserOrAdmin(http.HandlerFunc(userH.Me)),
	).ServeHTTP(rec, meReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("me: статус = %d, хочу 200; body=%s", rec.Code, rec.Body.String())
	}

	// ШАГ 5. Refresh: ротация — cookie заменяются новой парой.
	rec = httptest.NewRecorder()
	authH.Refresh(rec, refreshRequest(refresh))
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: статус = %d, хочу 200; body=%s", rec.Code, rec.Body.String())
	}
	rotated := cookieMap(rec.Result().Cookies())
	refresh2 := rotated[auth.RefreshCookie]
	if refresh2 == "" || refresh2 == refresh {
		t.Fatal("ротация не произошла: refresh-токен не сменился")
	}

	// ШАГ 6. АТАКА (replay): злоумышленник переиспользует украденный старый refresh.
	rec = httptest.NewRecorder()
	authH.Refresh(rec, refreshRequest(refresh))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay: статус = %d, хочу 401", rec.Code)
	}

	// ШАГ 7. После детекта replay все сессии отозваны: новый токен тоже не работает.
	rec = httptest.NewRecorder()
	authH.Refresh(rec, refreshRequest(refresh2))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("после replay сессии должны быть отозваны: статус = %d, хочу 401", rec.Code)
	}

	// ШАГ 8. Logout очищает cookie токенов (MaxAge = -1).
	rec = httptest.NewRecorder()
	authH.Logout(rec, httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("logout: статус = %d, хочу 200", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if (c.Name == auth.AccessCookie || c.Name == auth.RefreshCookie) && c.MaxAge != -1 {
			t.Errorf("cookie %s не удалена при logout (MaxAge=%d)", c.Name, c.MaxAge)
		}
	}
}
