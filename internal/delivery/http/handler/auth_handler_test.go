package handler

// Полное покрытие unit-тестами модуля аутентификации: регистрация пользователя,
// регистрация администратора, вход, ротация refresh-токенов, replay-атаки,
// CSRF-защита, выход из системы и сквозной жизненный цикл токенов.
// Все тесты работают через интерфейсы UserStore/TokenStore (способ 1) и in-memory, мок mockStore.

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

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/middleware"
	auth "github.com/trauringetag/synapse-backend/internal/infrastructure/security"
	"github.com/trauringetag/synapse-backend/internal/messages"
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

// cookieMap — выборка cookie ответа по имени (перенесен сюда из store_mock_test.go
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
		t.Fatalf("Не удалось декодировать тело ответа: %v; body = %s", err, rec.Body.String())
	}
	if _, ok := body.Details[field]; !ok {
		t.Errorf("В details отсутствует поле %q; body = %s", field, rec.Body.String())
	}
}

// assertMessage проверяет человекочитаемое сообщение об ошибке/успехе в теле ответа.
func assertMessage(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("Не удалось декодировать тело ответа: %v; body = %s", err, rec.Body.String())
	}
	if body.Message != want {
		t.Errorf("Message = %q, ожидается: %q", body.Message, want)
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
	h := NewAuthHandler(testConfig(), newAuthUC(testConfig(), newMockStore()))

	body := validRegBody()
	body["email"] = "  NewUser@Example.COM  " // пробелы и верхний регистр

	rec := httptest.NewRecorder()
	h.Register(rec, postJSON("/api/v1/register", body))

	if rec.Code != http.StatusCreated {
		t.Fatalf("Статус = %d, ожидается: 201; body = %s", rec.Code, rec.Body.String())
	}
	// Веб-формат (без X-Client-Platform): сообщение + профиль, токенов в теле нет.
	var resp struct {
		Message string      `json:"message"`
		User    domain.User `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Message != messages.RegistrationSuccessful {
		t.Errorf("Message = %q, ожидается: %q", resp.Message, messages.RegistrationSuccessful)
	}
	u := resp.User
	if u.Email != "newuser@example.com" {
		t.Errorf("Email не нормализован: %q", u.Email)
	}
	if u.Role != domain.RoleUser {
		t.Errorf("Роль по умолчанию = %q, ожидается: %q", u.Role, domain.RoleUser)
	}
	if u.Status != domain.StatusActive {
		t.Errorf("Статус нового пользователя = %q, ожидается: %q", u.Status, domain.StatusActive)
	}
	// Утечка данных: хеш пароля не должен попадать в JSON (json:"-").
	if strings.Contains(rec.Body.String(), "password") {
		t.Errorf("В ответе регистрации присутствует поле password: %s", rec.Body.String())
	}
}

// TestRegister_ValidationErrors — таблица негативных кейсов валидации регистрации.
func TestRegister_ValidationErrors(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(map[string]string)
		rawBody    string
		wantDetail string
	}{
		{name: "Email без символа @", mutate: func(b map[string]string) { b["email"] = "not-an-email" }, wantDetail: "email"},
		{name: "Пустой email", mutate: func(b map[string]string) { b["email"] = "" }, wantDetail: "email"},
		{name: "Email длиннее 255 символов", mutate: func(b map[string]string) { b["email"] = strings.Repeat("a", 250) + "@x.com" }, wantDetail: "email"},
		{name: "Пароль короче 8 символов", mutate: func(b map[string]string) { b["password"] = "Sh0rt" }, wantDetail: "password"},
		{name: "Пароль длиннее 72 символов (лимит bcrypt)", mutate: func(b map[string]string) { b["password"] = strings.Repeat("a", 73) }, wantDetail: "password"},
		{name: "Пустое имя", mutate: func(b map[string]string) { b["first_name"] = "" }, wantDetail: "first_name"},
		{name: "Пустая фамилия", mutate: func(b map[string]string) { b["last_name"] = "" }, wantDetail: "last_name"},
		{name: "Имя длиннее 255 символов", mutate: func(b map[string]string) { b["first_name"] = strings.Repeat("b", 256) }, wantDetail: "first_name"},
		{name: "Пустое JSON-тело {}", mutate: func(b map[string]string) {
			for k := range b {
				delete(b, k)
			}
		}, wantDetail: "email"},
		{name: "Битый JSON", rawBody: `{"email": `},
		{name: "Два JSON-документа в теле", rawBody: `{"email":"a@b.c"}{"email":"d@e.f"}`},
		{name: "Пустое тело запроса", rawBody: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAuthHandler(testConfig(), newAuthUC(testConfig(), newMockStore()))

			var req *http.Request
			if tt.mutate != nil {
				body := validRegBody()
				tt.mutate(body)
				req = postJSON("/api/v1/register", body)
			} else {
				req = httptest.NewRequest(http.MethodPost, "/api/v1/register", strings.NewReader(tt.rawBody))
				req.Header.Set("Content-Type", "application/json")
			}

			rec := httptest.NewRecorder()
			h.Register(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("Статус = %d, ожидается: 400; body = %s", rec.Code, rec.Body.String())
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
		{name: "Попытка задать role=admin при регистрации", extra: `"role":"admin"`},
		{name: "Попытка задать status", extra: `"status":"inactive"`},
		{name: "Неизвестное поле", extra: `"is_super":true`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAuthHandler(testConfig(), newAuthUC(testConfig(), newMockStore()))
			raw := `{"email":"u@example.com","password":"StrongPass123","first_name":"I","last_name":"P",` + tt.extra + `}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/register", strings.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			h.Register(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("Статус = %d, ожидается: 400 (поле отклонено); body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestRegister_DuplicateEmail — повторная регистрация на занятый email -> 409 Conflict.
func TestRegister_DuplicateEmail(t *testing.T) {
	store := newMockStore()
	h := NewAuthHandler(testConfig(), newAuthUC(testConfig(), store))

	rec := httptest.NewRecorder()
	h.Register(rec, postJSON("/api/v1/register", validRegBody()))
	if rec.Code != http.StatusCreated {
		t.Fatalf("Первая регистрация: статус = %d, ожидается: 201", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.Register(rec, postJSON("/api/v1/register", validRegBody()))
	if rec.Code != http.StatusConflict {
		t.Fatalf("Повторная регистрация: статус = %d, ожидается: 409; body = %s", rec.Code, rec.Body.String())
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
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))

	req := postJSON("/api/v1/register-admin", validRegBody())
	req.Header.Set("X-Admin-Token", cfg.AdminRegisterToken)

	rec := httptest.NewRecorder()
	h.RegisterAdmin(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Статус = %d, ожидается: 201; body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Message string      `json:"message"`
		User    domain.User `json:"user"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.User.Role != domain.RoleAdmin {
		t.Errorf("Роль = %q, ожидается: %q", resp.User.Role, domain.RoleAdmin)
	}
}

// TestRegisterAdmin_Forbidden — атака: регистрация админа без токена, с неверным
// токеном и с токеном, искаженным пробелами (constant-time compare не прощает расхождений).
func TestRegisterAdmin_Forbidden(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "Токен не передан", token: ""},
		{name: "Неверный токен", token: "wrong-token"},
		{name: "Токен с пробелом (искажение)", token: "secret-admin -register-token"},
		{name: "Токен в другом регистре", token: "SECRET-ADMIN-REGISTER-TOKEN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			cfg := testConfig()
			h := NewAuthHandler(cfg, newAuthUC(cfg, store))

			req := postJSON("/api/v1/register-admin", validRegBody())
			if tt.token != "" {
				req.Header.Set("X-Admin-Token", tt.token)
			}

			rec := httptest.NewRecorder()
			h.RegisterAdmin(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("Статус = %d, ожидается: 403; body = %s", rec.Code, rec.Body.String())
			}
			assertMessage(t, rec, messages.InvalidAdminToken)
			// Пользователь не должен создаться в хранилище.
			if _, err := store.GetByEmail(req.Context(), "user@example.com"); err == nil {
				t.Error("Пользователь не должен создаваться при невалидном admin-токене")
			}
		})
	}
}

// TestRegisterAdmin_ValidationRunsFirst — валидация полей выполняется ДО проверки
// admin-токена: битое тело дает 400 даже без токена (не раскрываем порядок проверок).
func TestRegisterAdmin_ValidationRunsFirst(t *testing.T) {
	store := newMockStore()
	h := NewAuthHandler(testConfig(), newAuthUC(testConfig(), store))

	body := validRegBody()
	body["password"] = "short"

	rec := httptest.NewRecorder()
	h.RegisterAdmin(rec, postJSON("/api/v1/register-admin", body)) // без X-Admin-Token

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Статус = %d, ожидается: 400 (валидация раньше проверки токена); body = %s", rec.Code, rec.Body.String())
	}
	assertDetail(t, rec, "password")
}

// ---------------------------------------------------------------------------
// ВХОД (LOGIN)
// ---------------------------------------------------------------------------

// seedUser создает пользователя с хешем bcrypt.MinCost (быстро) для большинства тестов.
func seedUser(t *testing.T, store *mockStore, email, password, role string) *domain.User {
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
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	rec := httptest.NewRecorder()
	h.Login(rec, postJSON("/api/v1/login", map[string]string{
		"email":    "User@Example.com", // регистр не важен
		"password": "StrongPass123",
	}))

	if rec.Code != http.StatusOK {
		t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	assertMessage(t, rec, messages.AuthorizationSuccessful)

	cookies := rec.Result().Cookies()
	cm := cookieMap(cookies)
	access, refresh := cm[auth.AccessCookie], cm[auth.RefreshCookie]
	if access == "" || refresh == "" {
		t.Fatalf("Не установлены Cookie токенов: %v", cm)
	}

	// Безопасные атрибуты cookie токенов.
	for _, c := range cookies {
		if c.Name == auth.AccessCookie || c.Name == auth.RefreshCookie {
			if !c.HttpOnly {
				t.Errorf("Cookie %s должна быть HttpOnly", c.Name)
			}
			if c.Path != "/api/v1/" {
				t.Errorf("Cookie %s: path = %q, ожидается: /api/v1/", c.Name, c.Path)
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Errorf("Cookie %s: SameSite = %v, ожидается: Lax", c.Name, c.SameSite)
			}
		}
	}

	// Токены валидны и имеют правильное назначение.
	if _, err := auth.Parse(cfg, access, "access"); err != nil {
		t.Errorf("Access-токен не разбирается: %v", err)
	}
	if _, err := auth.Parse(cfg, refresh, "refresh"); err != nil {
		t.Errorf("Refresh-токен не разбирается: %v", err)
	}
	// Атака: access-токен не должен приниматься как refresh и наоборот.
	if _, err := auth.Parse(cfg, access, "refresh"); err == nil {
		t.Error("Access-токен не должен приниматься как refresh")
	}
	if _, err := auth.Parse(cfg, refresh, "access"); err == nil {
		t.Error("Refresh-токен не должен приниматься как access")
	}

	// Refresh-токен сохранен в хранилище (по хешу).
	if _, err := store.GetActive(nilCtx(), auth.HashToken(refresh)); err != nil {
		t.Errorf("Refresh-токен не сохранен в хранилище: %v", err)
	}

	// Утечка данных: хеш пароля не попадает в ответ.
	if strings.Contains(rec.Body.String(), "password_hash") || strings.Contains(rec.Body.String(), "$2a$") {
		t.Errorf("В ответе login присутствует хеш пароля: %s", rec.Body.String())
	}
}

// TestLogin_InvalidCredentials — неверный пароль / неизвестный email / заблокированный
// пользователь: всегда 401 с одинаковым сообщением (без перечисления пользователей).
func TestLogin_InvalidCredentials(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)
	inactive := seedUser(t, store, "blocked@example.com", "StrongPass123", domain.RoleUser)
	inactive.Status = domain.StatusInactive

	tests := []struct {
		name     string
		email    string
		password string
	}{
		{name: "Неверный пароль", email: "user@example.com", password: "WrongPass123"},
		{name: "Неизвестный email", email: "ghost@example.com", password: "StrongPass123"},
		{name: "Заблокированный пользователь (status=inactive)", email: "blocked@example.com", password: "StrongPass123"},
		{name: "Пустой пароль", email: "user@example.com", password: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.Login(rec, postJSON("/api/v1/login", map[string]string{"email": tt.email, "password": tt.password}))

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("Статус = %d, ожидается: 401; body = %s", rec.Code, rec.Body.String())
			}
			assertMessage(t, rec, messages.InvalidCredentials)
			// Токены не выдаются.
			cm := cookieMap(rec.Result().Cookies())
			if cm[auth.AccessCookie] != "" || cm[auth.RefreshCookie] != "" {
				t.Error("При ошибочном входе Cookie токенов устанавливаться не должны")
			}
		})
	}
}

// TestLogin_BodyLimits — защита от переполнения: email > 255 или пароль > 72 -> 400,
// битый JSON -> 400.
func TestLogin_BodyLimits(t *testing.T) {
	store := newMockStore()
	h := NewAuthHandler(testConfig(), newAuthUC(testConfig(), store))

	tests := []struct {
		name string
		body string
	}{
		{name: "Email длиннее 255", body: `{"email":"` + strings.Repeat("a", 250) + `@x.com","password":"StrongPass123"}`},
		{name: "Пароль длиннее 72", body: `{"email":"u@e.com","password":"` + strings.Repeat("a", 73) + `"}`},
		{name: "Битый JSON", body: `{"email":`},
		{name: "Неизвестное поле", body: `{"email":"u@e.com","password":"StrongPass123","admin":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.Login(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("Статус = %d, ожидается: 400; body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestLogin_TimingAttackProtection тестирует защиту от timing-атак: время ответа
// должно быть одинаковым для существующего пользователя с неверным паролем
// и для несуществующего пользователя. Разница во времени не должна раскрывать
// существование учетной записи.
func TestLogin_TimingAttackProtection(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))

	// Создаем пользователя с реальным bcrypt-хешем боевой стоимости.
	realHash, err := bcrypt.GenerateFromPassword([]byte("CorrectPass123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	store.seedUser(&domain.User{
		ID: uuid.New(), Email: "exists@example.com", PasswordHash: string(realHash),
		Role: domain.RoleUser, Status: domain.StatusActive, FirstName: "E", LastName: "X",
	})

	// measure выполняет N итераций и возвращает среднее время для статистической устойчивости.
	measure := func(email string) time.Duration {
		const iterations = 10
		var total time.Duration
		for i := 0; i < iterations; i++ {
			rec := httptest.NewRecorder()
			start := time.Now()
			h.Login(rec, postJSON("/api/v1/login", map[string]string{
				"email":    email,
				"password": "WrongPass123",
			}))
			total += time.Since(start)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("Итерация %d: статус = %d, ожидается: 401 для %s", i, rec.Code, email)
			}
		}
		return total / iterations
	}

	// Проверяем, что фиктивный хеш валидный (иначе bcrypt не будет работать).
	// DummyHash больше не экспортируется слоем use-case (bcrypt вынесен в
	// инфраструктуру), поэтому проверяем эквивалентный хеш через тот же
	// инфраструктурный PasswordHasher, который внедряется в AuthUseCase.
	dummyHash, err := auth.NewBcryptHasher().Hash("dummy-password-for-timing-attack-protection")
	if err != nil {
		t.Fatalf("Хеширование dummy-пароля: %v", err)
	}
	if len(dummyHash) < 50 || !strings.HasPrefix(dummyHash, "$2a$") {
		t.Fatalf("DummyHash невалиден: %q (должен быть валидным bcrypt-хешем)", dummyHash)
	}

	// Измеряем среднее время для обеих веток.
	dExists := measure("exists@example.com")
	dMissing := measure("no-such-user@example.com")

	t.Logf("Среднее время ответа: exists = %v, missing = %v", dExists, dMissing)

	// Обе ветки обязаны пройти bcrypt (иначе сравнение было бы мгновенным).
	// Порог 10ms выбран с запасом: реальный bcrypt с DefaultCost занимает 20-100ms.
	const minBcryptDuration = 10 * time.Millisecond
	if dExists < minBcryptDuration {
		t.Errorf("Существующий пользователь: bcrypt не выполнен (время = %v < %v)", dExists, minBcryptDuration)
	}
	if dMissing < minBcryptDuration {
		t.Errorf("Несуществующий пользователь: bcrypt не выполнен (время = %v < %v)", dMissing, minBcryptDuration)
	}

	// Проверяем, что времена сопоставимы (расхождение не более чем в 3 раза).
	// Это мягкая проверка: в CI время может варьироваться из-за нагрузки.
	ratio := float64(dExists) / float64(dMissing)
	if ratio > 3.0 || ratio < 1.0/3.0 {
		t.Errorf("Расхождение времен слишком велико: exists = %v, missing = %v, ratio = %.2f (должно быть 0.33..3.0)",
			dExists, dMissing, ratio)
	}

	// Дополнительно: проверяем, что оба запроса возвращают одинаковое сообщение об ошибке
	// (не раскрываем существование пользователя через разные сообщения).
	rec1 := httptest.NewRecorder()
	h.Login(rec1, postJSON("/api/v1/login", map[string]string{"email": "exists@example.com", "password": "WrongPass123"}))
	rec2 := httptest.NewRecorder()
	h.Login(rec2, postJSON("/api/v1/login", map[string]string{"email": "ghost@example.com", "password": "WrongPass123"}))

	if rec1.Body.String() != rec2.Body.String() {
		t.Errorf("Ответы различаются (раскрытие существования пользователя):\nexists: %s\nmissing: %s",
			rec1.Body.String(), rec2.Body.String())
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
		t.Fatalf("Вход: статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	return cookieMap(rec.Result().Cookies())
}

// refreshRequest создает запрос /refresh с указанным refresh-токеном в cookie.
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
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	cm := loginCookies(t, h, "user@example.com", "StrongPass123")
	oldRefresh := cm[auth.RefreshCookie]

	rec := httptest.NewRecorder()
	h.Refresh(rec, refreshRequest(oldRefresh))

	if rec.Code != http.StatusOK {
		t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	assertMessage(t, rec, messages.TokensRefreshed)

	rotated := cookieMap(rec.Result().Cookies())
	newAccess, newRefresh := rotated[auth.AccessCookie], rotated[auth.RefreshCookie]
	if newRefresh == "" || newRefresh == oldRefresh {
		t.Fatal("Ротация не произошла: refresh-токен не сменился")
	}
	if newAccess == "" || newAccess == cm[auth.AccessCookie] {
		t.Error("Access-токен также должен быть перевыпущен")
	}

	// Старый токен отозван в хранилище (условный UPDATE внутри транзакции).
	oldRec, err := store.GetActive(nilCtx(), auth.HashToken(oldRefresh))
	if err == nil && !oldRec.Revoked {
		t.Error("Старый refresh-токен должен быть отозван после ротации")
	}
	// Новый токен активен.
	if _, err := store.GetActive(nilCtx(), auth.HashToken(newRefresh)); err != nil {
		t.Errorf("Новый refresh-токен не активен: %v", err)
	}
}

// TestRefresh_ReplayAttack — АТАКА: повторное использование украденного старого
// refresh-токена. Ожидаем 401 и ПОЛНЫЙ отзыв всех сессий пользователя (даже новых).
func TestRefresh_ReplayAttack(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	u := seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	cm := loginCookies(t, h, "user@example.com", "StrongPass123")
	oldRefresh := cm[auth.RefreshCookie]

	// Легитимная ротация: получаем новую пару.
	rec := httptest.NewRecorder()
	h.Refresh(rec, refreshRequest(oldRefresh))
	if rec.Code != http.StatusOK {
		t.Fatalf("Ротация: статус = %d, ожидается: 200", rec.Code)
	}
	newRefresh := cookieMap(rec.Result().Cookies())[auth.RefreshCookie]

	// Атакующий переиспользует старый токен -> детект replay.
	rec = httptest.NewRecorder()
	h.Refresh(rec, refreshRequest(oldRefresh))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Replay: статус = %d, ожидается: 401; body = %s", rec.Code, rec.Body.String())
	}
	assertMessage(t, rec, messages.InvalidOrExpiredRefreshToken)

	// Все сессии пользователя отозваны: даже свежий легитимный токен мертв.
	rec = httptest.NewRecorder()
	h.Refresh(rec, refreshRequest(newRefresh))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("После replay все сессии должны быть отозваны: статус = %d, ожидается: 401", rec.Code)
	}
	store.mu.Lock()
	for hash, tk := range store.tokens {
		_ = hash
		if tk.UserID == u.ID && !tk.Revoked {
			t.Errorf("Токен %s пользователя не отозван после replay-атаки", tk.TokenHash[:8])
		}
	}
	store.mu.Unlock()
}

// TestRefresh_RejectCases — негативные кейсы: нет cookie, мусор, access вместо refresh,
// просроченный токен, токен не из хранилища, заблокированный пользователь.
func TestRefresh_RejectCases(t *testing.T) {
	cfg := testConfig()

	t.Run("Отсутствует Cookie refresh_token", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, newAuthUC(cfg, store))
		rec := httptest.NewRecorder()
		h.Refresh(rec, refreshRequest(""))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Статус = %d, ожидается: 401", rec.Code)
		}
		// Cookie токенов очищаются даже при отказе.
		for _, c := range rec.Result().Cookies() {
			if (c.Name == auth.AccessCookie || c.Name == auth.RefreshCookie) && c.MaxAge != -1 {
				t.Errorf("Cookie %s должна быть удалена при отказе", c.Name)
			}
		}
	})

	t.Run("Мусорный токен", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, newAuthUC(cfg, store))
		rec := httptest.NewRecorder()
		h.Refresh(rec, refreshRequest("not.a.jwt"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Статус = %d, ожидается: 401", rec.Code)
		}
	})

	t.Run("Access-токен вместо refresh (проверка audience)", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, newAuthUC(cfg, store))
		seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)
		cm := loginCookies(t, h, "user@example.com", "StrongPass123")

		rec := httptest.NewRecorder()
		h.Refresh(rec, refreshRequest(cm[auth.AccessCookie])) // подмена назначения
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Статус = %d, ожидается: 401", rec.Code)
		}
	})

	t.Run("Просроченный, но корректно подписанный токен", func(t *testing.T) {
		expCfg := testConfig()
		expCfg.RefreshTTL = -time.Hour // токен родился уже просроченным
		store := newMockStore()
		h := NewAuthHandler(expCfg, newAuthUC(expCfg, store))
		u := seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)
		pair, err := auth.IssuePair(expCfg, u.ID, u.Email, u.Role)
		if err != nil {
			t.Fatal(err)
		}

		rec := httptest.NewRecorder()
		h.Refresh(rec, refreshRequest(pair.RefreshToken))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Статус = %d, ожидается: 401 для просроченного токена", rec.Code)
		}
	})

	t.Run("Валидный JWT, но неизвестный хранилищу токен", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, newAuthUC(cfg, store))
		u := seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)
		pair, _ := auth.IssuePair(cfg, u.ID, u.Email, u.Role) // в store не сохраняли

		rec := httptest.NewRecorder()
		h.Refresh(rec, refreshRequest(pair.RefreshToken))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Статус = %d, ожидается: 401 для неизвестного токена", rec.Code)
		}
	})

	t.Run("Refresh для заблокированного пользователя отзывает его сессии", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, newAuthUC(cfg, store))
		u := seedUser(t, store, "blocked@example.com", "StrongPass123", domain.RoleUser)
		pair, _ := auth.IssuePair(cfg, u.ID, u.Email, u.Role)
		_ = store.Store(nilCtx(), u.ID, auth.HashToken(pair.RefreshToken), pair.RefreshExp)
		u.Status = domain.StatusInactive // блокировка админом после выдачи токена

		rec := httptest.NewRecorder()
		h.Refresh(rec, refreshRequest(pair.RefreshToken))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Статус = %d, ожидается: 401 для inactive-пользователя", rec.Code)
		}
		if _, err := store.GetActive(nilCtx(), auth.HashToken(pair.RefreshToken)); err == nil {
			t.Error("Сессии заблокированного пользователя должны быть отозваны")
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

	t.Run("Выход с активным refresh-токеном", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, newAuthUC(cfg, store))
		seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)
		cm := loginCookies(t, h, "user@example.com", "StrongPass123")
		refresh := cm[auth.RefreshCookie]

		rec := httptest.NewRecorder()
		h.Logout(rec, refreshRequest(refresh))

		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200", rec.Code)
		}
		assertMessage(t, rec, messages.LoggedOut)
		if _, err := store.GetActive(nilCtx(), auth.HashToken(refresh)); err == nil {
			t.Error("Refresh-токен должен быть отозван при выходе")
		}
		for _, c := range rec.Result().Cookies() {
			if (c.Name == auth.AccessCookie || c.Name == auth.RefreshCookie) && c.MaxAge != -1 {
				t.Errorf("Cookie %s должна быть удалена при выходе", c.Name)
			}
		}
	})

	t.Run("Выход без Cookie также возвращает 200", func(t *testing.T) {
		store := newMockStore()
		h := NewAuthHandler(cfg, newAuthUC(cfg, store))
		rec := httptest.NewRecorder()
		h.Logout(rec, httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200", rec.Code)
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
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/csrf", nil)
	req.Header.Set("Origin", "https://app.example")
	rec := httptest.NewRecorder()
	h.CSRFToken(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Статус = %d, ожидается: 200", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	token := body["csrf_token"]
	if token == "" {
		t.Fatal("Тело ответа не содержит csrf_token")
	}
	cm := cookieMap(rec.Result().Cookies())
	if cm["csrf_token"] != token {
		t.Error("Значение CSRF-токена в cookie и в теле должно совпадать")
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			if c.HttpOnly {
				t.Error("CSRF Cookie обязана быть читаемой из JS (HttpOnly=false)")
			}
			if c.MaxAge != 3600 {
				t.Errorf("MaxAge CSRF Cookie = %d, ожидается: 3600", c.MaxAge)
			}
		}
	}
}

// TestCSRFMiddlewareBlocksStateChangingRequests — атака CSRF: POST без токена,
// с поддельным токеном и с токеном только в header (без cookie) -> 403.
func TestCSRFMiddlewareBlocksStateChangingRequests(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	chain := middleware.CSRF(cfg)(http.HandlerFunc(h.Register))

	t.Run("POST без CSRF-токена", func(t *testing.T) {
		req := postJSON("/api/v1/register", validRegBody())
		req.Header.Set("Origin", "https://app.example")
		// Имитация браузера жертвы: csrf_token cookie отправляется автоматически,
		// но X-CSRF-Token (читается JS с evil.com невозможно) отсутствует.
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "some.csrf.value"})
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("Статус = %d, ожидается: 403", rec.Code)
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
			t.Fatalf("Статус = %d, ожидается: 403", rec.Code)
		}
	})

	t.Run("POST с токеном только в header (cookie не совпадает)", func(t *testing.T) {
		token, _ := middleware.IssueCSRF(cfg.JWTSecret)
		req := postJSON("/api/v1/register", validRegBody())
		req.Header.Set("Origin", "https://app.example")
		// Браузер всегда прикладывает csrf_token cookie; подставим значение,
		// не совпадающее с заголовком — double-submit должен дать 403.
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "stale.or.other.value"})
		req.Header.Set("X-CSRF-Token", token)
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("Статус = %d, ожидается: 403", rec.Code)
		}
	})

	t.Run("POST с токеном только в Cookie (без Header)", func(t *testing.T) {
		token, _ := middleware.IssueCSRF(cfg.JWTSecret)
		req := postJSON("/api/v1/register", validRegBody())
		req.Header.Set("Origin", "https://app.example")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("Статус = %d, ожидается: 403", rec.Code)
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
			t.Fatalf("Статус = %d, ожидается: 403", rec.Code)
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
	authH := NewAuthHandler(cfg, newAuthUC(cfg, store))
	userH := NewUserHandler(testConfig(), newUserUC(store))
	const origin = "https://app.example"

	// ШАГ 1. Получаем CSRF-токен (cookie + тело ответа).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/csrf", nil)
	req.Header.Set("Origin", origin)
	authH.CSRFToken(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("CSRF: Статус = %d, ожидается: 200", rec.Code)
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
		t.Fatalf("Register: статус = %d, ожидается: 201; body = %s", rec.Code, rec.Body.String())
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
		t.Fatalf("Login: статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	cm := cookieMap(rec.Result().Cookies())
	access, refresh := cm[auth.AccessCookie], cm[auth.RefreshCookie]
	if access == "" || refresh == "" {
		t.Fatal("Login не установил Access/Refresh Cookie")
	}

	// ШАГ 4. Аутентифицированный запрос GET /users/me по access-токену.
	meReq := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	meReq.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: access})
	rec = httptest.NewRecorder()
	middleware.Authenticate(cfg, store)(
		middleware.RequireUserOrAdmin(http.HandlerFunc(userH.Me)),
	).ServeHTTP(rec, meReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("Me: Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}

	// ШАГ 5. Refresh: ротация — cookie заменяются новой парой.
	rec = httptest.NewRecorder()
	authH.Refresh(rec, refreshRequest(refresh))
	if rec.Code != http.StatusOK {
		t.Fatalf("Refresh: статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	rotated := cookieMap(rec.Result().Cookies())
	refresh2 := rotated[auth.RefreshCookie]
	if refresh2 == "" || refresh2 == refresh {
		t.Fatal("Ротация не произошла: refresh-токен не сменился")
	}

	// ШАГ 6. АТАКА (replay): злоумышленник переиспользует украденный старый refresh.
	rec = httptest.NewRecorder()
	authH.Refresh(rec, refreshRequest(refresh))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Replay: статус = %d, ожидается: 401", rec.Code)
	}

	// ШАГ 7. После детекта replay все сессии отозваны: новый токен тоже не работает.
	rec = httptest.NewRecorder()
	authH.Refresh(rec, refreshRequest(refresh2))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("После replay сессии должны быть отозваны: статус = %d, ожидается: 401", rec.Code)
	}

	// ШАГ 8. Logout очищает cookie токенов (MaxAge = -1).
	rec = httptest.NewRecorder()
	authH.Logout(rec, httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("Logout: статус = %d, ожидается: 200", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if (c.Name == auth.AccessCookie || c.Name == auth.RefreshCookie) && c.MaxAge != -1 {
			t.Errorf("Cookie %s не удалена при logout (MaxAge = %d)", c.Name, c.MaxAge)
		}
	}
}
