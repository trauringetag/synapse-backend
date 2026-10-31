package tests

// Интеграционные тесты HTTP-транспорта: реальный роутер (router.New) со всеми
// middleware (CSRF, Origin, Authenticate, RateLimit) гоняется поверх in-memory
// mockStore без PostgreSQL. Покрываются сценарии:
//   - TestIntegration_WebClient_LoginAndAccess — cookie + CSRF, полный flow;
//   - TestIntegration_MobileClient_LoginAndAccess — Bearer без CSRF, полный flow;
//   - TestIntegration_MobileClient_NoCSRFRequired — мобильный без CSRF не получает 403;
//   - TestIntegration_WebClient_CSRFRequired — веб без CSRF получает 403;
//   - TestIntegration_MobileClient_RefreshFlow — ротация через Bearer;
//   - TestIntegration_MobileClient_ReplayAttack_RevokesAllSessions — replay отзывает все сессии;
//   - TestIntegration_WebClient_BackwardCompatibility — существующий веб-flow не сломан;
//   - TestIntegration_PlatformHeaderSpoofing_CookieRequest_StillRequiresCSRF —
//     подделка X-Client-Platform не отключает CSRF для cookie-запроса.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	auth "github.com/trauringetag/synapse-backend/internal/infrastructure/security"
	router "github.com/trauringetag/synapse-backend/internal/infrastructure/transport"
	"github.com/trauringetag/synapse-backend/internal/usecase"
)

// ---------------------------------------------------------------------------
// Тестовый стек
// ---------------------------------------------------------------------------

type testEnv struct {
	srv    http.Handler
	store  *mockStore
	limits *fakeRateLimiter
	cfg    *config.Config
}

// fakeRateLimiter — in-memory реализация domain.RateLimitStore с очень
// высокими лимитами: в интеграционных тестах нас интересует бизнес-логика,
// а не сами счётчики (работа RefreshKey покрыта unit-тестами middleware).
type fakeRateLimiter struct {
	hits map[string]int
}

func newFakeRateLimiter() *fakeRateLimiter {
	return &fakeRateLimiter{hits: map[string]int{}}
}

func (f *fakeRateLimiter) Increment(_ context.Context, key string, _ time.Duration) (int, error) {
	f.hits[key]++
	return f.hits[key], nil
}

func (f *fakeRateLimiter) Cleanup(_ context.Context, _ time.Duration) error { return nil }

var _ domain.RateLimitStore = (*fakeRateLimiter)(nil)

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	cfg := &config.Config{
		AppEnv:                 "synapse-test",
		JWTSecret:              []byte("integration-test-secret-at-least-32-bytes"),
		AccessTTL:              15 * time.Minute,
		RefreshTTL:             168 * time.Hour,
		AdminRegisterToken:     "admin-token-123",
		CookieSecure:           false,
		CookieSameSite:         http.SameSiteLaxMode,
		CookiePath:             "/api/v1/",
		CORSOrigins:            []string{"https://app.example.com"},
		LoginRateLimit:         1000,
		RegisterRateLimit:      1000,
		RefreshRateLimit:       1000,
		LogoutRateLimit:        1000,
		AuthenticatedRateLimit: 1000,
	}
	store := newMockStore()
	limits := newFakeRateLimiter()

	hasher := auth.NewBcryptHasher()
	authUC := usecase.NewAuthUseCase(store, store, hasher, auth.NewJWTService(cfg), auth.NewCSRFService(cfg), cfg.AdminRegisterToken)
	userUC := usecase.NewUserUseCase(store, store, hasher)

	srv := router.New(cfg, authUC, userUC, store, limits, []byte("openapi: 3.0.3"))
	return &testEnv{srv: srv, store: store, limits: limits, cfg: cfg}
}

const (
	testEmail    = "ada@example.com"
	testPassword = "Str0ng-Passw0rd!"
	// login/register/refresh/logout защищены middleware.CSRF: даже без cookie
	// запрос обязан нести разрешённый Origin (CSRF требует его до проверки токена).
	webOrigin = "https://app.example.com"
)

// // csrfPair выдаёт валидную CSRF-пару (значение одинаково в cookie csrf_token
// // и заголовке X-CSRF-Token — как это делает браузер после GET /csrf).
// func csrfPair(t *testing.T, cfg *config.Config) string {
// 	t.Helper()
// 	v, err := auth.IssueCSRF(cfg.JWTSecret)
// 	if err != nil {
// 		t.Fatalf("issue csrf: %v", err)
// 	}
// 	return v
// }

// // postJSON выполняет POST с JSON-телом и произвольными заголовками.
// func (e *testEnv) postJSON(t *testing.T, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
// 	t.Helper()
// 	var rdr io.Reader
// 	if body != nil {
// 		b, err := json.Marshal(body)
// 		if err != nil {
// 			t.Fatalf("marshal: %v", err)
// 		}
// 		rdr = bytes.NewReader(b)
// 	}
// 	req := httptest.NewRequest(http.MethodPost, path, rdr)
// 	if body != nil {
// 		req.Header.Set("Content-Type", "application/json")
// 	}
// 	for k, v := range headers {
// 		switch k {
// 		case "Cookie":
// 			req.Header.Add(k, v) // cookie-заголовки накапливаются
// 		default:
// 			req.Header.Set(k, v)
// 		}
// 	}
// 	rec := httptest.NewRecorder()
// 	e.srv.ServeHTTP(rec, req)
// 	return rec
// }

// // webAuthHeaders — заголовки веб-клиента для state-changing эндпоинтов под
// // защитой CSRF: разрешённый Origin + CSRF-пара (cookie csrf_token +
// // заголовок X-CSRF-Token).
// func (e *testEnv) webAuthHeaders(t *testing.T) map[string]string {
// 	csrf := csrfPair(t, e.cfg)
// 	return map[string]string{
// 		"Origin":       webOrigin,
// 		"Cookie":       "csrf_token=" + csrf,
// 		"X-CSRF-Token": csrf,
// 	}
// }

// // mobileAuthHeaders — заголовки мобильного клиента: только декларация
// // платформы; Bearer/cookie/CSRF не требуются (безопасность определяется
// // фактическим способом аутентификации, а не заголовком).
// func mobileAuthHeaders() map[string]string {
// 	return map[string]string{"X-Client-Platform": "mobile"}
// }

// registerUser создаёт пользователя напрямую через mockStore (bcrypt-хеш),
// минуя HTTP /register: интеграционные тесты фокусируются на flows
// логина/refresh/logout, а регистрация покрыта отдельными тестами.
func (e *testEnv) registerUser(t *testing.T, email string) *domain.User {
	return e.registerUserWithRole(t, email, domain.RoleUser)
}

func (e *testEnv) registerUserWithRole(t *testing.T, email, role string) *domain.User {
	t.Helper()
	hash, err := auth.NewBcryptHasher().Hash(testPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u, err := e.store.Create(context.Background(), email, hash, role, "Ada", "Lovelace")
	if err != nil {
		t.Fatalf("store create %s: %v", email, err)
	}
	return u
}

// mobileLogin выполняет POST /api/v1/login от имени мобильного клиента.
// Если пользователь ещё не существует — он создаётся напрямую через
// mockStore (bcrypt-хеш), что эквивалентно успешной регистрации: тесты
// фокусируются на flows логина/refresh/logout, а мобильная регистрация
// покрыта TestIntegration_MobileClient_LoginAndAccess. Безопасность
// (отсутствие CSRF/Origin) определяется фактическим способом
// аутентификации, а не заголовком X-Client-Platform.
func (e *testEnv) mobileLogin(t *testing.T, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	if _, err := e.store.GetByEmail(context.Background(), email); err != nil {
		e.registerUser(t, email) // пароль в моке всегда testPassword
	}
	return e.doMobile(t, http.MethodPost, "/api/v1/login", "", map[string]any{
		"email": email, "password": password,
	})
}

// loginMobile — хелпер с телом запроса (см. mobileLogin).
func (e *testEnv) loginMobile(t *testing.T, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	email, _ := body["email"].(string)
	password, _ := body["password"].(string)
	return e.mobileLogin(t, email, password)
}

// loginWeb выполняет веб-логин от имени сессии s: CSRF-пара получается
// автоматически через doWeb (GET /csrf при необходимости), ответные cookie
// применяются к jar сессии. Платформа не заявляется — поведение по умолчанию
// (web), что проверяется тестом обратной совместимости.
func (e *testEnv) loginWeb(t *testing.T, s *webSession, body any) *httptest.ResponseRecorder {
	t.Helper()
	return e.doWeb(t, s, http.MethodPost, "/api/v1/login", body, nil)
}

// webSession логинит веб-клиента и возвращает jar cookie + CSRF-пару.
type webSession struct {
	jar        map[string]string // name -> value
	csrfCookie string
	csrfHeader string
}

func newWebSession() *webSession { return &webSession{jar: map[string]string{}} }

func (s *webSession) applyCookies(res *http.Response) {
	for _, c := range res.Cookies() {
		if c.MaxAge < 0 {
			delete(s.jar, c.Name) // сервер сбросил cookie
			continue
		}
		s.jar[c.Name] = c.Value
	}
	// CSRF-токен живёт в не-HttpOnly cookie csrf_token — синхронизируем пару.
	if v, ok := s.jar["csrf_token"]; ok {
		s.csrfCookie = v
		s.csrfHeader = v
	}
}

func (s *webSession) cookieHeader() string {
	parts := make([]string, 0, len(s.jar))
	for n, v := range s.jar {
		parts = append(parts, n+"="+v)
	}
	return strings.Join(parts, "; ")
}

// ensureCSRF гарантирует, что сессия имеет валидную CSRF-пару: если токен
// ещё не выдавался — получаем его через GET /api/v1/csrf (так же, как это
// делает браузер перед первой state-changing операцией). Вызывается из
// doWeb автоматически, поэтому тестовый код не может случайно отправить
// запрос «в обход» CSRF-протокола.
func (e *testEnv) ensureCSRF(t *testing.T, s *webSession) {
	t.Helper()
	if s.csrfHeader != "" {
		return
	}
	e.issueCSRF(t, s)
}

// do выполняет запрос от имени веб-клиента: cookie + Origin + CSRF-пара
// (cookie csrf_token + заголовок X-CSRF-Token — как делает браузер) для
// небезопасных методов.
func (e *testEnv) doWeb(t *testing.T, s *webSession, method, path string, body any, extraHeaders map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		// Браузер перед state-changing запросом уже получил CSRF-пару
		// (GET /csrf): cookie csrf_token лежит в jar, значение дублируется
		// в заголовке X-CSRF-Token.
		e.ensureCSRF(t, s)
	}
	if hdr := s.cookieHeader(); hdr != "" {
		req.Header.Add("Cookie", hdr)
	}
	req.Header.Set("Origin", webOrigin)
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		if s.csrfHeader != "" {
			req.Header.Set("X-CSRF-Token", s.csrfHeader)
		}
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	s.applyCookies(rec.Result())
	return rec
}

// doMobile выполняет запрос от имени мобильного клиента: Bearer (если token
// непустой) и X-Client-Platform: mobile. Cookie/CSRF не отправляются.
func (e *testEnv) doMobile(t *testing.T, method, path, bearer string, body any) *httptest.ResponseRecorder {
	return e.doMobileWithHeaders(t, method, path, bearer, body, nil)
}

// doMobileWithHeaders — то же, но с возможностью добавить заголовки
// (например X-Admin-Token для register-admin).
func (e *testEnv) doMobileWithHeaders(t *testing.T, method, path, bearer string, body any, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Client-Platform", "mobile")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	return rec
}

// issueCSRF получает CSRF-токен через GET /api/v1/csrf (безопасный метод).
func (e *testEnv) issueCSRF(t *testing.T, s *webSession) {
	t.Helper()
	rec := e.doWeb(t, s, http.MethodGet, "/api/v1/csrf", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/csrf: код %d, тело %s", rec.Code, rec.Body.String())
	}
	var out struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("/csrf decode: %v", err)
	}
	s.csrfHeader = out.CSRFToken
	if v, ok := s.jar["csrf_token"]; ok {
		s.csrfCookie = v
	}
}

type mobileTokens struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}

func decodeMobileTokens(t *testing.T, rec *httptest.ResponseRecorder) mobileTokens {
	t.Helper()
	var tr mobileTokens
	if err := json.Unmarshal(rec.Body.Bytes(), &tr); err != nil {
		t.Fatalf("decode tokenResponse: %v; body=%s", err, rec.Body.String())
	}
	return tr
}

// // globalBodyOK — страховка интеграционных тестов: успешные ответы не должны
// // попадать в счётчики rate limiter ("Слишком много запросов"). Если из-за
// // регрессии лимиты начнут считать по ответу (а не по телу запроса), тест
// // упадёт здесь явно, а не мутной ошибкой дальше по flow.
// func globalBodyOK(t *testing.T, rec *httptest.ResponseRecorder, what string) {
// 	t.Helper()
// 	body := rec.Body.String()
// 	if strings.Contains(body, "\u0421\u043b\u0438\u0448\u043a\u043e\u043c \u043c\u043d\u043e\u0433\u043e \u0437\u0430\u043f\u0440\u043e\u0441\u043e\u0432") || strings.Contains(body, "Too Many Requests") {
// 		t.Fatalf("%s: unexpected rate-limit response (код %d, тело %s)", what, rec.Code, body)
// 	}
// }

func assertNoSetCookie(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.AccessCookie || c.Name == auth.RefreshCookie {
			t.Errorf("мобильный ответ не должен устанавливать cookie %s", c.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// Веб-клиент: login -> /users/me -> refresh -> logout (cookie + CSRF)
// ---------------------------------------------------------------------------

func TestIntegration_WebClient_LoginAndAccess(t *testing.T) {
	e := newTestEnv(t)
	s := newWebSession()

	// Регистрация (веб-формат: без токенов в теле). CSRF-пара получается
	// заранее через GET /csrf — так же, как это делает браузер.
	e.issueCSRF(t, s)
	rec := e.doWeb(t, s, http.MethodPost, "/api/v1/register", map[string]any{
		"email": testEmail, "password": testPassword,
		"first_name": "Ada", "last_name": "Lovelace",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: код %d, тело %s", rec.Code, rec.Body.String())
	}
	var regBody map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &regBody)
	if _, ok := regBody["access_token"]; ok {
		t.Errorf("веб-ответ регистрации не должен содержать access_token")
	}
	if s.csrfHeader == "" {
		t.Fatalf("CSRF-токен не выдан")
	}

	// Логин: устанавливает HttpOnly cookie, токенов в теле нет.
	rec = e.loginWeb(t, s, map[string]any{"email": testEmail, "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: код %d, тело %s", rec.Code, rec.Body.String())
	}
	var loginBody map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &loginBody)
	if _, ok := loginBody["access_token"]; ok {
		t.Errorf("веб-ответ логина не должен содержать access_token (риск XSS)")
	}
	if _, ok := s.jar[auth.AccessCookie]; !ok {
		t.Errorf("веб-логин должен установить cookie access_token")
	}
	if _, ok := s.jar[auth.RefreshCookie]; !ok {
		t.Errorf("веб-логин должен установить cookie refresh_token")
	}

	// Доступ к защищённому эндпоинту по cookie.
	rec = e.doWeb(t, s, http.MethodGet, "/api/v1/users/me", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /users/me: код %d, тело %s", rec.Code, rec.Body.String())
	}
	var me map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatalf("decode me: %v", err)
	}
	if me["email"] != testEmail {
		t.Errorf("email = %v, ожидается %s", me["email"], testEmail)
	}

	// Refresh по cookie: новые cookie, тело без токенов.
	oldRefresh := s.jar[auth.RefreshCookie]
	rec = e.doWeb(t, s, http.MethodPost, "/api/v1/refresh", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: код %d, тело %s", rec.Code, rec.Body.String())
	}
	if s.jar[auth.RefreshCookie] == oldRefresh {
		t.Errorf("refresh должен ротировать cookie refresh_token")
	}

	// Logout: cookie сброшены, профиль недоступен.
	rec = e.doWeb(t, s, http.MethodPost, "/api/v1/logout", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout: код %d, тело %s", rec.Code, rec.Body.String())
	}
	rec = e.doWeb(t, s, http.MethodGet, "/api/v1/users/me", nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("после logout /users/me: код %d, ожидается 401", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Мобильный клиент: login -> /users/me -> refresh -> logout (Bearer, без CSRF)
// ---------------------------------------------------------------------------

func TestIntegration_MobileClient_LoginAndAccess(t *testing.T) {
	e := newTestEnv(t)

	body := map[string]any{"email": "mobile@example.com", "password": testPassword,
		"first_name": "Grace", "last_name": "Hopper"}

	// Регистрация мобильного пользователя: токены сразу в теле (пользователь входит).
	rec := e.doMobile(t, http.MethodPost, "/api/v1/register", "", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("mobile register: код %d, тело %s", rec.Code, rec.Body.String())
	}
	assertNoSetCookie(t, rec)
	tr := decodeMobileTokens(t, rec)
	if tr.AccessToken == "" || tr.RefreshToken == "" {
		t.Fatalf("мобильная регистрация должна вернуть токены: %+v", tr)
	}
	if tr.TokenType != "Bearer" {
		t.Errorf("token_type = %q, ожидается Bearer", tr.TokenType)
	}
	if tr.ExpiresIn <= 0 || tr.ExpiresIn > 900 {
		t.Errorf("expires_in = %d, ожидается (0, 900]", tr.ExpiresIn)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("ответ с токенами обязан иметь Cache-Control: no-store, получено %q", cc)
	}

	// Логин: тоже токены в теле.
	rec = e.loginMobile(t, map[string]any{"email": "mobile@example.com", "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("mobile login: код %d, тело %s", rec.Code, rec.Body.String())
	}
	assertNoSetCookie(t, rec)
	tr = decodeMobileTokens(t, rec)

	// /users/me по Bearer access-токену — без cookie, CSRF и Origin.
	rec = e.doMobile(t, http.MethodGet, "/api/v1/users/me", tr.AccessToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /users/me (Bearer): код %d, тело %s", rec.Code, rec.Body.String())
	}

	// Refresh по Bearer refresh-токену: новые токены в теле, cookie нет.
	rec = e.doMobile(t, http.MethodPost, "/api/v1/refresh", tr.RefreshToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("mobile refresh: код %d, тело %s", rec.Code, rec.Body.String())
	}
	assertNoSetCookie(t, rec)
	newTr := decodeMobileTokens(t, rec)
	if newTr.AccessToken == "" || newTr.RefreshToken == "" {
		t.Fatalf("refresh должен вернуть новые токены")
	}
	if newTr.RefreshToken == tr.RefreshToken {
		t.Errorf("refresh-токен должен ротироваться")
	}

	// Старый access всё ещё валиден до exp, старый refresh — уже отозван.
	rec = e.doMobile(t, http.MethodPost, "/api/v1/refresh", tr.RefreshToken, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("повторное использование старого refresh: код %d, ожидается 401", rec.Code)
	}

	// Logout мобильного: refresh из JSON-тела.
	rec = e.doMobile(t, http.MethodPost, "/api/v1/logout", "", map[string]any{"refresh_token": newTr.RefreshToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("mobile logout: код %d, тело %s", rec.Code, rec.Body.String())
	}
	// После logout refresh отозван.
	rec = e.doMobile(t, http.MethodPost, "/api/v1/refresh", newTr.RefreshToken, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("после logout refresh: код %d, ожидается 401", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// CSRF: мобильный (Bearer) не требует, веб (cookie) требует
// ---------------------------------------------------------------------------

func TestIntegration_MobileClient_NoCSRFRequired(t *testing.T) {
	e := newTestEnv(t)

	rec := e.loginMobile(t, map[string]any{"email": "nosfrf@example.com", "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: код %d, тело %s", rec.Code, rec.Body.String())
	}
	tr := decodeMobileTokens(t, rec)

	// PUT /users/me с Bearer, без CSRF-токена и без Origin — не 403.
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/me", strings.NewReader(
		`{"email":"nosfrf@example.com","first_name":"Ada","last_name":"L."}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-Platform", "mobile")
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	rec = httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("Bearer-запрос не должен требовать CSRF: %s", rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /users/me (Bearer): код %d, тело %s", rec.Code, rec.Body.String())
	}
}

func TestIntegration_WebClient_CSRFRequired(t *testing.T) {
	e := newTestEnv(t)

	s := newWebSession()
	rec := e.doWeb(t, s, http.MethodPost, "/api/v1/register", map[string]any{
		"email": "csrf@example.com", "password": testPassword,
		"first_name": "A", "last_name": "B",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: код %d, тело %s", rec.Code, rec.Body.String())
	}
	rec = e.loginWeb(t, s, map[string]any{"email": "csrf@example.com", "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: код %d, тело %s", rec.Code, rec.Body.String())
	}
	s.applyCookies(rec.Result())

	// PUT /users/me с cookie, но БЕЗ X-CSRF-Token -> 403.
	req := httptest.NewRequest(http.MethodPut, "/api/v1/users/me", strings.NewReader(`{"email":"csrf@example.com","first_name":"A","last_name":"C"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", webOrigin)
	req.Header.Add("Cookie", s.cookieHeader())
	rec = httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cookie-запрос без CSRF: код %d, ожидается 403; тело %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Refresh flow мобильного + replay-атака
// ---------------------------------------------------------------------------

func TestIntegration_MobileClient_RefreshFlow(t *testing.T) {
	e := newTestEnv(t)

	rec := e.loginMobile(t, map[string]any{"email": "flow@example.com", "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: код %d", rec.Code)
	}
	tr := decodeMobileTokens(t, rec)

	// Цепочка из трёх ротаций: каждый следующий refresh работает, предыдущий
	// отзывается. Повторная отправка prev детектируется как replay (401), что
	// по политике безопасности отзывает ВСЕ сессии пользователя — поэтому
	// проверка replay выполняется один раз в конце цепочки, после чего
	// легитимный клиент восстанавливается через повторный login.
	cur := tr.RefreshToken
	var prev string
	for i := 0; i < 3; i++ {
		prev = cur
		rec = e.doMobile(t, http.MethodPost, "/api/v1/refresh", prev, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("ротация %d: код %d, тело %s", i+1, rec.Code, rec.Body.String())
		}
		nt := decodeMobileTokens(t, rec)
		cur = nt.RefreshToken
		if cur == prev {
			t.Fatalf("ротация %d: refresh не изменился", i+1)
		}
	}

	// Replay самого старого токена цепочки -> 401 + отзыв всех сессий.
	rec = e.doMobile(t, http.MethodPost, "/api/v1/refresh", prev, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay prev: код %d, ожидается 401", rec.Code)
	}
	if n := e.store.ActiveTokenCount(); n != 0 {
		t.Fatalf("после replay не должно остаться активных сессий, есть %d", n)
	}

	// Альтернативный вход мобильного refresh: JSON-тело вместо Bearer.
	// После replay все сессии отозваны — выполняем свежий login.
	rec = e.loginMobile(t, map[string]any{"email": "flow@example.com", "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("re-login перед refresh через тело: код %d", rec.Code)
	}
	cur = decodeMobileTokens(t, rec).RefreshToken
	rec = e.doMobile(t, http.MethodPost, "/api/v1/refresh", "", map[string]any{"refresh_token": cur})
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh через тело: код %d, тело %s", rec.Code, rec.Body.String())
	}
	nt := decodeMobileTokens(t, rec)
	if nt.RefreshToken == cur {
		t.Errorf("refresh через тело должен ротировать токен")
	}
}

func TestIntegration_MobileClient_ReplayAttack_RevokesAllSessions(t *testing.T) {
	e := newTestEnv(t)

	rec := e.loginMobile(t, map[string]any{"email": "replay@example.com", "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: код %d", rec.Code)
	}
	tr := decodeMobileTokens(t, rec)
	stolen := tr.RefreshToken

	// Легитимная ротация: stolen отзывается, создаётся активный преемник.
	rec = e.doMobile(t, http.MethodPost, "/api/v1/refresh", stolen, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: код %d", rec.Code)
	}
	legit := decodeMobileTokens(t, rec)
	if e.store.ActiveTokenCount() != 1 {
		t.Fatalf("после ротации должен быть ровно 1 активный refresh, есть %d", e.store.ActiveTokenCount())
	}

	// Злоумышленник повторно отправляет украденный (уже отозванный) refresh —
	// replay-детект: 401 И отзыв ВСЕХ сессий пользователя.
	rec = e.doMobile(t, http.MethodPost, "/api/v1/refresh", stolen, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay: код %d, ожидается 401", rec.Code)
	}
	if n := e.store.ActiveTokenCount(); n != 0 {
		t.Errorf("replay-атака обязана отозвать все сессии, осталось активных: %d", n)
	}

	// Даже легитимный свежий refresh теперь отозван.
	rec = e.doMobile(t, http.MethodPost, "/api/v1/refresh", legit.RefreshToken, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("легитимный refresh после replay-детекта: код %d, ожидается 401", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Обратная совместимость веб-клиента (без X-Client-Platform вообще)
// ---------------------------------------------------------------------------

func TestIntegration_WebClient_BackwardCompatibility(t *testing.T) {
	e := newTestEnv(t)
	s := newWebSession()

	// Клиент не отправляет X-Client-Platform нигде — поведение как у web.
	rec := e.doWeb(t, s, http.MethodPost, "/api/v1/register", map[string]any{
		"email": "legacy@example.com", "password": testPassword,
		"first_name": "Old", "last_name": "Client",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: код %d, тело %s", rec.Code, rec.Body.String())
	}
	e.issueCSRF(t, s)

	rec = e.loginWeb(t, s, map[string]any{"email": "legacy@example.com", "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: код %d, тело %s", rec.Code, rec.Body.String())
	}
	if _, ok := s.jar[auth.AccessCookie]; !ok {
		t.Fatalf("логин без заголовка должен ставить cookie")
	}

	rec = e.doWeb(t, s, http.MethodGet, "/api/v1/users/me", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/users/me: код %d, тело %s", rec.Code, rec.Body.String())
	}

	rec = e.doWeb(t, s, http.MethodPatch, "/api/v1/users/me", map[string]any{"first_name": "NewName"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH /users/me: код %d, тело %s", rec.Code, rec.Body.String())
	}

	rec = e.doWeb(t, s, http.MethodPost, "/api/v1/refresh", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: код %d, тело %s", rec.Code, rec.Body.String())
	}
	var rb map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &rb)
	if _, ok := rb["access_token"]; ok {
		t.Errorf("веб-refresh не должен возвращать токены в теле")
	}

	rec = e.doWeb(t, s, http.MethodPost, "/api/v1/logout", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout: код %d, тело %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Подделка X-Client-Platform: cookie-запрос всё равно требует CSRF/Origin
// ---------------------------------------------------------------------------

func TestIntegration_PlatformHeaderSpoofing_CookieRequest_StillRequiresCSRF(t *testing.T) {
	e := newTestEnv(t)
	s := newWebSession()

	// Жертва вошла как обычный веб-клиент (cookie установлены, CSRF выдан).
	rec := e.doWeb(t, s, http.MethodPost, "/api/v1/register", map[string]any{
		"email": "victim@example.com", "password": testPassword,
		"first_name": "Vik", "last_name": "Tim",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: код %d", rec.Code)
	}
	e.issueCSRF(t, s)
	rec = e.loginWeb(t, s, map[string]any{"email": "victim@example.com", "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: код %d", rec.Code)
	}

	// Фишинговый сайт evil.com шлёт запрос ИЗ БРАУЗЕРА ЖЕРТВЫ: cookie
	// отправляются автоматически, заголовок X-Client-Platform: mobile
	// подделан, CSRF-заголовок отсутствует.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/me", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.Header.Set("X-Client-Platform", "mobile")
	req.Header.Add("Cookie", s.cookieHeader())
	rec = httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("подделка заголовка не должна обходить CSRF/Origin: код %d, тело %s",
			rec.Code, rec.Body.String())
	}

	// Вариант атаки с корректным Origin, но без CSRF-токена — тоже 403.
	req = httptest.NewRequest(http.MethodPut, "/api/v1/users/me", strings.NewReader(`{"email":"victim@example.com","first_name":"Evil","last_name":"Doer"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", webOrigin)
	req.Header.Set("X-Client-Platform", "mobile")
	req.Header.Add("Cookie", s.cookieHeader())
	rec = httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cookie + platform:mobile без CSRF: код %d, ожидается 403; тело %s", rec.Code, rec.Body.String())
	}

	// Профиль жертвы не изменён.
	rec = e.doWeb(t, s, http.MethodGet, "/api/v1/users/me", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/users/me: код %d", rec.Code)
	}
	var me map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if me["first_name"] != "Vik" {
		t.Errorf("данные жертвы изменены атакующим: %v", me["first_name"])
	}
}

// ---------------------------------------------------------------------------
// Прочие гарантии безопасности
// ---------------------------------------------------------------------------

// Мобильный ответ всегда содержит Cache-Control: no-store.
func TestIntegration_MobileResponses_HaveNoStoreCacheControl(t *testing.T) {
	e := newTestEnv(t)

	rec := e.loginMobile(t, map[string]any{"email": "cache@example.com", "password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: код %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, ожидается no-store", cc)
	}
}

// Неизвестная схема Authorization отклоняется на защищённом эндпоинте.
func TestIntegration_UnsupportedAuthScheme_Returns401(t *testing.T) {
	e := newTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Basic-схема: код %d, ожидается 401", rec.Code)
	}
}

// Админский flow мобильного клиента: register-admin с токенами в теле,
// доступ к /users только у admin.
func TestIntegration_MobileAdmin_Flow(t *testing.T) {
	e := newTestEnv(t)

	rec := e.doMobileWithHeaders(t, http.MethodPost, "/api/v1/register-admin", "", map[string]any{
		"email": "root@example.com", "password": testPassword,
		"first_name": "Root", "last_name": "Admin",
	}, map[string]string{"X-Admin-Token": e.cfg.AdminRegisterToken})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register-admin: код %d, тело %s", rec.Code, rec.Body.String())
	}
	tr := decodeMobileTokens(t, rec)

	rec = e.doMobile(t, http.MethodGet, "/api/v1/users", tr.AccessToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /users (admin Bearer): код %d, тело %s", rec.Code, rec.Body.String())
	}

	// Обычный пользователь не имеет доступа к списку.
	rec = e.loginMobile(t, map[string]any{"email": "plain@example.com", "password": testPassword})
	utr := decodeMobileTokens(t, rec)
	rec = e.doMobile(t, http.MethodGet, "/api/v1/users", utr.AccessToken, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /users (user Bearer): код %d, ожидается 403", rec.Code)
	}
}

// Компиляционная проверка: uuid используется (совпадение с портами мока).
var _ = uuid.New
