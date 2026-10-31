package handler

// Unit-тесты платформенно-зависимого формата ответов (X-Client-Platform) и
// мобильного Bearer-flow в HTTP-слое:
//   - /login, /refresh, /register, /register-admin: web -> cookie, mobile -> JSON-токены;
//   - обратная совместимость: отсутствие заголовка = web;
//   - /logout мобильного принимает refresh_token из JSON-тела;
//   - мобильный refresh через Authorization: Bearer <refresh_token>.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/middleware"
	auth "github.com/trauringetag/synapse-backend/internal/infrastructure/security"
	"github.com/trauringetag/synapse-backend/internal/messages"
)

// mobileRequest — POST с JSON-телом и заявленной мобильной платформой.
func mobileRequest(url string, body any) *http.Request {
	req := postJSON(url, body)
	req.Header.Set("X-Client-Platform", "mobile")
	return req
}

// decodeTokenResponse разбирает мобильный контракт ответа.
func decodeTokenResponse(t *testing.T, rec *httptest.ResponseRecorder) tokenResponse {
	t.Helper()
	var tr tokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &tr); err != nil {
		t.Fatalf("Не удалось декодировать tokenResponse: %v; body = %s", err, rec.Body.String())
	}
	return tr
}

// assertNoAuthCookies проверяет, что ответ не устанавливает cookie токенов
// (мобильный формат: токены живут только в JSON-теле).
func assertNoAuthCookies(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.AccessCookie || c.Name == auth.RefreshCookie {
			t.Errorf("Мобильный ответ не должен устанавливать cookie %s", c.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// LOGIN
// ---------------------------------------------------------------------------

func TestLogin_WebPlatform_SetsCookies(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	req := postJSON("/api/v1/login", map[string]string{"email": "user@example.com", "password": "StrongPass123"})
	req.Header.Set("X-Client-Platform", "web")
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	cm := cookieMap(rec.Result().Cookies())
	if cm[auth.AccessCookie] == "" || cm[auth.RefreshCookie] == "" {
		t.Errorf("Веб-вход не установил cookie токенов: %v", cm)
	}
	// Токенов в теле нет (риск XSS).
	if strings.Contains(rec.Body.String(), "access_token") || strings.Contains(rec.Body.String(), "refresh_token") {
		t.Errorf("Веб-ответ не должен содержать токены в теле: %s", rec.Body.String())
	}
	assertMessage(t, rec, messages.AuthorizationSuccessful)
}

func TestLogin_MobilePlatform_ReturnsTokensInBody(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	u := seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	rec := httptest.NewRecorder()
	h.Login(rec, mobileRequest("/api/v1/login", map[string]string{"email": "user@example.com", "password": "StrongPass123"}))

	if rec.Code != http.StatusOK {
		t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	tr := decodeTokenResponse(t, rec)
	if tr.TokenType != "Bearer" {
		t.Errorf("token_type = %q, ожидается: Bearer", tr.TokenType)
	}
	if tr.AccessToken == "" || tr.RefreshToken == "" {
		t.Fatal("Мобильный ответ не содержит токены")
	}
	if tr.ExpiresIn <= 0 || tr.ExpiresIn > 900 {
		t.Errorf("expires_in = %d, ожидается (0, 900]", tr.ExpiresIn)
	}
	if tr.RefreshExpiresIn <= 0 {
		t.Errorf("refresh_expires_in = %d, ожидается > 0", tr.RefreshExpiresIn)
	}
	if tr.User == nil || tr.User.ID != u.ID {
		t.Errorf("Профиль пользователя в мобильном ответе некорректен: %+v", tr.User)
	}
	assertNoAuthCookies(t, rec)
	// Refresh-токен сохранён в хранилище (по хешу).
	if _, err := store.GetActive(nilCtx(), auth.HashToken(tr.RefreshToken)); err != nil {
		t.Errorf("Refresh-токен не сохранён в хранилище: %v", err)
	}
	// Ответ с токенами обязан иметь Cache-Control: no-store (гарантирует middleware).
	recCC := httptest.NewRecorder()
	middleware.CacheControl(http.HandlerFunc(h.Login)).ServeHTTP(recCC,
		mobileRequest("/api/v1/login", map[string]string{"email": "user@example.com", "password": "StrongPass123"}))
	if cc := recCC.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control мобильного login = %q, ожидается no-store", cc)
	}
}

func TestLogin_NoPlatform_SetsCookies(t *testing.T) {
	// Обратная совместимость: клиент без X-Client-Platform ведёт себя как web.
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	rec := httptest.NewRecorder()
	h.Login(rec, postJSON("/api/v1/login", map[string]string{"email": "user@example.com", "password": "StrongPass123"}))

	if rec.Code != http.StatusOK {
		t.Fatalf("Статус = %d, ожидается: 200", rec.Code)
	}
	cm := cookieMap(rec.Result().Cookies())
	if cm[auth.AccessCookie] == "" || cm[auth.RefreshCookie] == "" {
		t.Error("Вход без заголовка платформы должен устанавливать cookie (обратная совместимость)")
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Error("Тело веб-ответа не должно содержать токены")
	}
}

// ---------------------------------------------------------------------------
// REFRESH
// ---------------------------------------------------------------------------

func TestRefresh_MobilePlatform_ReturnsTokensInBody(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	// Мобильный вход -> refresh-токен из JSON-ответа.
	rec := httptest.NewRecorder()
	h.Login(rec, mobileRequest("/api/v1/login", map[string]string{"email": "user@example.com", "password": "StrongPass123"}))
	oldRefresh := decodeTokenResponse(t, rec).RefreshToken

	// Ротация через Authorization: Bearer <refresh_token>.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req.Header.Set("X-Client-Platform", "mobile")
	req.Header.Set("Authorization", "Bearer "+oldRefresh)
	rec = httptest.NewRecorder()
	h.Refresh(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Refresh: статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	tr := decodeTokenResponse(t, rec)
	if tr.RefreshToken == "" || tr.RefreshToken == oldRefresh {
		t.Error("Ротация не произошла: refresh-токен не сменился")
	}
	if tr.AccessToken == "" {
		t.Error("Access-токен не перевыпущен")
	}
	assertNoAuthCookies(t, rec)
	// Старый refresh отозван (атомарная ротация).
	if r, err := store.GetActive(nilCtx(), auth.HashToken(oldRefresh)); err == nil && !r.Revoked {
		t.Error("Старый refresh-токен должен быть отозван после ротации")
	}
}

func TestRefresh_WebPlatform_SetsNewCookies(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	cm := loginCookies(t, h, "user@example.com", "StrongPass123")
	oldRefresh := cm[auth.RefreshCookie]

	req := refreshRequest(oldRefresh)
	req.Header.Set("X-Client-Platform", "web")
	rec := httptest.NewRecorder()
	h.Refresh(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	assertMessage(t, rec, messages.TokensRefreshed)
	rotated := cookieMap(rec.Result().Cookies())
	if rotated[auth.RefreshCookie] == "" || rotated[auth.RefreshCookie] == oldRefresh {
		t.Error("Веб-ротация не установила новый refresh-cookie")
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Error("Веб-ответ /refresh не должен содержать токены в теле")
	}
}

// ---------------------------------------------------------------------------
// LOGOUT
// ---------------------------------------------------------------------------

func TestLogout_MobilePlatform_AcceptsRefreshInBody(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	rec := httptest.NewRecorder()
	h.Login(rec, mobileRequest("/api/v1/login", map[string]string{"email": "user@example.com", "password": "StrongPass123"}))
	refresh := decodeTokenResponse(t, rec).RefreshToken

	// Logout мобильного клиента: refresh_token в JSON-теле (cookie нет).
	rec = httptest.NewRecorder()
	h.Logout(rec, mobileRequest("/api/v1/logout", map[string]string{"refresh_token": refresh}))

	if rec.Code != http.StatusOK {
		t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	assertMessage(t, rec, messages.LoggedOut)
	if _, err := store.GetActive(nilCtx(), auth.HashToken(refresh)); err == nil {
		t.Error("Refresh-токен не отозван при мобильном logout через тело")
	}
	assertNoAuthCookies(t, rec)

	// Logout мобильного через Bearer — тоже работает.
	rec = httptest.NewRecorder()
	h.Login(rec, mobileRequest("/api/v1/login", map[string]string{"email": "user@example.com", "password": "StrongPass123"}))
	refresh2 := decodeTokenResponse(t, rec).RefreshToken
	req := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	req.Header.Set("X-Client-Platform", "mobile")
	req.Header.Set("Authorization", "Bearer "+refresh2)
	rec = httptest.NewRecorder()
	h.Logout(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Bearer logout: статус = %d, ожидается: 200", rec.Code)
	}
	if _, err := store.GetActive(nilCtx(), auth.HashToken(refresh2)); err == nil {
		t.Error("Refresh-токен не отозван при logout через Bearer")
	}
}

// ---------------------------------------------------------------------------
// REGISTER / REGISTER-ADMIN
// ---------------------------------------------------------------------------

func TestRegister_MobilePlatform_ReturnsTokensInBody(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))

	rec := httptest.NewRecorder()
	h.Register(rec, mobileRequest("/api/v1/register", validRegBody()))

	if rec.Code != http.StatusCreated {
		t.Fatalf("Статус = %d, ожидается: 201; body = %s", rec.Code, rec.Body.String())
	}
	tr := decodeTokenResponse(t, rec)
	if tr.AccessToken == "" || tr.RefreshToken == "" || tr.TokenType != "Bearer" {
		t.Error("Мобильная регистрация должна вернуть пару токенов")
	}
	if tr.User == nil || tr.User.Email != "user@example.com" || tr.User.Role != domain.RoleUser {
		t.Errorf("Профиль в мобильном ответе регистрации некорректен: %+v", tr.User)
	}
	assertNoAuthCookies(t, rec)
}

func TestRegister_WebPlatform_NoTokensInBody(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))

	rec := httptest.NewRecorder()
	h.Register(rec, postJSON("/api/v1/register", validRegBody())) // без заголовка = web

	if rec.Code != http.StatusCreated {
		t.Fatalf("Статус = %d, ожидается: 201", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "access_token") || strings.Contains(rec.Body.String(), "refresh_token") {
		t.Errorf("Веб-ответ регистрации не должен содержать токены: %s", rec.Body.String())
	}
	assertMessage(t, rec, messages.RegistrationSuccessful)
}

func TestRegisterAdmin_MobilePlatform_ReturnsTokensInBody(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))

	req := mobileRequest("/api/v1/register-admin", validRegBody())
	req.Header.Set("X-Admin-Token", cfg.AdminRegisterToken)
	rec := httptest.NewRecorder()
	h.RegisterAdmin(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Статус = %d, ожидается: 201; body = %s", rec.Code, rec.Body.String())
	}
	tr := decodeTokenResponse(t, rec)
	if tr.AccessToken == "" || tr.RefreshToken == "" {
		t.Error("Мобильная регистрация админа должна вернуть токены")
	}
	if tr.User == nil || tr.User.Role != domain.RoleAdmin {
		t.Errorf("Роль в мобильном ответе = %+v, ожидается admin", tr.User)
	}
	assertNoAuthCookies(t, rec)
}

// ---------------------------------------------------------------------------
// РЕГРЕССИЯ: ЭКСФИЛЬТРАЦИЯ REFRESH-ТОКЕНА ЧЕРЕЗ ПОДМЕНУ X-Client-Platform
// ---------------------------------------------------------------------------

// csrfPairFor выдаёт валидную CSRF-пару (значение в cookie csrf_token и в
// заголовке X-CSRF-Token — как делает браузер после GET /csrf).
func csrfPairFor(t *testing.T, cfg *config.Config) string {
	t.Helper()
	v, err := auth.IssueCSRF(cfg.JWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// assertNoTokensInBody проверяет, что JSON-тело ответа не содержит полей
// токенов (веб-контракт: токены живут только в HttpOnly cookie).
func assertNoTokensInBody(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	body := rec.Body.String()
	for _, k := range []string{"access_token", "refresh_token"} {
		if strings.Contains(body, k) {
			t.Errorf("Тело веб-ответа не должно содержать %q: %s", k, body)
		}
	}
}

// TestRefresh_CookieCredential_WinsOverMobileHeader — РЕГРЕССИОННЫЙ ТЕСТ
// утечки токенов: запрос с валидной cookie refresh_token + поддельным
// X-Client-Platform: mobile + валидным CSRF НЕ должен возвращать токены в
// JSON-теле. Формат ответа определяется ИСТОЧНИКОМ credentials (cookie ->
// Web-Flow: Set-Cookie), а не заявленной платформой.
func TestRefresh_CookieCredential_WinsOverMobileHeader(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	cm := loginCookies(t, h, "user@example.com", "StrongPass123")
	oldRefresh := cm[auth.RefreshCookie]

	csrf := csrfPairFor(t, cfg)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req.AddCookie(&http.Cookie{Name: auth.RefreshCookie, Value: oldRefresh})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("X-Client-Platform", "mobile") // попытка эксфильтрации

	rec := httptest.NewRecorder()
	middleware.CSRF(cfg)(http.HandlerFunc(h.Refresh)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	// КРИТИЧНО: токенов в теле нет — Web-Flow принудительно выбран по cookie.
	assertNoTokensInBody(t, rec)
	assertMessage(t, rec, messages.TokensRefreshed)

	// Ответ обязан содержать новые HttpOnly cookie (Web-Flow).
	rotated := cookieMap(rec.Result().Cookies())
	newRefresh := rotated[auth.RefreshCookie]
	if newRefresh == "" || newRefresh == oldRefresh {
		t.Error("Web-Flow не установил новый refresh-cookie")
	}
	if rotated[auth.AccessCookie] == "" {
		t.Error("Web-Flow не установил access-cookie")
	}
}

// TestRefresh_BearerWithoutCookies_MobileFlow — легитимный Mobile-Flow:
// Authorization: Bearer <refresh> при отсутствии auth-cookie -> токены в
// JSON-теле, cookie НЕ устанавливаются.
func TestRefresh_BearerWithoutCookies_MobileFlow(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	rec := httptest.NewRecorder()
	h.Login(rec, mobileRequest("/api/v1/login", map[string]string{"email": "user@example.com", "password": "StrongPass123"}))
	oldRefresh := decodeTokenResponse(t, rec).RefreshToken

	req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+oldRefresh)
	req.Header.Set("X-Client-Platform", "mobile")
	rec = httptest.NewRecorder()
	h.Refresh(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	tr := decodeTokenResponse(t, rec)
	if tr.RefreshToken == "" || tr.RefreshToken == oldRefresh {
		t.Error("Mobile-Flow через Bearer должен ротировать токены в теле")
	}
	assertNoAuthCookies(t, rec)
}

// TestRefresh_BearerAndCookie_Conflict — смешанные credentials (Bearer +
// cookie refresh_token одновременно) запрещены контрактом: 409 Conflict,
// ротация не выполняется.
func TestRefresh_BearerAndCookie_Conflict(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	cm := loginCookies(t, h, "user@example.com", "StrongPass123")
	cookieRefresh := cm[auth.RefreshCookie]

	// Второй (незаконно смешиваемый) источник — Bearer с другим активным токеном.
	rec := httptest.NewRecorder()
	h.Login(rec, mobileRequest("/api/v1/login", map[string]string{"email": "user@example.com", "password": "StrongPass123"}))
	bearerRefresh := decodeTokenResponse(t, rec).RefreshToken

	req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+bearerRefresh)
	req.AddCookie(&http.Cookie{Name: auth.RefreshCookie, Value: cookieRefresh})
	rec = httptest.NewRecorder()
	h.Refresh(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("Статус = %d, ожидается: 409; body = %s", rec.Code, rec.Body.String())
	}
	// Смешанный запрос не должен раскрывать токены ни в каком виде.
	assertNoTokensInBody(t, rec)
	// Ротация не выполнена: cookie-токен остался активен в хранилище.
	if _, err := store.GetActive(nilCtx(), auth.HashToken(cookieRefresh)); err != nil {
		t.Error("При 409 Conflict refresh-токен не должен быть отозван/ротирован")
	}
}

// TestLogout_CookieCredential_WinsOverMobileHeader — та же защита для
// /logout: cookie refresh_token + X-Client-Platform: mobile -> выход всё
// равно чистит cookie (Web-Flow), несмотря на заявленную платформу.
func TestLogout_CookieCredential_WinsOverMobileHeader(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	cm := loginCookies(t, h, "user@example.com", "StrongPass123")
	refresh := cm[auth.RefreshCookie]

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	req.AddCookie(&http.Cookie{Name: auth.RefreshCookie, Value: refresh})
	req.Header.Set("X-Client-Platform", "mobile")
	rec := httptest.NewRecorder()
	h.Logout(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.RefreshCookie && c.MaxAge == -1 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("Logout по cookie-credentials обязан сбросить refresh-cookie (Max-Age=-1)")
	}
	if _, err := store.GetActive(nilCtx(), auth.HashToken(refresh)); err == nil {
		t.Error("Refresh-токен не отозван в хранилище")
	}
}

// TestMobileRefreshViaBodyToken — альтернативный мобильный вход refresh: токен
// в JSON-теле {"refresh_token": "..."} без Bearer и cookie.
func TestMobileRefreshViaBodyToken(t *testing.T) {
	cfg := testConfig()
	store := newMockStore()
	h := NewAuthHandler(cfg, newAuthUC(cfg, store))
	seedUser(t, store, "user@example.com", "StrongPass123", domain.RoleUser)

	rec := httptest.NewRecorder()
	h.Login(rec, mobileRequest("/api/v1/login", map[string]string{"email": "user@example.com", "password": "StrongPass123"}))
	oldRefresh := decodeTokenResponse(t, rec).RefreshToken

	rec = httptest.NewRecorder()
	h.Refresh(rec, mobileRequest("/api/v1/refresh", map[string]string{"refresh_token": oldRefresh}))
	if rec.Code != http.StatusOK {
		t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
	}
	tr := decodeTokenResponse(t, rec)
	if tr.RefreshToken == oldRefresh {
		t.Error("Ротация через тело не произошла")
	}
	assertNoAuthCookies(t, rec)
}
