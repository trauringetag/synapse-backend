package middleware

// Unit-тесты поддержки мобильных клиентов (Bearer + X-Client-Platform):
//   - ClientPlatform: детекция формата ответа (web/mobile, обратная совместимость);
//   - IsBearerAuth / extractAccessToken: двойной источник токена с приоритетом Bearer;
//   - Authenticate: Bearer-токен проходит те же проверки, что и cookie;
//   - CSRF / RequireAllowedOrigin: привязаны к способу аутентификации, НЕ к
//     заголовку платформы (защита от подделки X-Client-Platform);
//   - RefreshKey: одинаковая работа rate limiter для обоих типов клиентов.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	auth "github.com/trauringetag/synapse-backend/internal/infrastructure/security"
)

func platformTestConfig() *config.Config {
	return &config.Config{
		JWTSecret:   []byte("test-secret-key-at-least-32-bytes-long"),
		AccessTTL:   15 * time.Minute,
		RefreshTTL:  168 * time.Hour,
		CORSOrigins: []string{"https://app.example.com"},
	}
}

// ---------------------------------------------------------------------------
// ClientPlatform — детекция формата ответа
// ---------------------------------------------------------------------------

func TestClientPlatform_Web(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Client-Platform", "web")
	if got := ClientPlatform(req); got != "web" {
		t.Errorf("ClientPlatform = %q, ожидается: web", got)
	}
}

func TestClientPlatform_Mobile(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Client-Platform", "mobile")
	if got := ClientPlatform(req); got != "mobile" {
		t.Errorf("ClientPlatform = %q, ожидается: mobile", got)
	}
}

func TestClientPlatform_Missing_DefaultsToWeb(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := ClientPlatform(req); got != "web" {
		t.Errorf("Без заголовка ClientPlatform = %q, ожидается: web (обратная совместимость)", got)
	}
}

func TestClientPlatform_Invalid_DefaultsToWeb(t *testing.T) {
	for _, v := range []string{"desktop", "ios", "android", "", "mobi", "web-app"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Client-Platform", v)
		if got := ClientPlatform(req); got != "web" {
			t.Errorf("ClientPlatform(%q) = %q, ожидается: web", v, got)
		}
	}
}

func TestClientPlatform_CaseInsensitive(t *testing.T) {
	for _, v := range []string{"MOBILE", "Mobile", "mObIlE", " mobile ", "\tWEB\t"} {
		want := "mobile"
		if strings.EqualFold(strings.TrimSpace(v), "web") {
			want = "web"
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Client-Platform", v)
		if got := ClientPlatform(req); got != want {
			t.Errorf("ClientPlatform(%q) = %q, ожидается: %q", v, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// IsBearerAuth / extractAccessToken
// ---------------------------------------------------------------------------

func TestIsBearerAuth(t *testing.T) {
	tests := []struct {
		header string
		want   bool
	}{
		{"Bearer abc.def.ghi", true},
		{"bearer abc.def.ghi", true},  // case-insensitive схема
		{"BEARER abc.def.ghi", true},  // case-insensitive схема
		{"Bearer ", false},            // пустой токен — не Bearer-аутентификация
		{"Basic dXNlcjpwYXNz", false}, // чужая схема
		{"Token abc", false},          // чужая схема
		{"", false},                   // заголовок отсутствует
		{"Bear", false},               // короткий префикс
	}
	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tt.header != "" {
			req.Header.Set("Authorization", tt.header)
		}
		if got := IsBearerAuth(req); got != tt.want {
			t.Errorf("IsBearerAuth(%q) = %v, ожидается: %v", tt.header, got, tt.want)
		}
	}
}

func TestExtractAccessToken_PriorityAndSchemes(t *testing.T) {
	cfg := platformTestConfig()
	id := uuid.New()
	pair, err := auth.IssuePair(cfg, id, "user@example.com", domain.RoleUser)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Bearer имеет приоритет над cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: "cookie-token"})
		tok, err := extractAccessToken(req)
		if err != nil || tok != pair.AccessToken {
			t.Errorf("Извлечён не Bearer-токен: tok=%q err=%v", tok, err)
		}
	})

	t.Run("Пробелы вокруг токена обрезаются", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer   "+pair.AccessToken+"   ")
		tok, err := extractAccessToken(req)
		if err != nil || tok != pair.AccessToken {
			t.Errorf("Токен не обрезан: tok=%q err=%v", tok, err)
		}
	})

	t.Run("Неизвестная схема -> ошибка", func(t *testing.T) {
		for _, h := range []string{"Basic dXNlcjpwYXNz", "Token abc", "Digest x"} {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", h)
			if _, err := extractAccessToken(req); err == nil {
				t.Errorf("Схема %q должна отклоняться", h)
			}
		}
	})

	t.Run("Пустой Bearer -> ошибка", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer    ")
		if _, err := extractAccessToken(req); err == nil {
			t.Error("Пустой Bearer-токен должен отклоняться")
		}
	})

	t.Run("Без Authorization используется cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: pair.AccessToken})
		tok, err := extractAccessToken(req)
		if err != nil || tok != pair.AccessToken {
			t.Errorf("Cookie-токен не извлечён: tok=%q err=%v", tok, err)
		}
	})
}

// ---------------------------------------------------------------------------
// Authenticate — Bearer-токен
// ---------------------------------------------------------------------------

// runAuthenticate гонит запрос через Authenticate и возвращает код ответа и
// был ли вызван next.
func runAuthenticate(t *testing.T, cfg *config.Config, lookup UserLookup, req *http.Request) (int, bool) {
	t.Helper()
	nextCalled := false
	var captured *Principal
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		captured, _ = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	Authenticate(cfg, lookup)(next).ServeHTTP(rec, req)
	_ = captured
	return rec.Code, nextCalled
}

func newActiveLookupWith(t *testing.T, status string) (uuid.UUID, *mockUserLookup) {
	t.Helper()
	id := uuid.New()
	m := newMockUserLookup()
	m.users[id] = &domain.User{ID: id, Email: "user@example.com", Role: domain.RoleUser, Status: status}
	return id, m
}

func TestAuthenticate_BearerToken_Success(t *testing.T) {
	cfg := platformTestConfig()
	id, lookup := newActiveLookupWith(t, domain.StatusActive)
	pair, _ := auth.IssuePair(cfg, id, "user@example.com", domain.RoleUser)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "bearer "+pair.AccessToken) // регистронезависимая схема

	code, called := runAuthenticate(t, cfg, lookup, req)
	if code != http.StatusOK || !called {
		t.Fatalf("Bearer-аутентификация не прошла: код = %d, next = %v", code, called)
	}
}

func TestAuthenticate_BearerToken_InvalidSignature(t *testing.T) {
	cfg := platformTestConfig()
	_, lookup := newActiveLookupWith(t, domain.StatusActive)
	otherCfg := platformTestConfig()
	otherCfg.JWTSecret = []byte("ANOTHER-secret-key-32-bytes-long!!")
	id := uuid.New()
	pair, _ := auth.IssuePair(otherCfg, id, "user@example.com", domain.RoleUser)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)

	code, called := runAuthenticate(t, cfg, lookup, req)
	if code != http.StatusUnauthorized || called {
		t.Errorf("Поддельная подпись: код = %d (ожидается 401), next = %v", code, called)
	}
}

func TestAuthenticate_BearerToken_Expired(t *testing.T) {
	cfg := platformTestConfig()
	cfg.AccessTTL = -time.Minute // access уже просрочен
	id, lookup := newActiveLookupWith(t, domain.StatusActive)
	pair, _ := auth.IssuePair(cfg, id, "user@example.com", domain.RoleUser)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)

	code, called := runAuthenticate(t, cfg, lookup, req)
	if code != http.StatusUnauthorized || called {
		t.Errorf("Просроченный Bearer: код = %d (ожидается 401), next = %v", code, called)
	}
}

func TestAuthenticate_BearerToken_InactiveUser(t *testing.T) {
	cfg := platformTestConfig()
	id, lookup := newActiveLookupWith(t, domain.StatusInactive)
	pair, _ := auth.IssuePair(cfg, id, "user@example.com", domain.RoleUser)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)

	code, called := runAuthenticate(t, cfg, lookup, req)
	if code != http.StatusUnauthorized || called {
		t.Errorf("Неактивный пользователь с Bearer: код = %d (ожидается 401), next = %v", code, called)
	}
}

func TestAuthenticate_BearerToken_TakesPriorityOverCookie(t *testing.T) {
	cfg := platformTestConfig()
	goodID, lookup := newActiveLookupWith(t, domain.StatusActive)
	pair, _ := auth.IssuePair(cfg, goodID, "user@example.com", domain.RoleUser)

	// Cookie содержит мусор, Bearer — валидный токен: должен победить Bearer.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: "garbage.cookie.token"})

	code, called := runAuthenticate(t, cfg, lookup, req)
	if code != http.StatusOK || !called {
		t.Errorf("Bearer не имел приоритета над cookie: код = %d, next = %v", code, called)
	}
}

func TestAuthenticate_UnsupportedScheme_Returns401(t *testing.T) {
	cfg := platformTestConfig()
	id, lookup := newActiveLookupWith(t, domain.StatusActive)
	pair, _ := auth.IssuePair(cfg, id, "user@example.com", domain.RoleUser)

	// Даже с валидным cookie-токеном неизвестная схема в Authorization -> 401:
	// смешивание источников исключено, fallback на cookie при наличии
	// заголовка Authorization не допускается.
	for _, scheme := range []string{"Basic dXNlcjpwYXNz", "Token abc123", "Digest x"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
		req.Header.Set("Authorization", scheme)
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: pair.AccessToken})

		code, called := runAuthenticate(t, cfg, lookup, req)
		if code != http.StatusUnauthorized || called {
			t.Errorf("Схема %q: код = %d (ожидается 401), next = %v", scheme, code, called)
		}
	}
}

func TestAuthenticate_EmptyBearer_Returns401(t *testing.T) {
	cfg := platformTestConfig()
	_, lookup := newActiveLookupWith(t, domain.StatusActive)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer ")

	code, called := runAuthenticate(t, cfg, lookup, req)
	if code != http.StatusUnauthorized || called {
		t.Errorf("Пустой Bearer: код = %d (ожидается 401), next = %v", code, called)
	}
}

// ---------------------------------------------------------------------------
// CSRF — привязка к способу аутентификации, а НЕ к X-Client-Platform
// ---------------------------------------------------------------------------

func runCSRF(t *testing.T, cfg *config.Config, req *http.Request) (int, bool) {
	t.Helper()
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	CSRF(cfg)(next).ServeHTTP(rec, req)
	return rec.Code, nextCalled
}

func TestCSRF_BearerToken_SkipsCheck(t *testing.T) {
	cfg := platformTestConfig()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer some.access.jwt")
	// Заявленная веб-платформа НЕ обязывает CSRF для Bearer-запроса:
	// безопасность определяется способом аутентификации, не заголовком.
	req.Header.Set("X-Client-Platform", "web")

	code, called := runCSRF(t, cfg, req)
	if code != http.StatusNoContent || !called {
		t.Errorf("Bearer без CSRF: код = %d (ожидается 204), next = %v", code, called)
	}
}

func TestCSRF_CookieWithoutCSRF_Returns403(t *testing.T) {
	cfg := platformTestConfig()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: "access.jwt"})
	// КЛЮЧЕВОЙ кейс: клиент заявил mobile, но запрос идёт с cookie —
	// это потенциальная подделка заголовка, CSRF обязателен.
	req.Header.Set("X-Client-Platform", "mobile")

	code, called := runCSRF(t, cfg, req)
	if code != http.StatusForbidden || called {
		t.Errorf("Cookie без CSRF (заявлен mobile): код = %d (ожидается 403), next = %v", code, called)
	}
}

func TestCSRF_CookieWithValidCSRF_Passes(t *testing.T) {
	cfg := platformTestConfig()
	token, _ := IssueCSRF(cfg.JWTSecret)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: "access.jwt"})

	code, called := runCSRF(t, cfg, req)
	if code != http.StatusNoContent || !called {
		t.Errorf("Cookie с валидным CSRF: код = %d (ожидается 204), next = %v", code, called)
	}
}

func TestCSRF_BearerAndCookie_BearerWins(t *testing.T) {
	cfg := platformTestConfig()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer some.access.jwt")
	// Cookie есть, но CSRF-токена нет: Bearer побеждает, CSRF не требуется,
	// потому что фактическая аутентификация — заголовком (Authenticate
	// игнорирует cookie при наличии Bearer).
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: "cookie.jwt"})

	code, called := runCSRF(t, cfg, req)
	if code != http.StatusNoContent || !called {
		t.Errorf("Bearer + cookie: код = %d (ожидается 204), next = %v", code, called)
	}
}

func TestCSRF_PlatformHeaderDoesNotAffectCSRF(t *testing.T) {
	cfg := platformTestConfig()

	// Фишинг-сценарий: evil.com отправляет запрос с cookie жертвы и
	// поддельным X-Client-Platform: mobile. CSRF обязан остаться включённым.
	spoof := httptest.NewRequest(http.MethodPost, "/api/v1/users/me", nil)
	spoof.Header.Set("X-Client-Platform", "mobile")
	spoof.Header.Set("Origin", "https://evil.com")
	spoof.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: "victim.session.jwt"})
	if code, _ := runCSRF(t, cfg, spoof); code != http.StatusForbidden {
		t.Errorf("Подделка заголовка обошла CSRF: код = %d (ожидается 403)", code)
	}

	// Тот же запрос с честным Origin, но без CSRF-токена — тоже 403.
	spoof2 := httptest.NewRequest(http.MethodPost, "/api/v1/users/me", nil)
	spoof2.Header.Set("X-Client-Platform", "mobile")
	spoof2.Header.Set("Origin", "https://app.example.com")
	spoof2.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: "victim.session.jwt"})
	if code, _ := runCSRF(t, cfg, spoof2); code != http.StatusForbidden {
		t.Errorf("Cookie без CSRF-токена: код = %d (ожидается 403)", code)
	}

	// Валидный CSRF для cookie-запроса с заявленным mobile — проходит:
	// заголовок влияет только на формат ответа.
	token, _ := IssueCSRF(cfg.JWTSecret)
	ok := httptest.NewRequest(http.MethodPost, "/api/v1/users/me", nil)
	ok.Header.Set("X-Client-Platform", "mobile")
	ok.Header.Set("Origin", "https://app.example.com")
	ok.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
	ok.Header.Set("X-CSRF-Token", token)
	if code, called := runCSRF(t, cfg, ok); code != http.StatusNoContent || !called {
		t.Errorf("Cookie + валидный CSRF + mobile: код = %d (ожидается 204)", code)
	}
}

// ---------------------------------------------------------------------------
// RequireAllowedOrigin — аналогично CSRF
// ---------------------------------------------------------------------------

func runOrigin(t *testing.T, cfg *config.Config, req *http.Request) (int, bool) {
	t.Helper()
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	RequireAllowedOrigin(cfg)(next).ServeHTTP(rec, req)
	return rec.Code, nextCalled
}

func TestRequireOrigin_BearerToken_NoOrigin_Passes(t *testing.T) {
	cfg := platformTestConfig()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer some.access.jwt")
	// Origin отсутствует полностью — мобильный клиент его не отправляет.

	code, called := runOrigin(t, cfg, req)
	if code != http.StatusNoContent || !called {
		t.Errorf("Bearer без Origin: код = %d (ожидается 204), next = %v", code, called)
	}
}

func TestRequireOrigin_BearerToken_WeirdOrigin_Passes(t *testing.T) {
	cfg := platformTestConfig()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer some.access.jwt")
	req.Header.Set("Origin", "https://native-app.invalid")

	code, called := runOrigin(t, cfg, req)
	if code != http.StatusNoContent || !called {
		t.Errorf("Bearer с нестандартным Origin: код = %d (ожидается 204), next = %v", code, called)
	}
}

func TestRequireOrigin_Cookie_ValidOrigin_Passes(t *testing.T) {
	cfg := platformTestConfig()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: "access.jwt"})

	code, called := runOrigin(t, cfg, req)
	if code != http.StatusNoContent || !called {
		t.Errorf("Cookie с разрешённым Origin: код = %d (ожидается 204), next = %v", code, called)
	}
}

func TestRequireOrigin_Cookie_InvalidOrigin_Returns403(t *testing.T) {
	cfg := platformTestConfig()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: "access.jwt"})

	code, called := runOrigin(t, cfg, req)
	if code != http.StatusForbidden || called {
		t.Errorf("Cookie с запрещённым Origin: код = %d (ожидается 403), next = %v", code, called)
	}
}

func TestRequireOrigin_Cookie_PlatformMobile_StillChecksOrigin(t *testing.T) {
	cfg := platformTestConfig()
	// Подделка заголовка: заявлен mobile, но запрос идёт с cookie -> Origin
	// проверяется как для веб-клиента.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("X-Client-Platform", "mobile")
	req.Header.Set("Origin", "https://evil.com")
	req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: "victim.jwt"})

	code, called := runOrigin(t, cfg, req)
	if code != http.StatusForbidden || called {
		t.Errorf("Подделка platform не отключила Origin: код = %d (ожидается 403), next = %v", code, called)
	}
}

// ---------------------------------------------------------------------------
// RefreshKey — единый rate limiter для обоих типов клиентов
// ---------------------------------------------------------------------------

func TestRefreshKey_BearerAndCookie(t *testing.T) {
	// Без cookie ключ не должен ломаться (падает на IP) и не должен
	// раскрывать значение токена.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req.Header.Set("Authorization", "Bearer refresh.jwt.value")
	key := RefreshKey(req)
	if !strings.HasPrefix(key, "refresh:") {
		t.Errorf("RefreshKey(Bearer) = %q, ожидается префикс refresh:", key)
	}
	if strings.Contains(key, "refresh.jwt.value") {
		t.Error("RefreshKey не должен содержать значение токена")
	}

	// Одинаковый Bearer -> одинаковый ключ (детерминированный хеш).
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req2.Header.Set("Authorization", "Bearer refresh.jwt.value")
	if RefreshKey(req2) != key {
		t.Error("Одинаковые Bearer-токены должны давать одинаковый ключ")
	}

	// Разные токены -> разные ключи.
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req3.Header.Set("Authorization", "Bearer other.refresh.jwt")
	if RefreshKey(req3) == key {
		t.Error("Разные токены должны давать разные ключи")
	}

	// Cookie-клиент: тот же refresh-токен в cookie даёт тот же ключ, что и в
	// Bearer (носитель не важен — важен сам токен).
	req4 := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	req4.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh.jwt.value"})
	if RefreshKey(req4) != key {
		t.Error("Cookie и Bearer с одинаковым токеном должны давать одинаковый ключ")
	}

	// Ни Bearer, ни cookie -> fallback на IP (лимитер не ломается).
	req5 := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
	if k := RefreshKey(req5); !strings.HasPrefix(k, "refresh:") {
		t.Errorf("Fallback-ключ = %q, ожидается префикс refresh:", k)
	}
}
