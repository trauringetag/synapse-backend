package tests

// Интеграционные тесты критериев приёмки разделения rate-limit политик и
// защиты от account-lockout DoS (проверяются через реальный роутер +
// fakeRateLimiter, фиксирующий bucket-ключи):
//   - TestIntegration_RateLimitPolicy_RegisterDoesNotBlockLogout —
//     100 исчерпывающих /register с одного IP НЕ блокируют /logout того же IP
//     (ключи rl:register:v1:... и rl:logout:v1:... не пересекаются);
//   - TestIntegration_RateLimitPolicy_SuccessfulLoginResetsFailedCounter —
//     неудачные входы (401) наращивают счётчик login_failed, успешный вход
//     (2xx) сбрасывает его;
//   - TestIntegration_RateLimitPolicy_NoPIIInBucketKeys — email/IP никогда не
//     хранятся в открытом виде в ключах хранилища (только HMAC-дайджест).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/middleware"
)

// newTestEnvWithLimits — стек как newTestEnv, но с индивидуальными порогами
// лимитов (для проверок 429 без 1000 запросов).
func newTestEnvWithLimits(t *testing.T, loginLimit, registerLimit, logoutLimit int) *testEnv {
	t.Helper()
	cfg := &config.Config{
		AppEnv:                 "synapse-test",
		JWTSecret:              []byte("integration-test-secret-at-least-32-bytes"),
		RateLimitHMACKey:       []byte("integration-test-rate-limit-hmac-key-32b!"),
		AccessTTL:              15 * time.Minute,
		RefreshTTL:             168 * time.Hour,
		AdminRegisterToken:     "admin-token-123",
		CookieSecure:           false,
		CookieSameSite:         http.SameSiteLaxMode,
		CookiePath:             "/api/v1/",
		CORSOrigins:            []string{"https://app.example.com"},
		LoginRateLimit:         loginLimit,
		RegisterRateLimit:      registerLimit,
		RefreshRateLimit:       1000,
		LogoutRateLimit:        logoutLimit,
		AuthenticatedRateLimit: 1000,
	}
	return buildTestEnv(t, cfg)
}

// policyKeys возвращает все bucket-ключи хранилища, относящиеся к политике
// (префикс rl:<policy>:v1:).
func policyKeys(snap map[string]int, policy string) []string {
	prefix := "rl:" + policy + ":"
	var out []string
	for k := range snap {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}

// shortBucket — компактное представление ключа для сообщений тестов.
func shortBucket(k string) string {
	if len(k) > 24 {
		return k[:24] + "..."
	}
	return k
}

// httptestProbeRequest — синтетический POST /login с телом {email}, чтобы
// вычислить тот же bucket-ключ, что строит middleware (LoginFailedKey).
func httptestProbeRequest(email string) *http.Request {
	body := `{"email":"` + email + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// ---------------------------------------------------------------------------
// Критерий 1: N неудачных /register не блокируют /logout того же IP.
// ---------------------------------------------------------------------------

func TestIntegration_RateLimitPolicy_RegisterDoesNotBlockLogout(t *testing.T) {
	// Порог регистрации 3 — после него /register отдаёт 429; logout остаётся
	// доступным, т.к. это отдельная политика rl:logout:v1:<hmac(ip)>.
	e := newTestEnvWithLimits(t, 1000, 3, 10)

	var lastCode int
	for i := 0; i < 100; i++ {
		rec := e.doMobile(t, http.MethodPost, "/api/v1/register", "", map[string]any{
			"email":      "spam" + itoa(i) + "@example.com",
			"password":   testPassword,
			"first_name": "Spam",
			"last_name":  "Mer",
		})
		lastCode = rec.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("ожидан 429 на /register после 100 попыток, получен %d", lastCode)
	}

	snap := e.limits.snapshot()
	regKeys := policyKeys(snap, middleware.PolicyRegister)
	logoutKeys := policyKeys(snap, middleware.PolicyLogout)
	if len(regKeys) != 1 {
		t.Fatalf("политика register: ожидан 1 bucket для одного IP, найдено %v", regKeys)
	}
	if got := snap[regKeys[0]]; got < 10 {
		t.Errorf("bucket register должен быть переполнен (>=limit), hits=%d", got)
	}
	if len(logoutKeys) != 0 {
		t.Errorf("запросы /register не должны создавать buckets политики logout: %v", logoutKeys)
	}

	// /logout того же IP — не заблокирован (без cookie обработчик отвечает 200).
	rec := e.doMobile(t, http.MethodPost, "/api/v1/logout", "", nil)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("/logout заблокирован политикой /register (общий bucket?): 429")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("/logout: неожиданный код %d, body=%s", rec.Code, rec.Body.String())
	}
}

func itoa(i int) string {
	return strconv.Itoa(i)
}

// ---------------------------------------------------------------------------
// Критерий 2: успешный вход сбрасывает счётчик неудачных попыток.
// ---------------------------------------------------------------------------

func TestIntegration_RateLimitPolicy_SuccessfulLoginResetsFailedCounter(t *testing.T) {
	e := newTestEnvWithLimits(t, 5, 1000, 1000)
	e.registerUser(t, testEmail)

	keyFn := middleware.LoginFailedKey(e.cfg)
	probe := httptestProbeRequest(testEmail)
	bucket := keyFn(probe)

	// 3 неудачных входа (неверный пароль => 401) наращивают login_failed.
	for i := 0; i < 3; i++ {
		rec := e.doMobile(t, http.MethodPost, "/api/v1/login", "", map[string]any{
			"email": testEmail, "password": "wrong-password",
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("неудачный вход: ожидан 401, получен %d body=%s", rec.Code, rec.Body.String())
		}
	}
	if got := e.limits.count(bucket); got != 3 {
		t.Fatalf("счётчик login_failed после 3x401: ожидан 3, получен %d (bucket=%s)", got, shortBucket(bucket))
	}

	// Успешный вход (200) обязан СБРОСИТЬ счётчик неудачных попыток.
	rec := e.doMobile(t, http.MethodPost, "/api/v1/login", "", map[string]any{
		"email": testEmail, "password": testPassword,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("успешный вход: ожидан 200, получен %d body=%s", rec.Code, rec.Body.String())
	}
	if got := e.limits.count(bucket); got != 0 {
		t.Errorf("успешный вход не сбросил login_failed: hits=%d", got)
	}
	if calls := e.limits.resetCalls(bucket); calls == 0 {
		t.Errorf("ожидались вызовы Reset по bucket %s при успешном входе", shortBucket(bucket))
	}

	// Дополнительно: лимит тратится ТОЛЬКО неудачами — 400 (валидация) не
	// увеличивает login_failed.
	before := e.limits.count(bucket)
	e.doMobile(t, http.MethodPost, "/api/v1/login", "", map[string]any{
		"email": "not-an-email", "password": "x",
	})
	if after := e.limits.count(bucket); after != before {
		t.Errorf("запрос с невалидным email изменил login_failed: %d -> %d", before, after)
	}
}

// ---------------------------------------------------------------------------
// Критерий 3: PII (email/IP) не хранится в открытом виде в ключах.
// ---------------------------------------------------------------------------

func TestIntegration_RateLimitPolicy_NoPIIInBucketKeys(t *testing.T) {
	e := newTestEnvWithLimits(t, 1000, 1000, 1000)
	e.registerUser(t, testEmail)

	// Один неудачный и один успешный вход + register/logout/refresh.
	e.doMobile(t, http.MethodPost, "/api/v1/login", "", map[string]any{
		"email": testEmail, "password": "wrong-password",
	})
	e.doMobile(t, http.MethodPost, "/api/v1/login", "", map[string]any{
		"email": testEmail, "password": testPassword,
	})
	e.doMobile(t, http.MethodPost, "/api/v1/register", "", map[string]any{
		"email": "other@example.com", "password": testPassword,
		"first_name": "O", "last_name": "K",
	})
	e.doMobile(t, http.MethodPost, "/api/v1/logout", "", nil)

	mustContain := []string{testEmail, "other@example.com", "@example.com", "127.0.0.1", "[::1]", "|"}
	snap := e.limits.snapshot()
	if len(snap) == 0 {
		t.Fatal("хранилище пусто — тест не покрыл ни один лимитер")
	}
	for key := range snap {
		if !strings.HasPrefix(key, "rl:") {
			t.Errorf("ключ вне нового формата rl:<policy>:v1:<hmac>: %q", key)
		}
		for _, pii := range mustContain {
			if strings.Contains(key, pii) {
				t.Errorf("PII %q найдено в bucket_key открытым текстом: %q", pii, key)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Retry-After: остаток до сброса окна, а не вся длина окна.
// ---------------------------------------------------------------------------

func TestIntegration_RateLimitPolicy_RetryAfterIsRemainingWindow(t *testing.T) {
	e := newTestEnvWithLimits(t, 1000, 2, 1000)

	// Фиксируем момент сброса окна на 47 секунд в будущем — так можно
	// детерминированно проверить, что Retry-After отдаёт ОСТАТОК до сброса,
	// а не всю длину часового окна политики register.
	e.limits.setResetAt(time.Now().Add(47 * time.Second))

	var retry string
	for i := 0; i < 5; i++ {
		rec := e.doMobile(t, http.MethodPost, "/api/v1/register", "", map[string]any{
			"email":      "flood" + itoa(i) + "@example.com",
			"password":   testPassword,
			"first_name": "F", "last_name": "L",
		})
		if rec.Code == http.StatusTooManyRequests {
			retry = rec.Header().Get("Retry-After")
			break
		}
	}
	if retry == "" {
		t.Fatal("ожидались 429 с Retry-After на /register")
	}
	secs := parseRetryAfter(t, retry)
	const window = 3600 // часовое окно политики register
	if secs <= 0 || secs >= window {
		t.Errorf("Retry-After=%d должен быть остатком окна (0..%d), а не всей длиной", secs, window)
	}
	// Ожидаем ~47 секунд (округление middleware допускает ±1с).
	if secs < 46 || secs > 48 {
		t.Errorf("Retry-After=%d, ожидался остаток окна ~47с", secs)
	}
}

func parseRetryAfter(t *testing.T, v string) int {
	t.Helper()
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		t.Fatalf("некорректный Retry-After %q: %v", v, err)
	}
	return n
}

// Проверка соответствия fake-хранилища порту используется и здесь, чтобы файл
// компилировался как часть пакета tests.
var _ domain.RateLimitStore = (*fakeRateLimiter)(nil)
var _ = context.Background
