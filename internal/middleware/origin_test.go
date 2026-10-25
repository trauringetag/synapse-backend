package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trauringetag/synapse-backend/internal/config"
)

// TestRequireAllowedOrigin тестирует middleware проверки разрешенных источников (CORS)
func TestRequireAllowedOrigin(t *testing.T) {
	cfg := &config.Config{CORSOrigins: []string{"http://localhost:3000", "https://app.example.com"}}

	tests := []struct {
		name       string
		origin     string
		referer    string
		wantStatus int
	}{
		{
			name:       "Разрешенный origin проходит проверку",
			origin:     "http://localhost:3000",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "Использование Referer при отсутствии Origin (fallback)",
			referer:    "http://localhost:3000/register?from=test",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "Referer корректно парсится (удаляются path и query)",
			referer:    "https://app.example.com/some/path",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "Отсутствие Origin и Referer блокирует запрос",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Недоверенный origin блокируется даже при валидном referer",
			origin:     "https://evil.example",
			referer:    "http://localhost:3000/",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Недоверенный referer блокирует запрос",
			referer:    "https://evil.example/path",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Origin с trailing slash принимается корректно",
			origin:     "http://localhost:3000/",
			wantStatus: http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
			})

			handler := RequireAllowedOrigin(cfg)(next)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/csrf", nil)

			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("Статус = %d, ожидается: %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}

			// Проверяем, что следующий handler вызывается только при успешной проверке
			if nextCalled != (tt.wantStatus == http.StatusNoContent) {
				t.Fatalf("nextCalled = %v, должно соответствовать статусу %d", nextCalled, tt.wantStatus)
			}
		})
	}
}

// TestRequireAllowedOriginUsesRefererOnlyWhenOriginMissing тестирует логику fallback на Referer
func TestRequireAllowedOriginUsesRefererOnlyWhenOriginMissing(t *testing.T) {
	cfg := &config.Config{CORSOrigins: []string{"https://app.example"}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := RequireAllowedOrigin(cfg)(next)

	tests := []struct {
		name       string
		origin     string
		referer    string
		wantStatus int
	}{
		{
			name:       "Разрешенный Origin используется напрямую",
			origin:     "https://app.example",
			referer:    "",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "Referer используется как fallback при отсутствии Origin",
			origin:     "",
			referer:    "https://app.example/account",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "Отсутствие Origin и Referer возвращает 403",
			origin:     "",
			referer:    "",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Недопустимый Origin блокирует запрос даже при допустимом Referer (защита от атаки)",
			origin:     "https://evil.example",
			referer:    "https://app.example/account",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Недопустимый Referer блокирует запрос",
			origin:     "",
			referer:    "https://evil.example/account",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/csrf", nil)

			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("Статус = %d, ожидается: %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestCSRFUsesRefererFallbackWhenOriginMissing тестирует CSRF с fallback на Referer
func TestCSRFUsesRefererFallbackWhenOriginMissing(t *testing.T) {
	cfg := &config.Config{
		CORSOrigins: []string{"https://app.example"},
		JWTSecret:   []byte("test-secret-that-is-at-least-32-bytes"),
	}

	token, err := IssueCSRF(cfg.JWTSecret)
	if err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	handler := CSRF(cfg)(next)

	tests := []struct {
		name       string
		origin     string
		referer    string
		wantStatus int
	}{
		{
			name:       "Разрешенный Referer как fallback проходит CSRF проверку",
			origin:     "",
			referer:    "https://app.example/form",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "Недопустимый Origin блокирует запрос даже при допустимом Referer",
			origin:     "https://evil.example",
			referer:    "https://app.example/form",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "Отсутствие Origin и Referer блокирует запрос",
			origin:     "",
			referer:    "",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)

			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}

			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
			req.Header.Set("X-CSRF-Token", token)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("Статус = %d, ожидается: %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestRequestOriginParsing тестирует парсинг Origin из заголовков
func TestRequestOriginParsing(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		referer  string
		expected string
	}{
		{
			name:     "Origin имеет приоритет над Referer",
			origin:   "http://localhost:3000",
			referer:  "https://app.example.com/path",
			expected: "http://localhost:3000",
		},
		{
			name:     "Referer парсится в origin при отсутствии Origin header",
			origin:   "",
			referer:  "https://app.example.com/page?param=value",
			expected: "https://app.example.com",
		},
		{
			name:     "Origin с trailing slash нормализуется",
			origin:   "http://localhost:3000/",
			referer:  "",
			expected: "http://localhost:3000",
		},
		{
			name:     "Пустые заголовки возвращают пустую строку",
			origin:   "",
			referer:  "",
			expected: "",
		},
		{
			name:     "Некорректный Referer игнорируется",
			origin:   "",
			referer:  "not-a-valid-url",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}

			got := requestOrigin(req)
			if got != tt.expected {
				t.Errorf("requestOrigin() = %q, ожидается: %q", got, tt.expected)
			}
		})
	}
}

// TestIsAllowedOrigin тестирует проверку разрешенных origins
func TestIsAllowedOrigin(t *testing.T) {
	cfg := &config.Config{CORSOrigins: []string{"http://localhost:3000", "https://app.example.com"}}

	tests := []struct {
		name    string
		origin  string
		allowed bool
	}{
		{"Точное совпадение разрешено", "http://localhost:3000", true},
		{"HTTPS домен разрешен", "https://app.example.com", true},
		{"Неизвестный домен заблокирован", "https://evil.com", false},
		{"Поддомен не разрешен без явного указания", "https://sub.app.example.com", false},
		{"HTTP вместо HTTPS заблокирован", "http://app.example.com", false},
		{"Пустой origin не разрешен", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAllowedOrigin(cfg, tt.origin)
			if got != tt.allowed {
				t.Errorf("isAllowedOrigin(%q) = %v, ожидается: %v", tt.origin, got, tt.allowed)
			}
		})
	}
}

// TestOriginSecurityAttackScenarios тестирует сценарии атак на Origin validation
func TestOriginSecurityAttackScenarios(t *testing.T) {
	cfg := &config.Config{CORSOrigins: []string{"https://trusted.example.com"}}
	handler := RequireAllowedOrigin(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Run("Атака: попытка обхода через манипуляцию Origin с пробелами", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/csrf", nil)
		req.Header.Set("Origin", " https://trusted.example.com ") // Пробелы по краям

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Errorf("Origin с пробелами должен быть обработан корректно, status=%d", rec.Code)
		}
	})

	t.Run("Атака: попытка внедрения через подделку subdomain", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/csrf", nil)
		req.Header.Set("Origin", "https://trusted.example.com.evil.com")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Error("Поддельный поддомен должен быть заблокирован")
		}
	})

	t.Run("Атака: попытка использования другого протокола", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/csrf", nil)
		req.Header.Set("Origin", "http://trusted.example.com") // HTTP вместо HTTPS

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Error("Неправильный протокол должен быть заблокирован")
		}
	})

	t.Run("Атака: попытка обхода через null byte", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/csrf", nil)
		req.Header.Set("Origin", "https://trusted.example.com%00.evil.com")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Error("Null byte в Origin должен быть заблокирован")
		}
	})
}
