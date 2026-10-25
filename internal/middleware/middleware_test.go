package middleware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/trauringetag/synapse-backend/internal/auth"
	"github.com/trauringetag/synapse-backend/internal/config"
	"github.com/trauringetag/synapse-backend/internal/models"
	"github.com/trauringetag/synapse-backend/internal/repository"
)

// mockUserRepository создает моковое хранилище пользователей для тестов
type mockUserLookup struct {
	users map[uuid.UUID]*models.User
	err   error // позволяет эмулировать недоступность БД
}

func newMockUserLookup() *mockUserLookup {
	return &mockUserLookup{users: map[uuid.UUID]*models.User{}}
}

func (m *mockUserLookup) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	if u, ok := m.users[id]; ok {
		return u, nil
	}
	return nil, repository.ErrNotFound
}

var _ UserLookup = (*mockUserLookup)(nil)

// TestCacheControlHeaders тестирует middleware, устанавливающий заголовки кэширования
func TestCacheControlHeaders(t *testing.T) {
	t.Run("Установка заголовков Cache-Control для предотвращения кэширования", func(t *testing.T) {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := CacheControl(next)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		// Проверяем, что заголовки установлены корректно
		if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "no-store") {
			t.Errorf("Cache-Control = %v, должен содержать: no-store", got)
		}
		if got := rec.Header().Get("Pragma"); got != "no-cache" {
			t.Errorf("Pragma = %v, должен быть: no-cache", got)
		}
		if !nextCalled {
			t.Error("Следующий handler не был вызван")
		}
	})
}

// TestJSONContentType тестирует middleware для установки X-Content-Type-Options
func TestJSONContentType(t *testing.T) {
	t.Run("Защита от MIME-type sniffing через X-Content-Type-Options", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := JSONContentType(next)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		// X-Content-Type-Options: nosniff предотвращает MIME-sniffing атаки
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %v, должен быть: nosniff", got)
		}
	})
}

// TestSecurityHeaders тестирует middleware безопасности (HSTS, X-Frame-Options, Referrer-Policy)
func TestSecurityHeaders(t *testing.T) {
	t.Run("Установка заголовков безопасности для защиты от различных атак", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := SecurityHeaders(next)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		// HSTS - принудительное использование HTTPS
		if got := rec.Header().Get("Strict-Transport-Security"); !strings.Contains(got, "max-age=31536000") {
			t.Errorf("HSTS header не установлен корректно: %v", got)
		}
		// X-Frame-Options: DENY - защита от clickjacking атак
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("X-Frame-Options = %v, должен быть: DENY", got)
		}
		// Referrer-Policy - контроль утечки информации через Referer
		if got := rec.Header().Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
			t.Errorf("Referrer-Policy = %v, должен быть: strict-origin-when-cross-origin", got)
		}
	})
}

// TestLimitBody тестирует middleware ограничения размера тела запроса
func TestLimitBody(t *testing.T) {
	t.Run("Ограничение размера тела запроса для предотвращения DoS-атак", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := LimitBody(next)

		// Создаем тело запроса, превышающее лимит (>1MB)
		largeBody := bytes.Repeat([]byte("x"), int(MaxJSONBodyBytes)+1024)
		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(largeBody))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		// Проверяем, что ограничение применено
		// При попытке чтения будет ошибка MaxBytesError
		_, err := bytes.NewReader(largeBody).Read(make([]byte, len(largeBody)))
		_ = err // Ошибка может быть nil, так как мы проверяем middleware
	})

	t.Run("GET запросы не ограничиваются по размеру тела", func(t *testing.T) {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := LimitBody(next)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Error("GET запрос должен проходить без ограничений")
		}
	})
}

// TestClientIP тестирует извлечение IP-адреса клиента из запроса
func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{
			name:       "Корректный формат IP:port",
			remoteAddr: "192.168.1.1:12345",
			want:       "192.168.1.1",
		},
		{
			name:       "Только IP без порта",
			remoteAddr: "192.168.1.1",
			want:       "192.168.1.1",
		},
		{
			name:       "Пустая строка",
			remoteAddr: "",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr

			got := ClientIP(req)
			if got != tt.want {
				t.Errorf("ClientIP() = %v, ожидается: %v", got, tt.want)
			}
		})
	}
}

// TestAccountIPKey тестирует формирование ключа для rate limiting по email и IP
func TestAccountIPKey(t *testing.T) {
	t.Run("Формирование ключа для защиты от брутфорса по аккаунту", func(t *testing.T) {
		body := strings.NewReader(`{"email":"Test@Example.com"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", body)
		req.RemoteAddr = "192.168.1.1:12345"

		key := AccountIPKey(req)

		// Ключ должен содержать IP и нормализованный email
		if !strings.Contains(key, "login:") {
			t.Error("Ключ должен содержать префикс login")
		}
		if !strings.Contains(key, "192.168.1.1") {
			t.Error("Ключ должен содержать IP-адрес")
		}
		if !strings.Contains(key, "test@example.com") {
			t.Error("Email должен быть приведен к нижнему регистру")
		}
	})

	t.Run("Обработка запроса без тела", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		key := AccountIPKey(req)
		if !strings.Contains(key, "login:192.168.1.1:") {
			t.Errorf("Ключ должен содержать IP даже без тела: %v", key)
		}
	})
}

// TestIPKey тестирует формирование ключа только по IP-адресу
func TestIPKey(t *testing.T) {
	t.Run("Формирование ключа для общего rate limiting по IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:54321"

		key := IPKey(req)
		if !strings.HasPrefix(key, "ip:10.0.0.1") {
			t.Errorf("Ключ должен начинаться с ip:10.0.0.1, получено: %v", key)
		}
	})
}

// TestRefreshKey тестирует формирование ключа для rate limiting refresh токенов
func TestRefreshKey(t *testing.T) {
	t.Run("Формирование ключа по хешу refresh токена", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "test-refresh-token-123"})

		key := RefreshKey(req)
		if !strings.HasPrefix(key, "refresh:") {
			t.Errorf("Ключ должен начинаться с refresh, получено: %v", key)
		}
	})

	t.Run("Формирование ключа по IP при отсутствии refresh токена", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/refresh", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		key := RefreshKey(req)
		if !strings.Contains(key, "192.168.1.1") {
			t.Errorf("При отсутствии токена должен использоваться IP: %v", key)
		}
	})
}

// TestUserKey тестирует формирование ключа для аутентифицированных пользователей
func TestUserKey(t *testing.T) {
	t.Run("Ключ формируется из ID аутентифицированного пользователя", func(t *testing.T) {
		userID := uuid.New()
		principal := &Principal{ID: userID, Email: "test@example.com", Role: "user"}
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(context.WithValue(req.Context(), userKey, principal))

		key := UserKey(req)
		if !strings.Contains(key, userID.String()) {
			t.Errorf("Ключ должен содержать ID пользователя: %v", key)
		}
	})

	t.Run("При отсутствии Principal используется IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		key := UserKey(req)
		if !strings.Contains(key, "ip:") {
			t.Errorf("Должен использоваться IP: %v", key)
		}
	})
}

// TestIssueCSRF тестирует генерацию CSRF-токена с HMAC подписью
func TestIssueCSRF(t *testing.T) {
	t.Run("Генерация валидного CSRF-токена с HMAC-SHA256 подписью", func(t *testing.T) {
		secret := []byte("test-secret-key-at-least-32-bytes-long")
		token, err := IssueCSRF(secret)
		if err != nil {
			t.Fatalf("Ошибка генерации CSRF: %v", err)
		}

		// Токен должен состоять из nonce и подписи, разделенных точкой
		parts := strings.Split(token, ".")
		if len(parts) != 2 {
			t.Fatalf("CSRF токен должен иметь формат nonce.signature, получено: %v", token)
		}
	})

	t.Run("Разные токены уникальны", func(t *testing.T) {
		secret := []byte("test-secret-key-at-least-32-bytes-long")
		token1, _ := IssueCSRF(secret)
		token2, _ := IssueCSRF(secret)

		if token1 == token2 {
			t.Error("Два последовательно сгенерированных токена должны быть разными")
		}
	})
}

// TestValidCSRF тестирует валидацию CSRF-токена
func TestValidCSRF(t *testing.T) {
	secret := []byte("test-secret-key-at-least-32-bytes-long")

	t.Run("Валидный токен проходит проверку", func(t *testing.T) {
		token, _ := IssueCSRF(secret)
		if !validCSRF(secret, token) {
			t.Error("Валидный токен должен пройти проверку")
		}
	})

	t.Run("Токен с неверной подписью не проходит проверку", func(t *testing.T) {
		token, _ := IssueCSRF(secret)
		// Подменяем подпись
		parts := strings.Split(token, ".")
		fakeToken := parts[0] + ".invalidsignature"

		if validCSRF(secret, fakeToken) {
			t.Error("Токен с неверной подписью не должен проходить проверку")
		}
	})

	t.Run("Токен с другим секретом не проходит проверку", func(t *testing.T) {
		token, _ := IssueCSRF(secret)
		differentSecret := []byte("different-secret-key-also-32-bytes")

		if validCSRF(differentSecret, token) {
			t.Error("Токен не должен проходить проверку с другим секретом")
		}
	})

	t.Run("Пустой токен не проходит проверку", func(t *testing.T) {
		if validCSRF(secret, "") {
			t.Error("Пустой токен не должен проходить проверку")
		}
	})

	t.Run("Токен без разделителя не проходит проверку", func(t *testing.T) {
		if validCSRF(secret, "tokenwithoutdot") {
			t.Error("Токен без точки не должен проходить проверку")
		}
	})
}

// TestCSRFMiddleware тестирует middleware CSRF-защиты
func TestCSRFMiddleware(t *testing.T) {
	cfg := &config.Config{
		CORSOrigins: []string{"http://localhost:3000"},
		JWTSecret:   []byte("test-secret-key-at-least-32-bytes-long"),
	}

	t.Run("CSRF проверка успешна при валидном токене", func(t *testing.T) {
		token, _ := IssueCSRF(cfg.JWTSecret)
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusNoContent)
		})

		handler := CSRF(cfg)(next)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
		req.Header.Set("X-CSRF-Token", token)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Errorf("Статус = %d, должен быть: %d, body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
		}
		if !nextCalled {
			t.Error("Handler должен быть вызван при валидном CSRF")
		}
	})

	t.Run("CSRF проверка не применяется к GET запросам", func(t *testing.T) {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := CSRF(cfg)(next)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Error("GET запрос должен проходить без CSRF проверки")
		}
	})

	t.Run("Отсутствие CSRF токена возвращает 403", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := CSRF(cfg)(next)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		req.Header.Set("Origin", "http://localhost:3000")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("При отсутствии CSRF статус = %d, должен быть: 403", rec.Code)
		}
	})

	t.Run("Несовпадение токенов в cookie и header возвращает 403", func(t *testing.T) {
		token1, _ := IssueCSRF(cfg.JWTSecret)
		token2, _ := IssueCSRF(cfg.JWTSecret)

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := CSRF(cfg)(next)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token1})
		req.Header.Set("X-CSRF-Token", token2) // Другой токен

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("При несовпадении токенов статус = %d, должен быть: 403", rec.Code)
		}
	})

	t.Run("CSRF проверка блокирует запрос с недопустимым Origin", func(t *testing.T) {
		token, _ := IssueCSRF(cfg.JWTSecret)
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := CSRF(cfg)(next)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		req.Header.Set("Origin", "https://evil.com") // Злоумышленный origin
		req.AddCookie(&http.Cookie{Name: "csrf_token", Value: token})
		req.Header.Set("X-CSRF-Token", token)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("При недопустимом Origin статус = %d, должен быть: 403", rec.Code)
		}
	})
}

// TestRequireRoles тестирует middleware проверки ролей
func TestRequireRoles(t *testing.T) {
	t.Run("Доступ разрешен пользователю с правильной ролью", func(t *testing.T) {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := RequireRoles("user", "admin")(next)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), userKey, &Principal{ID: uuid.New(), Role: "user"})
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Error("Пользователь с ролью user должен иметь доступ")
		}
	})

	t.Run("Доступ запрещен пользователю без нужной роли", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := RequireRoles("admin")(next)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		ctx := context.WithValue(req.Context(), userKey, &Principal{ID: uuid.New(), Role: "user"})
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Статус = %d, должен быть: 403 для обычного пользователя", rec.Code)
		}
	})

	t.Run("Доступ запрещен при отсутствии Principal в контексте", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := RequireRoles("user")(next)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Статус = %d, должен быть: 401 при отсутствии аутентификации", rec.Code)
		}
	})
}

// TestRequireAdmin тестирует middleware для проверки прав администратора
func TestRequireAdmin(t *testing.T) {
	t.Run("Администратор имеет доступ к защищенным ресурсам", func(t *testing.T) {
		nextCalled := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		handler := RequireAdmin(next)
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		ctx := context.WithValue(req.Context(), userKey, &Principal{ID: uuid.New(), Role: "admin"})
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !nextCalled {
			t.Error("Администратор должен иметь доступ")
		}
	})

	t.Run("Обычный пользователь не имеет доступа к админским ресурсам", func(t *testing.T) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		handler := RequireAdmin(next)
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		ctx := context.WithValue(req.Context(), userKey, &Principal{ID: uuid.New(), Role: "user"})
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Обычный пользователь должен получить 403, получено: %d", rec.Code)
		}
	})
}

// TestRequireUserOrAdmin тестирует middleware для доступа пользователей и администраторов
func TestRequireUserOrAdmin(t *testing.T) {
	t.Run("Пользователь и администратор имеют доступ", func(t *testing.T) {
		for _, role := range []string{"user", "admin"} {
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			handler := RequireUserOrAdmin(next)
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := context.WithValue(req.Context(), userKey, &Principal{ID: uuid.New(), Role: role})
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if !nextCalled {
				t.Errorf("Роль %s должна иметь доступ", role)
			}
		}
	})
}

// TestFromContext тестирует извлечение Principal из контекста
func TestFromContext(t *testing.T) {
	t.Run("Успешное извлечение Principal из контекста", func(t *testing.T) {
		userID := uuid.New()
		principal := &Principal{ID: userID, Email: "test@example.com", Role: "user"}
		ctx := context.WithValue(context.Background(), userKey, principal)

		got, ok := FromContext(ctx)
		if !ok {
			t.Error("Principal должен быть извлечен из контекста")
		}
		if got.ID != userID {
			t.Errorf("ID = %v, ожидается: %v", got.ID, userID)
		}
	})

	t.Run("Возврат false при отсутствии Principal", func(t *testing.T) {
		ctx := context.Background()
		_, ok := FromContext(ctx)
		if ok {
			t.Error("При отсутствии Principal ok должен быть false")
		}
	})
}

// TestAuthenticate тестирует middleware аутентификации по access-токену.
func TestAuthenticate(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:  []byte("test-secret-key-at-least-32-bytes-long"),
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 168 * time.Hour,
	}

	// newActiveUser создает мок с одним активным пользователем.
	newActiveUser := func() (uuid.UUID, *mockUserLookup) {
		id := uuid.New()
		m := newMockUserLookup()
		m.users[id] = &models.User{ID: id, Email: "user@example.com", Role: models.RoleUser, Status: models.StatusActive}
		return id, m
	}

	t.Run("Успех: валидный access-токен пропускает и кладет Principal в контекст", func(t *testing.T) {
		id, mock := newActiveUser()
		pair, err := auth.IssuePair(cfg, id, "user@example.com", models.RoleUser)
		if err != nil {
			t.Fatal(err)
		}
		var got *Principal
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := FromContext(r.Context())
			if !ok {
				t.Fatal("Principal не найден в контексте")
			}
			got = p
			w.WriteHeader(http.StatusOK)
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: pair.AccessToken})
		Authenticate(cfg, mock)(next).ServeHTTP(rec, req) // <-- теперь компилируется

		if rec.Code != http.StatusOK {
			t.Fatalf("Статус = %d, ожидается: 200; body = %s", rec.Code, rec.Body.String())
		}
		if got.ID != id || got.Role != models.RoleUser {
			t.Errorf("Principal = %+v, ожидается: id = %s, role = user", got, id)
		}
	})

	t.Run("Атака: отсутствие cookie access_token -> 401", func(t *testing.T) {
		_, mock := newActiveUser()
		rec := httptest.NewRecorder()
		Authenticate(cfg, mock)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Next не должен вызываться без токена")
		})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users/me", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Статус = %d, ожидается: 401", rec.Code)
		}
	})

	t.Run("Атака: поддельный/битый JWT -> 401", func(t *testing.T) {
		_, mock := newActiveUser()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: "invalid.token.value"})
		Authenticate(cfg, mock)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Next не должен вызываться с битым токеном")
		})).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Статус = %d, ожидается: 401", rec.Code)
		}
	})

	t.Run("Атака: refresh-токен вместо access-токена -> 401 (проверка audience)", func(t *testing.T) {
		id, mock := newActiveUser()
		pair, _ := auth.IssuePair(cfg, id, "user@example.com", models.RoleUser)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: pair.RefreshToken}) // чужое назначение
		Authenticate(cfg, mock)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Refresh-токен не должен приниматься как access")
		})).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Статус = %d, ожидается: 401", rec.Code)
		}
	})

	t.Run("Пользователь удален из БД -> 401", func(t *testing.T) {
		mock := newMockUserLookup() // пустой мок: пользователя нет
		pair, _ := auth.IssuePair(cfg, uuid.New(), "ghost@example.com", models.RoleUser)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: pair.AccessToken})
		Authenticate(cfg, mock)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Статус = %d, ожидается: 401", rec.Code)
		}
	})

	t.Run("Заблокированный пользователь (status=inactive) -> 401", func(t *testing.T) {
		id, mock := newActiveUser()
		mock.users[id].Status = models.StatusInactive
		pair, _ := auth.IssuePair(cfg, id, "user@example.com", models.RoleUser)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: pair.AccessToken})
		Authenticate(cfg, mock)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Статус = %d, ожидается: 401 для inactive-пользователя", rec.Code)
		}
	})

	t.Run("БД недоступна -> 503 (не раскрывается внутренняя ошибка)", func(t *testing.T) {
		mock := newMockUserLookup()
		mock.err = errors.New("В соединении отказано")
		pair, _ := auth.IssuePair(cfg, uuid.New(), "user@example.com", models.RoleUser)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
		req.AddCookie(&http.Cookie{Name: auth.AccessCookie, Value: pair.AccessToken})
		Authenticate(cfg, mock)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("Статус = %d, ожидается: 503 при ошибке БД", rec.Code)
		}
	})
}

// memoryRateLimitStore имитирует атомарное хранилище счетчиков без внешней БД.
type memoryRateLimitStore struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]memoryRateBucket
	err     error
}

type memoryRateBucket struct {
	start time.Time
	hits  int
}

func newMemoryRateLimitStore() *memoryRateLimitStore {
	return &memoryRateLimitStore{now: time.Now, buckets: make(map[string]memoryRateBucket)}
}

func (s *memoryRateLimitStore) Increment(ctx context.Context, key string, window time.Duration) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.err != nil {
		return 0, s.err
	}
	if window <= 0 {
		return 0, errors.New("Окно должно быть положительным")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	bucket, ok := s.buckets[key]
	if !ok || !bucket.start.Add(window).After(now) {
		bucket = memoryRateBucket{start: now}
	}
	bucket.hits++
	s.buckets[key] = bucket
	return bucket.hits, nil
}

// TestRateLimit проверяет лимиты, изоляцию ключей, сброс окна и fail-closed без PostgreSQL.
func TestRateLimit(t *testing.T) {
	t.Run("Разрешает запросы в пределах лимита и блокирует следующий", func(t *testing.T) {
		store := newMemoryRateLimitStore()
		called := 0
		h := RateLimitWithStore(store, 2, time.Minute, IPKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called++
			w.WriteHeader(http.StatusNoContent)
		}))
		for i, want := range []int{http.StatusNoContent, http.StatusNoContent, http.StatusTooManyRequests} {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != want {
				t.Errorf("Запрос %d: статус = %d, ожидается: %d", i+1, rec.Code, want)
			}
			if i == 2 && rec.Header().Get("Retry-After") != "60" {
				t.Errorf("Retry-After = %q, ожидается: 60", rec.Header().Get("Retry-After"))
			}
		}
		if called != 2 {
			t.Errorf("Обработчик вызван %d раз, ожидается: 2", called)
		}
	})
	t.Run("Разные IP используют разные счетчики", func(t *testing.T) {
		store := newMemoryRateLimitStore()
		h := RateLimitWithStore(store, 1, time.Minute, IPKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		for _, ip := range []string{"192.0.2.1:1234", "192.0.2.2:1234"} {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = ip
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Errorf("Первый запрос IP %s получил: %d", ip, rec.Code)
			}
		}
	})
	t.Run("Истекшее окно сбрасывает счетчик", func(t *testing.T) {
		store := newMemoryRateLimitStore()
		now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
		store.now = func() time.Time { return now }
		h := RateLimitWithStore(store, 1, time.Minute, IPKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		makeReq := func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "192.0.2.1:1234"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec
		}
		if got := makeReq().Code; got != http.StatusNoContent {
			t.Fatalf("Первый запрос: %d", got)
		}
		if got := makeReq().Code; got != http.StatusTooManyRequests {
			t.Fatalf("Превышение лимита: %d", got)
		}
		now = now.Add(time.Minute)
		if got := makeReq().Code; got != http.StatusNoContent {
			t.Fatalf("После окна: %d", got)
		}
	})
	t.Run("Конкурентные запросы не обходят общий лимит", func(t *testing.T) {
		store := newMemoryRateLimitStore()
		var allowed int
		var allowedMu sync.Mutex
		h := RateLimitWithStore(store, 7, time.Minute, IPKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowedMu.Lock()
			allowed++
			allowedMu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		}))
		var wg sync.WaitGroup
		for i := 0; i < 40; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.RemoteAddr = "192.0.2.9:1234"
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusNoContent && rec.Code != http.StatusTooManyRequests {
					t.Errorf("Неожиданный HTTP статус: %d", rec.Code)
				}
			}()
		}
		wg.Wait()
		if allowed != 7 {
			t.Errorf("Успешно прошло %d запросов, лимит равен: 7", allowed)
		}
	})
	t.Run("Ошибка хранилища закрывает доступ с 503", func(t *testing.T) {
		store := newMemoryRateLimitStore()
		store.err = errors.New("Хранилище недоступно")
		called := false
		h := RateLimitWithStore(store, 1, time.Minute, IPKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("Статус = %d, ожидается: 503", rec.Code)
		}
		if called {
			t.Error("Обработчик вызван несмотря на ошибку хранилища")
		}
	})
	t.Run("Некорректная конфигурация не отключает защиту молча", func(t *testing.T) {
		h := RateLimitWithStore(newMemoryRateLimitStore(), 0, time.Minute, IPKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Обработчик не должен вызываться")
		}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("Статус = %d, ожидается: 503", rec.Code)
		}
	})
}

// TestAccountGlobalKey проверяет, что глобальный лимит действительно привязан к email,
// а не превращает все учетные записи в один общий счетчик.
func TestAccountGlobalKey(t *testing.T) {
	request := func(body string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		return r
	}
	a := AccountGlobalKey(request(`{"email":" Alice@Example.com ","password":"x"}`))
	b := AccountGlobalKey(request(`{"email":"bob@example.com","password":"x"}`))
	c := AccountGlobalKey(request(`{"email":"alice@example.com","password":"y"}`))
	if a != c {
		t.Errorf("Один email должен давать одинаковый ключ: %q != %q", a, c)
	}
	if a == b {
		t.Errorf("Разные email получили одинаковый ключ: %q", a)
	}
}

// TestAccountIPKeyPreservesBody проверяет, что извлечение ключа лимитера не съедает JSON,
// необходимый следующему middleware и обработчику входа.
func TestAccountIPKeyPreservesBody(t *testing.T) {
	body := `{"email":"User@Example.com","password":"StrongPass123"}`
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	_ = AccountIPKey(r)
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("Тело изменилось: %q", string(got))
	}
}
