package handler

// Детекция платформы клиента и формата ответа — задача delivery-слоя.
// domain и usecase ничего не знают ни о cookie, ни о заголовке
// Authorization, ни о X-Client-Platform: единые хелперы живут в
// infrastructure/middleware, а handlers используют их как тонкие обёртки.
//
// Разделение ответственности (см. docs/MOBILE_INTEGRATION.md):
//   - X-Client-Platform определяет ТОЛЬКО формат ответа (cookie vs JSON-токены);
//   - CSRF/Origin определяются фактическим способом аутентификации
//     (Bearer vs cookie) в middleware — заголовок платформы на это не влияет.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/middleware"
	"github.com/trauringetag/synapse-backend/internal/usecase"
)

// isMobilePlatform возвращает true, если клиент заявил X-Client-Platform: mobile.
// Отсутствие или невалидное значение заголовка трактуется как "web" — полная
// обратная совместимость с существующими веб-клиентами.
func isMobilePlatform(r *http.Request) bool {
	return middleware.ClientPlatform(r) == "mobile"
}

// bearerToken возвращает токен из Authorization: Bearer <token>
// (схема case-insensitive, пробелы вокруг токена обрезаются) либо пустую
// строку. Значение токена никогда не логируется.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

const refreshCookieName = "refresh_token"

// refreshCredential извлекает refresh-токен для POST /refresh и POST /logout
// с чётким приоритетом источников (смешивание исключено):
//  1. Authorization: Bearer <refresh_token> — мобильные/серверные клиенты;
//  2. HttpOnly cookie refresh_token — веб-клиенты;
//  3. JSON-поле {"refresh_token": "..."} в теле запроса — альтернатива для
//     мобильных клиентов (тело читается без потребления: буфер возвращается
//     обратно в r.Body).
//
// hasToken == false означает, что ни один источник не предоставил непустой
// токен (для /logout это допустимо: возвращается 200 без отзыва сессии).
func refreshCredential(r *http.Request) (token string, hasToken bool) {
	// Приоритет 1: Bearer.
	if t := bearerToken(r); t != "" {
		return t, true
	}
	// Приоритет 2: cookie.
	if c, err := r.Cookie(refreshCookieName); err == nil && c.Value != "" {
		return c.Value, true
	}
	// Приоритет 3: JSON-тело (только POST с содержимым).
	if r.Method == http.MethodPost && r.Body != nil && r.ContentLength != 0 {
		b, err := io.ReadAll(io.LimitReader(r.Body, middleware.MaxJSONBodyBytes+1))
		r.Body.Close()
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		if err == nil && int64(len(b)) <= middleware.MaxJSONBodyBytes {
			var body struct {
				RefreshToken string `json:"refresh_token"`
			}
			if json.Unmarshal(b, &body) == nil && strings.TrimSpace(body.RefreshToken) != "" {
				return strings.TrimSpace(body.RefreshToken), true
			}
		}
	}
	return "", false
}

// tokenResponse — контракт ответа для мобильных клиентов
// (X-Client-Platform: mobile): JWT возвращаются в JSON-теле, cookie НЕ
// устанавливаются. Ответ всегда имеет Cache-Control: no-store (гарантирует
// middleware.CacheControl для всех путей /api/v1).
type tokenResponse struct {
	AccessToken      string       `json:"access_token"`
	RefreshToken     string       `json:"refresh_token"`
	TokenType        string       `json:"token_type"`
	ExpiresIn        int          `json:"expires_in"`
	RefreshExpiresIn int          `json:"refresh_expires_in"`
	User             *domain.User `json:"user"`
}

// loginResponse — ответ веб-клиента: сообщение + профиль пользователя.
// Токенов в теле нет (риск XSS): они живут только в HttpOnly cookie.
type loginResponse struct {
	Message string       `json:"message"`
	User    *domain.User `json:"user"`
}

// newTokenResponse собирает мобильный JSON-ответ из пары токенов use-case DTO.
func newTokenResponse(pair *usecase.TokenPair, user *domain.User) tokenResponse {
	return tokenResponse{
		AccessToken:      pair.AccessToken,
		RefreshToken:     pair.RefreshToken,
		TokenType:        "Bearer",
		ExpiresIn:        int(time.Until(pair.AccessExp).Seconds()),
		RefreshExpiresIn: int(time.Until(pair.RefreshExp).Seconds()),
		User:             user,
	}
}
