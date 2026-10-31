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

// credentialSource — фактический источник credentials для /refresh и /logout.
// Формат ответа (Web-Flow cookie vs Mobile-Flow JSON) определяется ИМЕННО им,
// а не заявленным заголовком X-Client-Platform: заголовок контролируется
// клиентом и может быть подделан (эксфильтрация refresh/access токенов в
// JSON-теле веб-сессией). Браузер отправляет cookie автоматически ->
// наличие cookie refresh_token всегда означает Web-Flow.
type credentialSource int

const (
	sourceNone credentialSource = iota
	// sourceCookie — HttpOnly cookie refresh_token (веб-клиент): ответ
	// всегда через Set-Cookie, токены в теле НЕ возвращаются.
	sourceCookie
	// sourceBearer — Authorization: Bearer <refresh> без auth-cookie
	// (мобильный/серверный клиент): токены в JSON-теле.
	sourceBearer
	// sourceBody — JSON-поле {"refresh_token": "..."} без cookie/Bearer
	// (альтернатива для мобильных): токены в JSON-теле.
	sourceBody
	// sourceConflict — смешанные credentials (Bearer + cookie одновременно).
	// Контрактом это запрещено: приоритет источников фиксирован, смешивание
	// исключено -> 409 Conflict, ротация не выполняется.
	sourceConflict
)

// hasAuthCookies проверяет наличие ЛЮБОЙ авторизационной cookie в запросе
// (access_token или refresh_token). Это индикатор браузерного (cookie)
// клиента: такой запрос никогда не должен получать токены в JSON-теле.
func hasAuthCookies(r *http.Request) bool {
	if _, err := r.Cookie(refreshCookieName); err == nil {
		return true
	}
	if _, err := r.Cookie("access_token"); err == nil {
		return true
	}
	return false
}

// bodyRefreshToken читает refresh_token из JSON-тела без потребления тела
// (буфер возвращается обратно в r.Body). Пустая строка — поля нет/тело не JSON.
func bodyRefreshToken(r *http.Request) string {
	if r.Method != http.MethodPost || r.Body == nil || r.ContentLength == 0 {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, middleware.MaxJSONBodyBytes+1))
	r.Body.Close()
	r.Body = io.NopCloser(strings.NewReader(string(b)))
	if err != nil || int64(len(b)) > middleware.MaxJSONBodyBytes {
		return ""
	}
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if json.Unmarshal(b, &body) != nil {
		return ""
	}
	return strings.TrimSpace(body.RefreshToken)
}

// refreshCredential извлекает refresh-токен для POST /refresh и POST /logout
// вместе с фактическим источником credentials (source), который определяет
// формат ответа:
//  1. Cookie refresh_token -> sourceCookie (Web-Flow): даже если клиент заявил
//     X-Client-Platform: mobile — это защита от эксфильтрации токенов через
//     подмену заголовка;
//  2. Bearer + cookie одновременно -> sourceConflict (409, токен не используется);
//  3. Bearer без auth-cookie -> sourceBearer (Mobile-Flow);
//  4. JSON-поле {"refresh_token": "..."} без cookie/Bearer -> sourceBody
//     (Mobile-Flow; тело читается без потребления).
//
// token == "" означает, что ни один источник не предоставил непустой токен
// (для /logout это допустимо: возвращается 200 без отзыва сессии).
func refreshCredential(r *http.Request) (token string, source credentialSource) {
	bearer := bearerToken(r)
	cookieVal := ""
	if c, err := r.Cookie(refreshCookieName); err == nil {
		cookieVal = c.Value
	}

	switch {
	case cookieVal != "" && bearer != "":
		// Смешанные credentials запрещены контрактом.
		return "", sourceConflict
	case cookieVal != "":
		// Приоритет cookie: Web-Flow принудительно, заголовок платформы игнорируется.
		return cookieVal, sourceCookie
	case bearer != "":
		if hasAuthCookies(r) {
			// Bearer + auth-cookie (даже пустая) — неоднозначный браузерный
			// запрос: мобильный JSON-формат браузеру не отдаём.
			return "", sourceConflict
		}
		return bearer, sourceBearer
	default:
		if t := bodyRefreshToken(r); t != "" {
			if hasAuthCookies(r) {
				return "", sourceConflict
			}
			return t, sourceBody
		}
		return "", sourceNone
	}
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
