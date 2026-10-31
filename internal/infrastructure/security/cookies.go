package auth

import (
	"net/http"
	"time"

	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
)

const (
	AccessCookie  = "access_token"
	RefreshCookie = "refresh_token"
)

func SetTokenCookies(w http.ResponseWriter, cfg *config.Config, pair *Pair) {
	setCookie(w, cfg, AccessCookie, pair.AccessToken, pair.AccessExp)
	setCookie(w, cfg, RefreshCookie, pair.RefreshToken, pair.RefreshExp)
}

// SetAuthCookies — установочный cookie-хелпер для веб-клиентов (алиас
// SetTokenCookies с именем, отражающим назначение: аутентификационная пара
// access_token + refresh_token как HttpOnly cookie). Используется HTTP-слоем,
// когда X-Client-Platform != "mobile". Для мобильных клиентов cookie НЕ
// устанавливаются — токены возвращаются в JSON-теле.
func SetAuthCookies(w http.ResponseWriter, cfg *config.Config, pair *Pair) {
	SetTokenCookies(w, cfg, pair)
}

func ClearTokenCookies(w http.ResponseWriter, cfg *config.Config) {
	expired := time.Unix(0, 0)
	setCookie(w, cfg, AccessCookie, "", expired)
	setCookie(w, cfg, RefreshCookie, "", expired)
}

// CSRFCookie — имя cookie двухсоставной CSRF-защиты (читается JS-ом,
// поэтому HttpOnly=false; живёт на пути /api/v1/).
const CSRFCookie = "csrf_token"

// ClearAuthCookies полностью завершает браузерную сессию: сбрасывает
// access_token, refresh_token И csrf_token (Max-Age=-1). Используется при
// logout и самоудалении аккаунта (DELETE /users/me), чтобы браузер не
// сохранил мёртвые, но долгоживущие auth-куки.
func ClearAuthCookies(w http.ResponseWriter, cfg *config.Config) {
	ClearTokenCookies(w, cfg)
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookie,
		Value:    "",
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: false, // csrf_token выпускается JS-читаемой — удаляем симметрично
		Secure:   cfg.CookieSecure,
		SameSite: cfg.CookieSameSite,
	})
}

func setCookie(w http.ResponseWriter, cfg *config.Config, name, value string, exp time.Time) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		Expires:  exp,
		MaxAge:   int(time.Until(exp).Seconds()),
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: cfg.CookieSameSite,
	}
	if exp.Before(time.Now()) || value == "" {
		c.MaxAge = -1
		c.Expires = time.Unix(0, 0)
	}
	http.SetCookie(w, c)
}

func ReadCookie(r *http.Request, name string) (string, error) {
	c, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	return c.Value, nil
}
