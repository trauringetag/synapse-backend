package auth

import (
	"net/http"
	"time"

	"github.com/trauringetag/synapse-backend/internal/config"
)

const (
	AccessCookie  = "access_token"
	RefreshCookie = "refresh_token"
)

func SetTokenCookies(w http.ResponseWriter, cfg *config.Config, pair *Pair) {
	setCookie(w, cfg, AccessCookie, pair.AccessToken, pair.AccessExp)
	setCookie(w, cfg, RefreshCookie, pair.RefreshToken, pair.RefreshExp)
}

func ClearTokenCookies(w http.ResponseWriter, cfg *config.Config) {
	expired := time.Unix(0, 0)
	setCookie(w, cfg, AccessCookie, "", expired)
	setCookie(w, cfg, RefreshCookie, "", expired)
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
