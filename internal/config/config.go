package config

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	AppPort            string
	AppEnv             string
	DatabaseURL        string
	JWTSecret          []byte
	AccessTTL          time.Duration
	RefreshTTL         time.Duration
	AdminRegisterToken string
	CookieSecure       bool
	CookieSameSite     http.SameSite
	CookieDomain       string
	CookiePath         string
	CORSOrigins        []string
	LoginRateLimit     int
	RegisterRateLimit  int
	RefreshRateLimit   int
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	accessTTL, err := time.ParseDuration(env("ACCESS_TOKEN_TTL", "15m"))
	if err != nil {
		return nil, fmt.Errorf("ACCESS_TOKEN_TTL: %w", err)
	}
	refreshTTL, err := time.ParseDuration(env("REFRESH_TOKEN_TTL", "168h"))
	if err != nil {
		return nil, fmt.Errorf("REFRESH_TOKEN_TTL: %w", err)
	}

	secret := env("JWT_SECRET", "")
	if secret == "" {
		return nil, fmt.Errorf("Необходимо указать JWT_SECRET")
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET должен содержать не менее 32 символов для безопасной работы алгоритма HS256")
	}

	adminToken := env("ADMIN_REGISTER_TOKEN", "")
	if adminToken == "" {
		return nil, fmt.Errorf("Необходимо указать ADMIN_REGISTER_TOKEN")
	}

	dbURL := env("DATABASE_URL", "")
	if dbURL == "" {
		user := env("POSTGRES_USER", "synapse-default-user")
		pass := env("POSTGRES_PASSWORD", "synapse-default-password")
		host := env("POSTGRES_HOST", "localhost")
		port := env("POSTGRES_PORT", "5432")
		name := env("POSTGRES_DB", "synapse-default-db")
		dbURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, pass, host, port, name)
	}

	sameSite := http.SameSiteLaxMode
	switch strings.ToLower(env("COOKIE_SAMESITE", "Lax")) {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}

	origins := []string{}
	for _, o := range strings.Split(env("CORS_ORIGINS", "http://localhost:3000"), ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			origins = append(origins, o)
		}
	}

	return &Config{
		AppPort:            env("APP_PORT", "8080"),
		AppEnv:             env("APP_ENV", "synapse-backend"),
		DatabaseURL:        dbURL,
		JWTSecret:          []byte(secret),
		AccessTTL:          accessTTL,
		RefreshTTL:         refreshTTL,
		AdminRegisterToken: adminToken,
		CookieSecure:       env("COOKIE_SECURE", "true") == "true",
		CookieSameSite:     sameSite,
		CookieDomain:       env("COOKIE_DOMAIN", ""),
		CookiePath:         "/api/v1/",
		CORSOrigins:        origins,
		LoginRateLimit:     intEnv("LOGIN_RATE_LIMIT", 10),
		RegisterRateLimit:  intEnv("REGISTER_RATE_LIMIT", 10),
		RefreshRateLimit:   intEnv("REFRESH_RATE_LIMIT", 30),
	}, nil
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func intEnv(key string, fallback int) int {
	v, err := strconv.Atoi(env(key, strconv.Itoa(fallback)))
	if err != nil || v < 1 {
		return fallback
	}
	return v
}
