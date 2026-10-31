package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	AppPort string
	// AppEnv — имя/описание сервиса (историческое поле, не окружение запуска).
	AppEnv string
	// Environment — режим развёртывания (ENVIRONMENT): development (по умолчанию),
	// staging, production. В production включается fail-fast валидация (SEC-03):
	// запуск с дефолтными секретами/небезопасными настройками невозможен.
	Environment        string
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
	// TrustedProxies — whitelist доверенных reverse-прокси (TRUSTED_PROXIES,
	// CSV: точные IP или CIDR). Определяет, кому RealIP разрешает переопределять
	// клиентский адрес заголовками X-Forwarded-For/X-Real-IP/True-Client-IP (SEC-05).
	// Пустой список ⇒ заголовки игнорируются полностью, используется r.RemoteAddr.
	TrustedProxies         []string
	LoginRateLimit         int
	RegisterRateLimit      int
	RefreshRateLimit       int
	LogoutRateLimit        int
	AuthenticatedRateLimit int
	// RateLimitCleanupInterval — как часто фоновый воркер удаляет устаревшие
	// строки из api_rate_limits (RATE_LIMIT_CLEANUP_INTERVAL, по умолчанию 1h).
	RateLimitCleanupInterval time.Duration
	// RateLimitMaxWindowSeconds — максимально возможное окно лимитов в системе
	// в секундах (RATE_LIMIT_MAX_WINDOW_SECONDS, по умолчанию 3600 — 1 час для
	// регистрации). Записи старше window_start + maxWindow удаляются.
	RateLimitMaxWindowSeconds int
	// RateLimitHMACKey — отдельный ключ (RATE_LIMIT_HMAC_KEY) для HMAC-SHA256
	// хеширования PII (email/IP) в ключах таблицы api_rate_limits. Email и IP
	// никогда не хранятся в открытом виде: bucket_key =
	// rl:<route_policy>:<version>:<hmac(...)> (защита от Account-Lockout DoS и
	// разделение rate-limit между маршрутами). В production обязателен; вне
	// production при отсутствии выводится детерминированно из JWT_SECRET
	// (доменный разделитель "synapse-rate-limit-hmac-key-v1"), чтобы ключ
	// лимитеров никогда не был тем же самым секретом, что и JWT/CSRF.
	RateLimitHMACKey []byte
}

// rateLimitHMACKeyDomain — доменный разделитель HKDF-подобного вывода
// RateLimitHMACKey из JWT_SECRET (используется только когда отдельный ключ
// не задан в конфигурации окружения).
const rateLimitHMACKeyDomain = "synapse-rate-limit-hmac-key-v1"

// SEC-03: дефолтные/небезопасные значения, которые запрещены в production.
// Совпадение с любым из них (или префикс CHANGE_ME_*) — fail-fast при запуске.
const (
	// DefaultJWTSecret — историческое значение по умолчанию из старых версий .env.example.
	DefaultJWTSecret = "change-me-to-a-long-random-secret"
	// DefaultAdminRegisterToken — историческое значение по умолчанию.
	DefaultAdminRegisterToken = "change-me-admin-register-token"
)

// DefaultInsecureSecrets — список значений JWT_SECRET, наличие которых в
// production означает, что секрет никто не менял.
var DefaultInsecureSecrets = []string{
	DefaultJWTSecret,
	"secret",
	"changeme",
	"change-me",
	"change-me-to-a-long-random-secret",
	"test-secret-key-for-development-only",
}

// placeholderPrefix — плейсхолдеры из .env.example, которые принципиально не
// должны допускаться к запуску ни в одном окружении (в особенности в production).
const placeholderPrefix = "CHANGE_ME_"

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

	cleanupInterval := durationEnv("RATE_LIMIT_CLEANUP_INTERVAL", time.Hour)

	secret := env("JWT_SECRET", "")
	if secret == "" {
		return nil, fmt.Errorf("Необходимо указать JWT_SECRET")
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET должен содержать не менее 32 символов для безопасной работы алгоритма HS256")
	}
	// Плейсхолдеры из .env.example (CHANGE_ME_*) не должны проходить валидацию
	// запуска НИ В ОДНОМ окружении — иначе продакши-деплой «случайно» стартует
	// с общеизвестным секретом.
	if strings.HasPrefix(secret, placeholderPrefix) {
		return nil, fmt.Errorf("JWT_SECRET содержит плейсхолдер %q: сгенерируйте случайный секрет (например, openssl rand -base64 48)", placeholderPrefix+"...")
	}

	adminToken := env("ADMIN_REGISTER_TOKEN", "")
	if adminToken == "" {
		return nil, fmt.Errorf("Необходимо указать ADMIN_REGISTER_TOKEN")
	}
	if strings.HasPrefix(adminToken, placeholderPrefix) {
		return nil, fmt.Errorf("ADMIN_REGISTER_TOKEN содержит неизменённый плейсхолдер %q", placeholderPrefix+"...")
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

	trustedProxies := []string{}
	for _, p := range strings.Split(env("TRUSTED_PROXIES", ""), ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			trustedProxies = append(trustedProxies, p)
		}
	}

	// Отдельный ключ HMAC для хеширования PII в ключах rate-limit. Если не
	// задан — выводится детерминированно из JWT_SECRET с доменным
	// разделителем (HMAC(key=JWT_SECRET, msg=domain)), а НЕ используется как
	// есть: секреты разных назначений не пересекются. В production явный
	// RATE_LIMIT_HMAC_KEY обязателен (см. Validate).
	hmacKey := []byte(env("RATE_LIMIT_HMAC_KEY", ""))
	if len(hmacKey) == 0 && secret != DefaultJWTSecret {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(rateLimitHMACKeyDomain))
		hmacKey = mac.Sum(nil)
	}

	cfg := &Config{
		AppPort:                   env("APP_PORT", "8080"),
		AppEnv:                    env("APP_ENV", "synapse-backend"),
		Environment:               strings.ToLower(env("ENVIRONMENT", "development")),
		DatabaseURL:               dbURL,
		JWTSecret:                 []byte(secret),
		AccessTTL:                 accessTTL,
		RefreshTTL:                refreshTTL,
		AdminRegisterToken:        adminToken,
		CookieSecure:              env("COOKIE_SECURE", "true") == "true",
		CookieSameSite:            sameSite,
		CookieDomain:              env("COOKIE_DOMAIN", ""),
		CookiePath:                "/api/v1/",
		CORSOrigins:               origins,
		TrustedProxies:            trustedProxies,
		LoginRateLimit:            intEnv("LOGIN_RATE_LIMIT", 10),
		RegisterRateLimit:         intEnv("REGISTER_RATE_LIMIT", 10),
		RefreshRateLimit:          intEnv("REFRESH_RATE_LIMIT", 30),
		LogoutRateLimit:           intEnv("LOGOUT_RATE_LIMIT", 10),
		AuthenticatedRateLimit:    intEnv("AUTHENTICATED_RATE_LIMIT", 600),
		RateLimitCleanupInterval:  cleanupInterval,
		RateLimitMaxWindowSeconds: intEnv("RATE_LIMIT_MAX_WINDOW_SECONDS", 3600),
		RateLimitHMACKey:          hmacKey,
	}

	// Fail-fast (SEC-03): в production запуск с дефолтными/небезопасными
	// значениями невозможен — ошибка вернётся сюда же, main.go завершится
	// log.Fatalf до поднятия HTTP-сервера.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// isProduction возвращает true, если окружение развёртывания — production.
func (c *Config) isProduction() bool {
	return strings.EqualFold(strings.TrimSpace(c.Environment), "production")
}

// Validate выполняет fail-fast проверку конфигурации (SEC-03). Вне production
// проверка ограничивается базовыми инвариантами; в production дополнительно
// запрещены: дефолтный/плейсхолдерный JWT_SECRET, COOKIE_SECURE=false и
// DATABASE_URL с sslmode=disable. Все найденные проблемы возвращаются одной
// сводной ошибкой, чтобы один запуск показал полный список.
func (c *Config) Validate() error {
	var problems []string

	// Базовые инварианты (для всех окружений).
	if len(c.JWTSecret) < 32 {
		problems = append(problems, fmt.Sprintf(
			"JWT_SECRET слишком короткий (%d байт; требуется не менее 32)", len(c.JWTSecret)))
	}
	if string(c.JWTSecret) == "" {
		problems = append(problems, "JWT_SECRET не задан")
	}

	if !c.isProduction() {
		if len(problems) > 0 {
			return fmt.Errorf("некорректная конфигурация: %s", strings.Join(problems, "; "))
		}
		return nil
	}

	// Production: секреты не должны совпадать с дефолтными/плейсхолдерными.
	secrets := string(c.JWTSecret)
	if strings.HasPrefix(secrets, placeholderPrefix) {
		problems = append(problems, "JWT_SECRET содержит неизменённый плейсхолдер CHANGE_ME_*")
	} else {
		for _, bad := range DefaultInsecureSecrets {
			if secrets == bad {
				problems = append(problems, fmt.Sprintf(
					"JWT_SECRET совпадает с общеизвестным дефолтным значением %q", bad))
				break
			}
		}
	}
	if strings.HasPrefix(c.AdminRegisterToken, placeholderPrefix) ||
		c.AdminRegisterToken == DefaultAdminRegisterToken {
		problems = append(problems, "ADMIN_REGISTER_TOKEN содержит дефолтное/плейсхолдерное значение")
	}

	// Production: secure-cookie и TLS к БД обязательны.
	if !c.CookieSecure {
		problems = append(problems, "COOKIE_SECURE=false в production недопустим (auth-куки уходят по HTTP)")
	}
	if strings.Contains(strings.ToLower(c.DatabaseURL), "sslmode=disable") {
		problems = append(problems, "DATABASE_URL содержит sslmode=disable — в production обязано TLS-соединение с PostgreSQL")
	}
	// Production: отдельный ключ HMAC для rate-limit обязателен и должен быть
	// достаточно длинным; вывод из JWT_SECRET допустим только вне production.
	// Проверяем явно заданный env (RATE_LIMIT_HMAC_KEY): Load кладёт в поле
	// выведенный из JWT_SECRET ключ, который сам по себе не считается
	// "отдельным секретом" для production.
	if len(env("RATE_LIMIT_HMAC_KEY", "")) < 32 {
		problems = append(problems, "RATE_LIMIT_HMAC_KEY не задан или короче 32 символов — в production обязателен отдельный секрет для хеширования PII в ключах api_rate_limits")
	}

	if len(problems) > 0 {
		return fmt.Errorf("fail-fast (ENVIRONMENT=production): %s", strings.Join(problems, "; "))
	}
	return nil
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

// durationEnv читает длительность (time.ParseDuration) из переменной окружения.
// Используется для настроек фоновых задач (например, интервала очистки).
func durationEnv(key string, fallback time.Duration) time.Duration {
	v, err := time.ParseDuration(env(key, fallback.String()))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}
