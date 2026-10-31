package config

// SEC-03: тесты fail-fast валидации конфигурации (TDD — написаны до реализации).
// Критерий приёмки: production-сборка падает при запуске с дефолтными секретами.

import (
	"net/http"
	"strings"
	"testing"
)

func baseProdConfig() Config {
	return Config{
		// Environment — режим развёртывания (ENVIRONMENT), именно он включает
		// fail-fast проверку; AppEnv — историческое имя сервиса.
		Environment:        "production",
		JWTSecret:          []byte(strings.Repeat("a", 48)), // сильный, не дефолтный
		RateLimitHMACKey:   []byte(strings.Repeat("r", 48)), // отдельный секрет для HMAC PII
		AdminRegisterToken: strings.Repeat("t", 32),         // не дефолтный/плейсхолдер
		CookieSecure:       true,
		DatabaseURL:        "postgres://u:p@db.internal:5432/synapse?sslmode=require",
	}
}

func TestValidate_ProductionSafeDefaultsPass(t *testing.T) {
	t.Setenv("RATE_LIMIT_HMAC_KEY", strings.Repeat("r", 48))
	cfg := baseProdConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("валидный production-конфиг не должен падать, got: %v", err)
	}
}

func TestValidate_ProductionRejectsMissingRateLimitHMACKey(t *testing.T) {
	// В production обязателен ЯВНЫЙ отдельный секрет RATE_LIMIT_HMAC_KEY:
	// детерминированный вывод из JWT_SECRET допустим только вне production.
	cfg := baseProdConfig() // поле заполнено, но env не задан
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "RATE_LIMIT_HMAC_KEY") {
		t.Fatalf("production без env RATE_LIMIT_HMAC_KEY обязан падать, got: %v", err)
	}

	// Короткий (<32 символов) env тоже отбраковывается.
	t.Setenv("RATE_LIMIT_HMAC_KEY", "short-key")
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "RATE_LIMIT_HMAC_KEY") {
		t.Fatalf("короткий RATE_LIMIT_HMAC_KEY в production обязан падать, got: %v", err)
	}
}

func TestValidate_ProductionRejectsDefaultJWTSecret(t *testing.T) {
	for _, secret := range DefaultInsecureSecrets {
		cfg := baseProdConfig()
		cfg.JWTSecret = []byte(secret)
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("дефолтный JWT_SECRET %q в production обязан давать ошибку", secret)
		}
		if !strings.Contains(err.Error(), "JWT_SECRET") {
			t.Errorf("ошибка должна упоминать JWT_SECRET, got: %v", err)
		}
	}
}

func TestValidate_ProductionRejectsPlaceholderSecrets(t *testing.T) {
	// Плейсхолдеры из .env.example принципиально не проходят валидацию запуска.
	cfg := baseProdConfig()
	cfg.JWTSecret = []byte("CHANGE_ME_IMMEDIATELY__generate_a_64_byte_random_string_here")
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "JWT_SECRET") {
		t.Fatalf("плейсхолдер CHANGE_ME_* в production обязан падать, got: %v", err)
	}
}

func TestValidate_ProductionRejectsShortJWTSecret(t *testing.T) {
	cfg := baseProdConfig()
	cfg.JWTSecret = []byte("too-short-secret")
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "JWT_SECRET") {
		t.Fatalf("короткий JWT_SECRET (<32 байт) в production обязан падать, got: %v", err)
	}
}

func TestValidate_ProductionRejectsInsecureCookies(t *testing.T) {
	cfg := baseProdConfig()
	cfg.CookieSecure = false
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "COOKIE_SECURE") {
		t.Fatalf("COOKIE_SECURE=false в production обязан падать, got: %v", err)
	}
}

func TestValidate_ProductionRejectsSSLDisabledDatabase(t *testing.T) {
	cfg := baseProdConfig()
	cfg.DatabaseURL = "postgres://u:p@db.internal:5432/synapse?sslmode=disable"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "sslmode=disable") {
		t.Fatalf("DATABASE_URL c sslmode=disable в production обязан падать, got: %v", err)
	}

	cfg2 := baseProdConfig()
	cfg2.DatabaseURL = "postgres://u:p@db.internal:5432/synapse?sslmode=DISABLE&timezone=UTC"
	if err := cfg2.Validate(); err == nil {
		t.Fatal("sslmode=DISABLE (регистронезависимо) обязан падать")
	}
}

func TestValidate_NonProductionIsLenient(t *testing.T) {
	// Локальная разработка: дефолтные значения допустимы (падать не должны).
	cfg := Config{
		Environment:    "development",
		JWTSecret:      []byte(DefaultJWTSecret),
		CookieSecure:   false,
		DatabaseURL:    "postgres://u:p@localhost:5432/db?sslmode=disable",
		CookieSameSite: http.SameSiteLaxMode,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("development не должен падать на дефолтах, got: %v", err)
	}
}

func TestValidate_AllErrorsReportedAtOnce(t *testing.T) {
	// Fail-fast: все проблемы сразу, чтобы один запуск показал весь список.
	cfg := baseProdConfig()
	cfg.JWTSecret = []byte(DefaultJWTSecret)
	cfg.CookieSecure = false
	cfg.DatabaseURL = "postgres://u:p@localhost:5432/db?sslmode=disable"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	msg := err.Error()
	for _, want := range []string{"JWT_SECRET", "COOKIE_SECURE", "sslmode=disable"} {
		if !strings.Contains(msg, want) {
			t.Errorf("в сводной ошибке отсутствует %q: %v", want, msg)
		}
	}
}

func TestLoad_ProductionWithExamplePlaceholdersFailsFast(t *testing.T) {
	// Сквозная проверка критерия «production-сборка падает при запуске с
	// дефолтными секретами»: значения из .env.example + ENVIRONMENT=production
	// обязаны привести Load() к ошибке (без чтения .env файла).
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("APP_ENV", "synapse-backend")
	t.Setenv("JWT_SECRET", "CHANGE_ME_IMMEDIATELY__generate_a_64_byte_random_string_here")
	t.Setenv("ADMIN_REGISTER_TOKEN", "CHANGE_ME_ADMIN_REGISTER_TOKEN")
	t.Setenv("COOKIE_SECURE", "false")
	t.Setenv("COOKIE_SAMESITE", "Lax")
	t.Setenv("DATABASE_URL", "postgres://synapse-backend:synapse-default-password@postgres:5432/synapse-backend?sslmode=disable")
	t.Setenv("ACCESS_TOKEN_TTL", "15m")
	t.Setenv("REFRESH_TOKEN_TTL", "168h")
	t.Setenv("CORS_ORIGINS", "http://localhost:3000")
	t.Setenv("TRUSTED_PROXIES", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() в production с плейсхолдерами из .env.example обязан вернуть ошибку")
	}
}

func TestLoad_ParsesTrustedProxies(t *testing.T) {
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("JWT_SECRET", strings.Repeat("k", 48))
	t.Setenv("ADMIN_REGISTER_TOKEN", "token")
	t.Setenv("COOKIE_SECURE", "false")
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.1, ,::1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	want := []string{"10.0.0.0/8", "192.168.1.1", "::1"}
	if len(cfg.TrustedProxies) != len(want) {
		t.Fatalf("TrustedProxies = %v, want %v", cfg.TrustedProxies, want)
	}
	for i := range want {
		if cfg.TrustedProxies[i] != want[i] {
			t.Errorf("TrustedProxies[%d] = %q, want %q", i, cfg.TrustedProxies[i], want[i])
		}
	}
}
