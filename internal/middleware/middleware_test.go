package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trauringetag/synapse-backend/internal/config"
)

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
		{"allowed Origin", "https://app.example", "", http.StatusNoContent},
		{"allowed Referer fallback", "", "https://app.example/account", http.StatusNoContent},
		{"no Origin or Referer", "", "", http.StatusForbidden},
		{"disallowed Origin cannot be overridden", "https://evil.example", "https://app.example/account", http.StatusForbidden},
		{"disallowed Referer", "", "https://evil.example/account", http.StatusForbidden},
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
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

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
		{"allowed Referer fallback", "", "https://app.example/form", http.StatusNoContent},
		{"disallowed Origin cannot be overridden", "https://evil.example", "https://app.example/form", http.StatusForbidden},
		{"no Origin or Referer", "", "", http.StatusForbidden},
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
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}
