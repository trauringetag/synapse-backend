package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trauringetag/synapse-backend/internal/config"
)

func TestRequireAllowedOrigin(t *testing.T) {
	cfg := &config.Config{CORSOrigins: []string{"http://localhost:3000", "https://app.example.com"}}
	tests := []struct {
		name       string
		origin     string
		referer    string
		wantStatus int
	}{
		{name: "allowed origin", origin: "http://localhost:3000", wantStatus: http.StatusNoContent},
		{name: "referer fallback", referer: "http://localhost:3000/register?from=test", wantStatus: http.StatusNoContent},
		{name: "referer fallback strips path and query", referer: "https://app.example.com/some/path", wantStatus: http.StatusNoContent},
		{name: "missing both headers", wantStatus: http.StatusForbidden},
		{name: "untrusted origin", origin: "https://evil.example", referer: "http://localhost:3000/", wantStatus: http.StatusForbidden},
		{name: "untrusted referer", referer: "https://evil.example/path", wantStatus: http.StatusForbidden},
		{name: "origin with trailing slash", origin: "http://localhost:3000/", wantStatus: http.StatusNoContent},
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
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if nextCalled != (tt.wantStatus == http.StatusNoContent) {
				t.Fatalf("nextCalled = %v, want %v", nextCalled, tt.wantStatus == http.StatusNoContent)
			}
		})
	}
}
