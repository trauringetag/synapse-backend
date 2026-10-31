package middleware

// SEC-05: тесты RealIP (TDD — написаны до реализации).
// Критерии:
//   - поддельный X-Forwarded-For НЕ влияет на ClientIP, если источник не в
//     whitelist доверенных прокси;
//   - пустой список TrustedProxies ⇒ XFF/X-Real-IP/True-Client-IP игнорируются
//     полностью, используется r.RemoteAddr;
//   - запрос от доверенного прокси ⇒ XFF разбирается корректно (первый IP
//     цепочки — настоящий клиент);
//   - Config.TrustedProxies поддерживает CIDR-нотацию.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
)

// newRealIPChain собирает chi-роутер с RealIPFromTrustedProxies и терминальным
// хендлером, возвращающим r.RemoteAddr — то, что видят key-func'i
// rate limiter'ов через ClientIP(r).
func newRealIPChain(trusted []string) http.Handler {
	r := chi.NewRouter()
	r.Use(RealIPFromTrustedProxies(&config.Config{TrustedProxies: trusted}))
	r.Get("/probe", func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte(req.RemoteAddr))
	})
	return r
}

func probeClientIP(t *testing.T, h http.Handler, remoteAddr string, headers map[string]string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

func TestRealIP_FakeXFFIgnoredWhenSourceNotTrusted(t *testing.T) {
	h := newRealIPChain([]string{"203.0.113.10"})

	// Атакующий подключается напрямую (198.51.100.77 ∉ whitelist) и подделывает XFF.
	got := probeClientIP(t, h, "198.51.100.77:5555", map[string]string{
		"X-Forwarded-For": "8.8.8.8, 203.0.113.10",
		"X-Real-IP":       "1.1.1.1",
		"True-Client-IP":  "9.9.9.9",
	})
	if got != "198.51.100.77:5555" {
		t.Fatalf("поддельный XFF изменил RemoteAddr на %q: rate-limit можно обойти, ожидаем 198.51.100.77:5555", got)
	}
}

func TestRealIP_EmptyTrustedListIgnoresXFF(t *testing.T) {
	h := newRealIPChain(nil)

	got := probeClientIP(t, h, "198.51.100.77:5555", map[string]string{
		"X-Forwarded-For": "8.8.8.8",
		"X-Real-IP":       "9.9.9.9",
	})
	if got != "198.51.100.77:5555" {
		t.Fatalf("при пустом списке прокси XFF обязан игнорироваться, got %q", got)
	}
}

func TestRealIP_TrustedProxyXFFHonored(t *testing.T) {
	h := newRealIPChain([]string{"203.0.113.0/24"})

	// Легитимный reverse-proxy из доверенной подсети (CIDR): первый IP цепочки — клиент.
	got := probeClientIP(t, h, "203.0.113.5:4444", map[string]string{
		"X-Forwarded-For": "198.51.100.23, 203.0.113.5",
	})
	if got != "198.51.100.23" {
		t.Fatalf("запрос от доверенного прокси: XFF должен применяться, got %q", got)
	}
}

func TestRealIP_TrustedSingleIPExactMatch(t *testing.T) {
	h := newRealIPChain([]string{"203.0.113.10"})

	got := probeClientIP(t, h, "203.0.113.10:6666", map[string]string{
		"X-Forwarded-For": "198.51.100.23",
	})
	if got != "198.51.100.23" {
		t.Fatalf("точное совпадение с whitelist: XFF должен применяться, got %q", got)
	}
}

func TestRealIP_UnparseableXFFKeepsRemoteAddr(t *testing.T) {
	h := newRealIPChain([]string{"203.0.113.10"})

	got := probeClientIP(t, h, "198.51.100.77:5555", map[string]string{
		"X-Forwarded-For": "not-an-ip-at-all",
	})
	if got != "198.51.100.77:5555" {
		t.Fatalf("битый XFF обязан оставлять RemoteAddr, got %q", got)
	}
}

// TestClientIP_SeesRealIP_EndToEnd — сквозная проверка: после цепочки RealIP
// IPKey (ключ rate limiter'а) строится по настоящему клиенту для запроса от
// доверенного прокси и по фактическому RemoteAddr — для атакующего с
// поддельным заголовком.
func TestClientIP_SeesRealIP_EndToEnd(t *testing.T) {
	probeKey := func(trusted []string, remoteAddr, xff string) string {
		t.Helper()
		var got string
		r := chi.NewRouter()
		r.Use(RealIPFromTrustedProxies(&config.Config{TrustedProxies: trusted}))
		r.Get("/probe", func(w http.ResponseWriter, req *http.Request) {
			got = IPKey(req)
		})
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.RemoteAddr = remoteAddr
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		r.ServeHTTP(httptest.NewRecorder(), req)
		return got
	}

	// Доверенный прокси -> ключ по реальному клиенту.
	if k := probeKey([]string{"10.0.0.0/8"}, "10.1.2.3:80", "198.51.100.77"); k != "ip:198.51.100.77" {
		t.Errorf("IPKey от доверенного прокси = %q, want ip:198.51.100.77", k)
	}

	// Недоверенный источник с поддельным XFF -> ключ по фактическому IP.
	if k := probeKey([]string{"10.0.0.0/8"}, "198.51.100.77:80", "1.2.3.4"); k != "ip:198.51.100.77" {
		t.Errorf("IPKey при поддельном XFF = %q, want ip:198.51.100.77 (обход rate-limit!)", k)
	}
}

func TestIsTrustedProxy_Unit(t *testing.T) {
	parsed, err := parseTrustedProxies([]string{"203.0.113.0/24", "192.168.1.5", "bad-cidr"})
	if err != nil {
		t.Fatalf("parseTrustedProxies: %v", err)
	}
	cases := []struct {
		remote string
		want   bool
	}{
		{"203.0.113.7:443", true},
		{"192.168.1.5:1234", true},
		{"198.51.100.1:1234", false},
		{"203.0.114.1:1234", false}, // соседняя подсеть
		{"garbage", false},
	}
	for _, c := range cases {
		if got := isTrustedProxy(c.remote, parsed); got != c.want {
			t.Errorf("isTrustedProxy(%q) = %v, want %v", c.remote, got, c.want)
		}
	}
}
