package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestHTTPHandlerHealthAndAuthentication(t *testing.T) {
	server := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := newHTTPHandler(server, "/mcp", "secret", "1.2.3", logger)

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"version":"1.2.3"`) {
		t.Fatalf("health response = %d %s", health.Code, health.Body.String())
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized response = %d, want 401", unauthorized.Code)
	}
	if unauthorized.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("security headers are missing")
	}

	crossSiteRequest := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	crossSiteRequest.Header.Set("Authorization", "Bearer secret")
	crossSiteRequest.Header.Set("Origin", "https://evil.example")
	crossSite := httptest.NewRecorder()
	handler.ServeHTTP(crossSite, crossSiteRequest)
	if crossSite.Code != http.StatusForbidden {
		t.Fatalf("cross-site response = %d, want 403", crossSite.Code)
	}
}

func TestBearerAuth(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := bearerAuth("token", next)
	for _, tt := range []struct {
		header string
		want   int
	}{
		{"", http.StatusUnauthorized},
		{"Bearer wrong", http.StatusUnauthorized},
		{"Bearer token", http.StatusNoContent},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", tt.header)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != tt.want {
			t.Errorf("header %q: status = %d, want %d", tt.header, w.Code, tt.want)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"} {
		if !isLoopbackHost(addr) {
			t.Errorf("%q was not recognized as loopback", addr)
		}
	}
	if isLoopbackHost("0.0.0.0:8080") {
		t.Error("0.0.0.0 was recognized as loopback")
	}
}

func TestCheckHealth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "http://")
	if err := checkHealth(addr); err != nil {
		t.Fatal(err)
	}
}

func TestRunVersionDoesNotRequireAPIKey(t *testing.T) {
	t.Setenv("ABUSEIPDB_API_KEY", "")
	if err := run([]string{"-version"}); err != nil {
		t.Fatal(err)
	}
}

func TestStdioHealthcheckDoesNotRequireHTTPOrAPIKey(t *testing.T) {
	t.Setenv("ABUSEIPDB_API_KEY", "")
	t.Setenv("MCP_TRANSPORT", "stdio")
	if err := run([]string{"-healthcheck"}); err != nil {
		t.Fatal(err)
	}
}
