package config

import (
	"testing"
	"time"

	"github.com/Sma-Das/AbuseIPDB-MCP/internal/abuseipdb"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("ABUSEIPDB_API_KEY", " key ")
	t.Setenv("ABUSEIPDB_BASE_URL", "")
	t.Setenv("ABUSEIPDB_TIMEOUT", "")
	t.Setenv("ABUSEIPDB_MAX_RESPONSE_BYTES", "")
	t.Setenv("MCP_TRANSPORT", "")
	t.Setenv("MCP_HTTP_ADDR", "")
	t.Setenv("MCP_HTTP_PATH", "")
	t.Setenv("MCP_HTTP_BEARER_TOKEN", " token ")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "key" || cfg.APIBaseURL != abuseipdb.DefaultBaseURL {
		t.Fatalf("unexpected API config: %+v", cfg)
	}
	if cfg.APITimeout != 30*time.Second || cfg.Transport != TransportStdio {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.HTTPBearerToken != "token" {
		t.Fatalf("token was not trimmed: %q", cfg.HTTPBearerToken)
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("ABUSEIPDB_API_KEY", "key")
	t.Setenv("ABUSEIPDB_BASE_URL", "http://localhost:9999/v2")
	t.Setenv("ABUSEIPDB_TIMEOUT", "5s")
	t.Setenv("ABUSEIPDB_MAX_RESPONSE_BYTES", "1234")
	t.Setenv("MCP_TRANSPORT", "HTTP")
	t.Setenv("MCP_HTTP_ADDR", "0.0.0.0:9000")
	t.Setenv("MCP_HTTP_PATH", "/custom")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APITimeout != 5*time.Second || cfg.MaxResponseSize != 1234 || cfg.Transport != "http" {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		value string
	}{
		{"missing key", "ABUSEIPDB_API_KEY", ""},
		{"bad timeout", "ABUSEIPDB_TIMEOUT", "forever"},
		{"bad response size", "ABUSEIPDB_MAX_RESPONSE_BYTES", "-1"},
		{"bad transport", "MCP_TRANSPORT", "websocket"},
		{"bad address", "MCP_HTTP_ADDR", "localhost"},
		{"bad path", "MCP_HTTP_PATH", "relative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ABUSEIPDB_API_KEY", "key")
			t.Setenv("ABUSEIPDB_TIMEOUT", "")
			t.Setenv("ABUSEIPDB_MAX_RESPONSE_BYTES", "")
			t.Setenv("MCP_TRANSPORT", "http")
			t.Setenv("MCP_HTTP_ADDR", "127.0.0.1:8080")
			t.Setenv("MCP_HTTP_PATH", "/mcp")
			t.Setenv(tt.env, tt.value)
			if _, err := Load(); err == nil {
				t.Fatal("Load() succeeded, want error")
			}
		})
	}
}
