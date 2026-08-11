// Package config loads and validates process configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Sma-Das/AbuseIPDB-MCP/internal/abuseipdb"
)

const (
	TransportStdio = "stdio"
	TransportHTTP  = "http"
)

// Config contains all runtime settings.
type Config struct {
	APIKey          string
	APIBaseURL      string
	APITimeout      time.Duration
	MaxResponseSize int64
	Transport       string
	HTTPAddr        string
	HTTPPath        string
	HTTPBearerToken string
}

// Load reads environment variables, applying safe defaults.
func Load() (Config, error) {
	timeout, err := durationEnv("ABUSEIPDB_TIMEOUT", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	maxResponse, err := int64Env("ABUSEIPDB_MAX_RESPONSE_BYTES", abuseipdb.DefaultMaxResponse)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		APIKey:          strings.TrimSpace(os.Getenv("ABUSEIPDB_API_KEY")),
		APIBaseURL:      envOr("ABUSEIPDB_BASE_URL", abuseipdb.DefaultBaseURL),
		APITimeout:      timeout,
		MaxResponseSize: maxResponse,
		Transport:       strings.ToLower(envOr("MCP_TRANSPORT", TransportStdio)),
		HTTPAddr:        envOr("MCP_HTTP_ADDR", "127.0.0.1:8080"),
		HTTPPath:        envOr("MCP_HTTP_PATH", "/mcp"),
		HTTPBearerToken: strings.TrimSpace(os.Getenv("MCP_HTTP_BEARER_TOKEN")),
	}
	return cfg, cfg.Validate()
}

// Validate checks configuration without making network calls.
func (c Config) Validate() error {
	if c.APIKey == "" {
		return errors.New("ABUSEIPDB_API_KEY is required")
	}
	if c.APITimeout <= 0 {
		return errors.New("ABUSEIPDB_TIMEOUT must be positive")
	}
	if c.MaxResponseSize <= 0 {
		return errors.New("ABUSEIPDB_MAX_RESPONSE_BYTES must be positive")
	}
	if c.Transport != TransportStdio && c.Transport != TransportHTTP {
		return fmt.Errorf("MCP_TRANSPORT must be %q or %q", TransportStdio, TransportHTTP)
	}
	if c.Transport == TransportHTTP {
		if _, _, err := net.SplitHostPort(c.HTTPAddr); err != nil {
			return fmt.Errorf("MCP_HTTP_ADDR must be in host:port form: %w", err)
		}
		if !strings.HasPrefix(c.HTTPPath, "/") || strings.ContainsAny(c.HTTPPath, "?#") {
			return errors.New("MCP_HTTP_PATH must be an absolute URL path without a query or fragment")
		}
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration (for example 30s)", name)
	}
	return d, nil
}

func int64Env(name string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return v, nil
}
