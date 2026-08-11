package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Sma-Das/AbuseIPDB-MCP/internal/abuseipdb"
	"github.com/Sma-Das/AbuseIPDB-MCP/internal/config"
	"github.com/Sma-Das/AbuseIPDB-MCP/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("abuseipdb-mcp", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	showVersion := flags.Bool("version", false, "print version information and exit")
	healthcheck := flags.Bool("healthcheck", false, "check the local HTTP health endpoint and exit")
	transport := flags.String("transport", "", "MCP transport override: stdio or http")
	httpAddr := flags.String("http-addr", "", "HTTP listen address override, in host:port form")
	httpPath := flags.String("http-path", "", "Streamable HTTP endpoint path override")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *showVersion {
		fmt.Printf("abuseipdb-mcp %s (commit %s, built %s)\n", version, commit, date)
		return nil
	}
	if *healthcheck {
		transport := strings.ToLower(strings.TrimSpace(os.Getenv("MCP_TRANSPORT")))
		if transport == "" || transport == config.TransportStdio {
			return nil
		}
		return checkHealth(os.Getenv("MCP_HTTP_ADDR"))
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if *transport != "" {
		cfg.Transport = strings.ToLower(strings.TrimSpace(*transport))
	}
	if *httpAddr != "" {
		cfg.HTTPAddr = strings.TrimSpace(*httpAddr)
	}
	if *httpPath != "" {
		cfg.HTTPPath = strings.TrimSpace(*httpPath)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	api, err := abuseipdb.NewClient(abuseipdb.Options{
		APIKey: cfg.APIKey, BaseURL: cfg.APIBaseURL,
		HTTPClient:      &http.Client{Timeout: cfg.APITimeout},
		UserAgent:       fmt.Sprintf("abuseipdb-mcp/%s", version),
		MaxResponseSize: cfg.MaxResponseSize,
	})
	if err != nil {
		return err
	}
	server := mcpserver.New(api, version)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cfg.Transport {
	case config.TransportStdio:
		logger.Info("starting MCP server", "transport", "stdio", "version", version)
		if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	case config.TransportHTTP:
		if cfg.HTTPBearerToken == "" && !isLoopbackHost(cfg.HTTPAddr) {
			logger.Warn("HTTP server is listening beyond loopback without bearer authentication; restrict network exposure or set MCP_HTTP_BEARER_TOKEN")
		}
		return serveHTTP(ctx, server, cfg, logger)
	default:
		return fmt.Errorf("unsupported transport %q", cfg.Transport)
	}
}

func serveHTTP(ctx context.Context, server *mcp.Server, cfg config.Config, logger *slog.Logger) error {
	handler := newHTTPHandler(server, cfg.HTTPPath, cfg.HTTPBearerToken, version, logger)
	httpServer := &http.Server{
		Addr: cfg.HTTPAddr, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting MCP server", "transport", "streamable-http", "address", cfg.HTTPAddr, "path", cfg.HTTPPath, "version", version)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down HTTP server: %w", err)
		}
		return nil
	}
}

func newHTTPHandler(server *mcp.Server, path, token, serverVersion string, logger *slog.Logger) http.Handler {
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless:           true,
		Logger:              logger,
		MaxRequestBodyBytes: 20 << 20,
	})

	var protected http.Handler = mcpHandler
	protected = http.NewCrossOriginProtection().Handler(protected)
	if token != "" {
		protected = bearerAuth(token, protected)
	}
	protected = securityHeaders(protected)

	mux := http.NewServeMux()
	mux.Handle(path, protected)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok", "service": mcpserver.ServerName, "version": serverVersion,
		})
	})
	return mux
}

func bearerAuth(token string, next http.Handler) http.Handler {
	expected := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provided := []byte(r.Header.Get("Authorization"))
		if len(provided) != len(expected) || subtle.ConstantTimeCompare(provided, expected) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="abuseipdb-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func isLoopbackHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func checkHealth(addr string) error {
	if strings.TrimSpace(addr) == "" {
		addr = "127.0.0.1:8080"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid MCP_HTTP_ADDR: %w", err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", resp.Status)
	}
	return nil
}
