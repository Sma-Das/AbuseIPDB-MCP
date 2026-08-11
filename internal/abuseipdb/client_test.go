package abuseipdb

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestClientCoversAllEndpoints(t *testing.T) {
	t.Helper()
	const apiKey = "test-secret-key"
	seen := make(map[string]int)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.Method+" "+r.URL.Path]++
		if got := r.Header.Get("Key"); got != apiKey {
			t.Errorf("Key header = %q, want test key", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept header = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "test-agent/1.0" {
			t.Errorf("User-Agent = %q", got)
		}

		switch r.Method + " " + r.URL.Path {
		case "GET /api/v2/check":
			assertQuery(t, r.URL.Query(), "ipAddress", "2001:db8::1")
			assertQuery(t, r.URL.Query(), "maxAgeInDays", "90")
			if !r.URL.Query().Has("verbose") {
				t.Error("verbose query parameter is missing")
			}
		case "GET /api/v2/reports":
			assertQuery(t, r.URL.Query(), "ipAddress", "192.0.2.1")
			assertQuery(t, r.URL.Query(), "maxAgeInDays", "30")
			assertQuery(t, r.URL.Query(), "page", "2")
			assertQuery(t, r.URL.Query(), "perPage", "50")
		case "GET /api/v2/blacklist":
			assertQuery(t, r.URL.Query(), "confidenceMinimum", "75")
			assertQuery(t, r.URL.Query(), "limit", "500")
			assertQuery(t, r.URL.Query(), "ipVersion", "6")
			assertQuery(t, r.URL.Query(), "onlyCountries", "CA,US")
		case "POST /api/v2/report":
			if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
				t.Errorf("Content-Type = %q", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			assertQuery(t, r.Form, "ip", "192.0.2.2")
			assertQuery(t, r.Form, "categories", "14,18")
			assertQuery(t, r.Form, "comment", "port scan")
			assertQuery(t, r.Form, "timestamp", "2026-08-01T00:00:00Z")
		case "GET /api/v2/check-block":
			assertQuery(t, r.URL.Query(), "network", "192.0.2.0/24")
			assertQuery(t, r.URL.Query(), "maxAgeInDays", "15")
		case "POST /api/v2/bulk-report":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Fatal(err)
			}
			file, _, err := r.FormFile("csv")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			contents, err := io.ReadAll(file)
			if err != nil {
				t.Fatal(err)
			}
			if string(contents) != "IP,Categories,ReportDate,Comment\n" {
				t.Errorf("CSV = %q", contents)
			}
		case "DELETE /api/v2/clear-address":
			assertQuery(t, r.URL.Query(), "ipAddress", "192.0.2.3")
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}

		w.Header().Set("X-RateLimit-Limit", "1000")
		w.Header().Set("X-RateLimit-Remaining", "999")
		w.Header().Set("X-RateLimit-Reset", "1786320000")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"ok":true}}`)
	}))
	defer ts.Close()

	client, err := NewClient(Options{
		BaseURL: ts.URL + "/api/v2/", APIKey: apiKey,
		HTTPClient: ts.Client(), UserAgent: "test-agent/1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	calls := []func() (*Response, error){
		func() (*Response, error) { return client.CheckIP(ctx, "2001:db8::1", 90, true) },
		func() (*Response, error) { return client.Reports(ctx, "192.0.2.1", 30, 2, 50) },
		func() (*Response, error) { return client.Blacklist(ctx, 75, 500, 6, []string{"CA", "US"}, nil) },
		func() (*Response, error) {
			return client.Report(ctx, "192.0.2.2", []int{14, 18}, "port scan", "2026-08-01T00:00:00Z")
		},
		func() (*Response, error) { return client.CheckBlock(ctx, "192.0.2.0/24", 15) },
		func() (*Response, error) { return client.BulkReport(ctx, "IP,Categories,ReportDate,Comment\n") },
		func() (*Response, error) { return client.ClearAddress(ctx, "192.0.2.3") },
	}
	for i, call := range calls {
		response, err := call()
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if response.Payload["data"] == nil {
			t.Fatalf("call %d has no data payload", i)
		}
		if response.RateLimit.Limit == nil || *response.RateLimit.Limit != 1000 {
			t.Fatalf("call %d did not capture rate limit: %+v", i, response.RateLimit)
		}
	}
	if len(seen) != 7 {
		t.Fatalf("called %d unique endpoints, want 7: %v", len(seen), seen)
	}
}

func TestClientAPIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "42")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"errors":[{"detail":"daily limit reached","status":429,"source":{"parameter":"ipAddress"}}]}`)
	}))
	defer ts.Close()
	client, err := NewClient(Options{BaseURL: ts.URL, APIKey: "never-expose-me", HTTPClient: ts.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CheckIP(context.Background(), "192.0.2.1", 30, false)
	var apiErr *Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %T %v, want *Error", err, err)
	}
	if apiErr.StatusCode != http.StatusTooManyRequests || len(apiErr.Items) != 1 {
		t.Fatalf("unexpected API error: %+v", apiErr)
	}
	if apiErr.RateLimit.RetryAfterSeconds == nil || *apiErr.RateLimit.RetryAfterSeconds != 42 {
		t.Fatalf("retry metadata = %+v", apiErr.RateLimit)
	}
	if strings.Contains(err.Error(), "never-expose-me") {
		t.Fatal("API key leaked in error")
	}
}

func TestClientResponseSizeLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":"this is too large"}`)
	}))
	defer ts.Close()
	client, err := NewClient(Options{BaseURL: ts.URL, APIKey: "key", HTTPClient: ts.Client(), MaxResponseSize: 8})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CheckIP(context.Background(), "192.0.2.1", 30, false)
	if err == nil || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("error = %v, want response size error", err)
	}
}

func TestClientDoesNotForwardKeyAcrossRedirects(t *testing.T) {
	redirectTargetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		redirectTargetCalled = true
		if r.Header.Get("Key") != "" {
			t.Error("API key was forwarded to redirect target")
		}
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer source.Close()

	client, err := NewClient(Options{BaseURL: source.URL, APIKey: "secret", HTTPClient: source.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CheckIP(context.Background(), "192.0.2.1", 30, false)
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusFound {
		t.Fatalf("error = %v, want redirect surfaced as API error", err)
	}
	if redirectTargetCalled {
		t.Fatal("redirect target was called")
	}
}

func TestNewClientValidation(t *testing.T) {
	tests := []Options{
		{BaseURL: "ftp://example.com", APIKey: "key"},
		{BaseURL: "https://user@example.com", APIKey: "key"},
		{BaseURL: "https://example.com?key=value", APIKey: "key"},
		{BaseURL: "https://example.com", APIKey: ""},
	}
	for _, opts := range tests {
		if _, err := NewClient(opts); err == nil {
			t.Errorf("NewClient(%+v) succeeded, want error", opts)
		}
	}
}

func assertQuery(t *testing.T, values url.Values, key, want string) {
	t.Helper()
	if got := values.Get(key); got != want {
		t.Errorf("query %s = %q, want %q", key, got, want)
	}
}

func TestParseEpochHeader(t *testing.T) {
	got := parseEpochHeader("0")
	if got == nil || !got.Equal(time.Unix(0, 0).UTC()) {
		t.Fatalf("parseEpochHeader(0) = %v", got)
	}
}
