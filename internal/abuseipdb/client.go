// Package abuseipdb implements a small, typed client for the AbuseIPDB API v2.
package abuseipdb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultBaseURL       = "https://api.abuseipdb.com/api/v2"
	DefaultMaxResponse   = int64(16 << 20) // 16 MiB
	defaultUserAgentName = "abuseipdb-mcp"
)

// Client calls the AbuseIPDB API. It is safe for concurrent use.
type Client struct {
	baseURL         *url.URL
	apiKey          string
	httpClient      *http.Client
	userAgent       string
	maxResponseSize int64
}

// Options configures a Client.
type Options struct {
	BaseURL         string
	APIKey          string
	HTTPClient      *http.Client
	UserAgent       string
	MaxResponseSize int64
}

// Response contains the decoded AbuseIPDB response and rate-limit metadata.
type Response struct {
	Payload   map[string]any `json:"payload"`
	RateLimit RateLimit      `json:"rate_limit"`
}

// RateLimit captures the useful rate-limit response headers documented by AbuseIPDB.
type RateLimit struct {
	Limit             *int64     `json:"limit,omitempty"`
	Remaining         *int64     `json:"remaining,omitempty"`
	ResetAt           *time.Time `json:"reset_at,omitempty"`
	RetryAfterSeconds *int64     `json:"retry_after_seconds,omitempty"`
}

// Error is a non-2xx response from AbuseIPDB.
type Error struct {
	StatusCode int
	Status     string
	Items      []ErrorItem
	RateLimit  RateLimit
	Body       string
}

// ErrorItem is the structured error format returned by AbuseIPDB API v2.
type ErrorItem struct {
	Detail string      `json:"detail"`
	Status any         `json:"status,omitempty"`
	Source ErrorSource `json:"source,omitempty"`
}

// ErrorSource identifies the input parameter responsible for an API error.
type ErrorSource struct {
	Parameter string `json:"parameter,omitempty"`
}

func (e *Error) Error() string {
	if len(e.Items) > 0 && e.Items[0].Detail != "" {
		return fmt.Sprintf("AbuseIPDB API returned %s: %s", e.Status, e.Items[0].Detail)
	}
	if e.Body != "" {
		return fmt.Sprintf("AbuseIPDB API returned %s: %s", e.Status, e.Body)
	}
	return "AbuseIPDB API returned " + e.Status
}

// NewClient validates options and returns an AbuseIPDB client.
func NewClient(opts Options) (*Client, error) {
	base := strings.TrimSpace(opts.BaseURL)
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse AbuseIPDB base URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("AbuseIPDB base URL must be an absolute HTTP(S) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("AbuseIPDB base URL must not contain credentials, a query, or a fragment")
	}
	if strings.TrimSpace(opts.APIKey) == "" {
		return nil, errors.New("AbuseIPDB API key is required")
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	// Clone the client so caller-owned configuration is not mutated, then reject
	// redirects. Go may otherwise copy the non-standard Key header to a redirect
	// target, which is an unnecessary credential-disclosure risk for this API.
	hcCopy := *hc
	hcCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	ua := strings.TrimSpace(opts.UserAgent)
	if ua == "" {
		ua = defaultUserAgentName
	}
	maxSize := opts.MaxResponseSize
	if maxSize <= 0 {
		maxSize = DefaultMaxResponse
	}

	return &Client{
		baseURL:         u,
		apiKey:          strings.TrimSpace(opts.APIKey),
		httpClient:      &hcCopy,
		userAgent:       ua,
		maxResponseSize: maxSize,
	}, nil
}

// CheckIP calls GET /check.
func (c *Client) CheckIP(ctx context.Context, ip string, maxAge int, verbose bool) (*Response, error) {
	q := url.Values{"ipAddress": {ip}, "maxAgeInDays": {strconv.Itoa(maxAge)}}
	if verbose {
		q.Set("verbose", "")
	}
	return c.do(ctx, http.MethodGet, "check", q, "", nil)
}

// Reports calls GET /reports.
func (c *Client) Reports(ctx context.Context, ip string, maxAge, page, perPage int) (*Response, error) {
	q := url.Values{
		"ipAddress":    {ip},
		"maxAgeInDays": {strconv.Itoa(maxAge)},
		"page":         {strconv.Itoa(page)},
		"perPage":      {strconv.Itoa(perPage)},
	}
	return c.do(ctx, http.MethodGet, "reports", q, "", nil)
}

// Blacklist calls GET /blacklist and requests JSON output.
func (c *Client) Blacklist(ctx context.Context, confidence, limit, ipVersion int, onlyCountries, exceptCountries []string) (*Response, error) {
	q := url.Values{
		"confidenceMinimum": {strconv.Itoa(confidence)},
		"limit":             {strconv.Itoa(limit)},
	}
	if ipVersion != 0 {
		q.Set("ipVersion", strconv.Itoa(ipVersion))
	}
	if len(onlyCountries) > 0 {
		q.Set("onlyCountries", strings.Join(onlyCountries, ","))
	}
	if len(exceptCountries) > 0 {
		q.Set("exceptCountries", strings.Join(exceptCountries, ","))
	}
	return c.do(ctx, http.MethodGet, "blacklist", q, "", nil)
}

// Report submits one abuse report with POST /report.
func (c *Client) Report(ctx context.Context, ip string, categories []int, comment, timestamp string) (*Response, error) {
	values := url.Values{
		"ip":         {ip},
		"categories": {joinInts(categories)},
	}
	if comment != "" {
		values.Set("comment", comment)
	}
	if timestamp != "" {
		values.Set("timestamp", timestamp)
	}
	body := strings.NewReader(values.Encode())
	return c.do(ctx, http.MethodPost, "report", nil, "application/x-www-form-urlencoded", body)
}

// CheckBlock calls GET /check-block.
func (c *Client) CheckBlock(ctx context.Context, network string, maxAge int) (*Response, error) {
	q := url.Values{"network": {network}, "maxAgeInDays": {strconv.Itoa(maxAge)}}
	return c.do(ctx, http.MethodGet, "check-block", q, "", nil)
}

// BulkReport uploads CSV data to POST /bulk-report.
func (c *Client) BulkReport(ctx context.Context, csvData string) (*Response, error) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("csv", "reports.csv")
	if err != nil {
		return nil, fmt.Errorf("create bulk report upload: %w", err)
	}
	if _, err := io.WriteString(part, csvData); err != nil {
		return nil, fmt.Errorf("write bulk report upload: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("finish bulk report upload: %w", err)
	}
	return c.do(ctx, http.MethodPost, "bulk-report", nil, w.FormDataContentType(), &body)
}

// ClearAddress deletes reports submitted by the authenticated account for an IP.
func (c *Client) ClearAddress(ctx context.Context, ip string) (*Response, error) {
	q := url.Values{"ipAddress": {ip}}
	return c.do(ctx, http.MethodDelete, "clear-address", q, "", nil)
}

func (c *Client) do(ctx context.Context, method, endpoint string, query url.Values, contentType string, body io.Reader) (*Response, error) {
	u := *c.baseURL
	u.Path = strings.TrimRight(c.baseURL.Path, "/") + "/" + endpoint
	u.RawPath = ""
	if query != nil {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("create AbuseIPDB request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("User-Agent", c.userAgent)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call AbuseIPDB API: %w", err)
	}
	defer resp.Body.Close()

	rate := parseRateLimit(resp.Header)
	limited := io.LimitReader(resp.Body, c.maxResponseSize+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read AbuseIPDB response: %w", err)
	}
	if int64(len(b)) > c.maxResponseSize {
		return nil, fmt.Errorf("AbuseIPDB response exceeds the %d-byte safety limit", c.maxResponseSize)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &Error{StatusCode: resp.StatusCode, Status: resp.Status, RateLimit: rate}
		var envelope struct {
			Errors []ErrorItem `json:"errors"`
		}
		if json.Unmarshal(b, &envelope) == nil {
			apiErr.Items = envelope.Errors
		}
		if len(apiErr.Items) == 0 {
			apiErr.Body = truncate(strings.TrimSpace(string(b)), 1024)
		}
		return nil, apiErr
	}

	var payload map[string]any
	if err := json.Unmarshal(b, &payload); err != nil {
		return nil, fmt.Errorf("decode AbuseIPDB JSON response: %w", err)
	}
	return &Response{Payload: payload, RateLimit: rate}, nil
}

func parseRateLimit(h http.Header) RateLimit {
	return RateLimit{
		Limit:             parseIntHeader(h.Get("X-RateLimit-Limit")),
		Remaining:         parseIntHeader(h.Get("X-RateLimit-Remaining")),
		ResetAt:           parseEpochHeader(h.Get("X-RateLimit-Reset")),
		RetryAfterSeconds: parseIntHeader(h.Get("Retry-After")),
	}
}

func parseIntHeader(s string) *int64 {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return nil
	}
	return &v
}

func parseEpochHeader(s string) *time.Time {
	v := parseIntHeader(s)
	if v == nil {
		return nil
	}
	t := time.Unix(*v, 0).UTC()
	return &t
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strconv.Itoa(value)
	}
	return strings.Join(parts, ",")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
