// Package mcpserver exposes AbuseIPDB through Model Context Protocol tools.
package mcpserver

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Sma-Das/AbuseIPDB-MCP/internal/abuseipdb"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ServerName     = "io.github.sma-das/abuseipdb"
	MaxBulkCSVSize = 8 << 20
	MaxBulkRows    = 9999 // AbuseIPDB's 10,000-line cap includes the header.
)

// API is the AbuseIPDB behavior used by the MCP handlers.
type API interface {
	CheckIP(context.Context, string, int, bool) (*abuseipdb.Response, error)
	Reports(context.Context, string, int, int, int) (*abuseipdb.Response, error)
	Blacklist(context.Context, int, int, int, []string, []string) (*abuseipdb.Response, error)
	Report(context.Context, string, []int, string, string) (*abuseipdb.Response, error)
	CheckBlock(context.Context, string, int) (*abuseipdb.Response, error)
	BulkReport(context.Context, string) (*abuseipdb.Response, error)
	ClearAddress(context.Context, string) (*abuseipdb.Response, error)
}

// New creates a fully configured MCP server.
func New(api API, version string) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: ServerName, Version: version},
		&mcp.ServerOptions{
			Instructions: "Use AbuseIPDB to investigate IP reputation and report directly observed abuse. Never submit a report based only on an AbuseIPDB score. Remove personal data from comments and obtain user approval before calling a write tool.",
			Capabilities: &mcp.ServerCapabilities{},
		},
	)
	registerTools(server, api)
	registerResources(server)
	return server
}

type CheckIPInput struct {
	IPAddress    string `json:"ip_address" jsonschema:"IPv4 or IPv6 address to check"`
	MaxAgeInDays int    `json:"max_age_in_days,omitempty" jsonschema:"Report lookback in days from 1 to 365; defaults to 30"`
	Verbose      bool   `json:"verbose,omitempty" jsonschema:"Include report details and country name; defaults to false and can produce a large response"`
}

type ReportsInput struct {
	IPAddress    string `json:"ip_address" jsonschema:"IPv4 or IPv6 address whose reports should be retrieved"`
	MaxAgeInDays int    `json:"max_age_in_days,omitempty" jsonschema:"Report lookback in days from 1 to 365; defaults to 30"`
	Page         int    `json:"page,omitempty" jsonschema:"One-based results page; defaults to 1"`
	PerPage      int    `json:"per_page,omitempty" jsonschema:"Results per page from 1 to 100; defaults to 25"`
}

type BlacklistInput struct {
	ConfidenceMinimum int      `json:"confidence_minimum,omitempty" jsonschema:"Minimum abuse confidence from 25 to 100; defaults to 100 and values below 100 require a subscription"`
	Limit             int      `json:"limit,omitempty" jsonschema:"Maximum number of IPs; defaults to 10000 and is truncated to the account plan limit"`
	OnlyCountries     []string `json:"only_countries,omitempty" jsonschema:"Optional ISO 3166-1 alpha-2 country codes to include; subscription feature"`
	ExceptCountries   []string `json:"except_countries,omitempty" jsonschema:"Optional ISO 3166-1 alpha-2 country codes to exclude; subscription feature"`
	IPVersion         int      `json:"ip_version,omitempty" jsonschema:"Optional IP version filter: 4 or 6; omit for both"`
}

type ReportIPInput struct {
	IPAddress  string `json:"ip_address" jsonschema:"IPv4 or IPv6 source address that directly attacked a system you control"`
	Categories []int  `json:"categories" jsonschema:"One or more AbuseIPDB category IDs from 1 through 23"`
	Comment    string `json:"comment" jsonschema:"Detailed attack description with all personally identifiable information removed"`
	ReportedAt string `json:"reported_at,omitempty" jsonschema:"Optional RFC 3339 attack timestamp no older than 60 days; defaults to the current time"`
	Confirm    bool   `json:"confirm" jsonschema:"Must be true to confirm this external write complies with the AbuseIPDB reporting policy"`
}

type CheckBlockInput struct {
	Network      string `json:"network" jsonschema:"IPv4 or IPv6 network in CIDR notation"`
	MaxAgeInDays int    `json:"max_age_in_days,omitempty" jsonschema:"Report lookback in days from 1 to 365; defaults to 30 and plan limits may be lower"`
}

type BulkReportInput struct {
	Reports []BulkReportItem `json:"reports" jsonschema:"One to 9999 directly observed abuse reports"`
	Confirm bool             `json:"confirm" jsonschema:"Must be true to confirm every row complies with the AbuseIPDB reporting policy"`
}

type BulkReportItem struct {
	IPAddress  string `json:"ip_address" jsonschema:"IPv4 or IPv6 source address that directly attacked a system you control"`
	Categories []int  `json:"categories" jsonschema:"One or more AbuseIPDB category IDs from 1 through 23"`
	ReportedAt string `json:"reported_at" jsonschema:"RFC 3339 attack timestamp no older than 60 days"`
	Comment    string `json:"comment" jsonschema:"Detailed attack description with all personally identifiable information removed"`
}

type ClearAddressInput struct {
	IPAddress string `json:"ip_address" jsonschema:"IPv4 or IPv6 address whose reports from your own account should be deleted"`
	Confirm   bool   `json:"confirm" jsonschema:"Must be true to confirm permanent deletion of your account's reports for this address"`
}

type CategoriesInput struct{}

func registerTools(server *mcp.Server, api API) {
	readOnly := annotations(true, false, true)
	write := annotations(false, false, true)
	destructive := annotations(false, true, true)
	closedWorld := annotations(true, false, false)

	mcp.AddTool(server, &mcp.Tool{
		Name: "check_ip", Title: "Check IP reputation", Annotations: readOnly,
		Description: "Check an IPv4 or IPv6 address against AbuseIPDB for confidence score, report counts, ISP, usage type, country, allowlist status, and optional report details.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CheckIPInput) (*mcp.CallToolResult, any, error) {
		ip, err := normalizeIP(in.IPAddress)
		if err != nil {
			return nil, nil, err
		}
		age, err := withDefaultRange("max_age_in_days", in.MaxAgeInDays, 30, 1, 365)
		if err != nil {
			return nil, nil, err
		}
		return apiResult(api.CheckIP(ctx, ip, age, in.Verbose))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "get_ip_reports", Title: "Get IP abuse reports", Annotations: readOnly,
		Description: "Retrieve paginated AbuseIPDB reports for an IPv4 or IPv6 address, including timestamps, comments, categories, and reporter country details.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ReportsInput) (*mcp.CallToolResult, any, error) {
		ip, err := normalizeIP(in.IPAddress)
		if err != nil {
			return nil, nil, err
		}
		age, err := withDefaultRange("max_age_in_days", in.MaxAgeInDays, 30, 1, 365)
		if err != nil {
			return nil, nil, err
		}
		page, err := withDefaultMin("page", in.Page, 1, 1)
		if err != nil {
			return nil, nil, err
		}
		perPage, err := withDefaultRange("per_page", in.PerPage, 25, 1, 100)
		if err != nil {
			return nil, nil, err
		}
		return apiResult(api.Reports(ctx, ip, age, page, perPage))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "get_blacklist", Title: "Get AbuseIPDB blacklist", Annotations: readOnly,
		Description: "Retrieve the most reported IP addresses from the AbuseIPDB blacklist, with confidence, country, IP-version, and plan-aware limit filters.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in BlacklistInput) (*mcp.CallToolResult, any, error) {
		confidence, err := withDefaultRange("confidence_minimum", in.ConfidenceMinimum, 100, 25, 100)
		if err != nil {
			return nil, nil, err
		}
		limit, err := withDefaultMin("limit", in.Limit, 10000, 1)
		if err != nil {
			return nil, nil, err
		}
		if in.IPVersion != 0 && in.IPVersion != 4 && in.IPVersion != 6 {
			return nil, nil, errors.New("ip_version must be 4, 6, or omitted")
		}
		only, err := normalizeCountries(in.OnlyCountries)
		if err != nil {
			return nil, nil, fmt.Errorf("only_countries: %w", err)
		}
		except, err := normalizeCountries(in.ExceptCountries)
		if err != nil {
			return nil, nil, fmt.Errorf("except_countries: %w", err)
		}
		if len(only) > 0 && len(except) > 0 {
			return nil, nil, errors.New("only_countries and except_countries are mutually exclusive")
		}
		return apiResult(api.Blacklist(ctx, confidence, limit, in.IPVersion, only, except))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "report_ip", Title: "Report an abusive IP", Annotations: write,
		Description: "Submit one directly observed attack to AbuseIPDB. This writes external data. Do not report based only on a reputation score, do not include PII, and do not report spoofable traffic.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ReportIPInput) (*mcp.CallToolResult, any, error) {
		if !in.Confirm {
			return nil, nil, errors.New("confirm must be true before submitting an external abuse report")
		}
		ip, err := normalizeIP(in.IPAddress)
		if err != nil {
			return nil, nil, err
		}
		categories, err := normalizeCategories(in.Categories)
		if err != nil {
			return nil, nil, err
		}
		comment := strings.TrimSpace(in.Comment)
		if comment == "" {
			return nil, nil, errors.New("comment is required by the AbuseIPDB reporting policy")
		}
		if len(comment) > 1024 {
			return nil, nil, errors.New("comment must not exceed 1024 bytes")
		}
		timestamp, err := validateTimestamp(in.ReportedAt, false, time.Now())
		if err != nil {
			return nil, nil, err
		}
		return apiResult(api.Report(ctx, ip, categories, comment, timestamp))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "check_block", Title: "Check a CIDR block", Annotations: readOnly,
		Description: "Check an IPv4 or IPv6 CIDR block in AbuseIPDB and return reported addresses plus network metadata. Subscription plans determine the largest permitted block and lookback.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in CheckBlockInput) (*mcp.CallToolResult, any, error) {
		network, err := normalizeNetwork(in.Network)
		if err != nil {
			return nil, nil, err
		}
		age, err := withDefaultRange("max_age_in_days", in.MaxAgeInDays, 30, 1, 365)
		if err != nil {
			return nil, nil, err
		}
		return apiResult(api.CheckBlock(ctx, network, age))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "bulk_report", Title: "Bulk-report abusive IPs", Annotations: write,
		Description: "Submit up to 9,999 directly observed attacks through AbuseIPDB's bulk CSV endpoint. This writes external data. Every row must omit PII and comply with the reporting policy.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in BulkReportInput) (*mcp.CallToolResult, any, error) {
		if !in.Confirm {
			return nil, nil, errors.New("confirm must be true before bulk-submitting external abuse reports")
		}
		csvData, err := buildBulkCSV(in.Reports, time.Now())
		if err != nil {
			return nil, nil, err
		}
		return apiResult(api.BulkReport(ctx, csvData))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "clear_address", Title: "Delete your reports for an IP", Annotations: destructive,
		Description: "Permanently delete every AbuseIPDB report submitted by the authenticated account for one IPv4 or IPv6 address. This cannot delete other users' reports.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ClearAddressInput) (*mcp.CallToolResult, any, error) {
		if !in.Confirm {
			return nil, nil, errors.New("confirm must be true before permanently deleting reports")
		}
		ip, err := normalizeIP(in.IPAddress)
		if err != nil {
			return nil, nil, err
		}
		return apiResult(api.ClearAddress(ctx, ip))
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "list_categories", Title: "List AbuseIPDB categories", Annotations: closedWorld,
		Description: "List all official AbuseIPDB report category IDs, names, and descriptions. Use this before report_ip or bulk_report when category IDs are unknown.",
	}, func(context.Context, *mcp.CallToolRequest, CategoriesInput) (*mcp.CallToolResult, any, error) {
		return nil, map[string]any{"categories": Categories}, nil
	})
}

func annotations(readOnly, destructive, openWorld bool) *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    readOnly,
		DestructiveHint: boolPointer(destructive),
		IdempotentHint:  readOnly || destructive,
		OpenWorldHint:   boolPointer(openWorld),
	}
}

func boolPointer(v bool) *bool { return &v }

func apiResult(resp *abuseipdb.Response, err error) (*mcp.CallToolResult, any, error) {
	if err != nil {
		var apiErr *abuseipdb.Error
		if errors.As(err, &apiErr) && apiErr.RateLimit.RetryAfterSeconds != nil {
			err = fmt.Errorf("%w; retry after %d seconds", err, *apiErr.RateLimit.RetryAfterSeconds)
		}
		return nil, nil, err
	}
	out := make(map[string]any, len(resp.Payload)+1)
	for key, value := range resp.Payload {
		out[key] = value
	}
	out["rate_limit"] = resp.RateLimit
	return nil, out, nil
}

func normalizeIP(raw string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("ip_address must be a valid IPv4 or IPv6 address")
	}
	return addr.Unmap().String(), nil
}

func normalizeNetwork(raw string) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("network must be a valid IPv4 or IPv6 CIDR block")
	}
	return prefix.Masked().String(), nil
}

func normalizeCategories(values []int) ([]int, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one category is required")
	}
	seen := make(map[int]struct{}, len(values))
	result := make([]int, 0, len(values))
	for _, value := range values {
		if !validCategory(value) {
			return nil, fmt.Errorf("category %d is invalid; valid category IDs are 1 through 23", value)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Ints(result)
	return result, nil
}

func normalizeCountries(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if len(value) != 2 || value[0] < 'A' || value[0] > 'Z' || value[1] < 'A' || value[1] > 'Z' {
			return nil, fmt.Errorf("%q is not a two-letter country code", value)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func validateTimestamp(raw string, required bool, now time.Time) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if required {
			return "", errors.New("reported_at is required")
		}
		return "", nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return "", errors.New("reported_at must be an RFC 3339 timestamp with a timezone")
	}
	if t.Before(now.Add(-60 * 24 * time.Hour)) {
		return "", errors.New("reported_at must not be older than 60 days")
	}
	return t.Format(time.RFC3339), nil
}

func withDefaultRange(name string, value, fallback, min, max int) (int, error) {
	if value == 0 {
		value = fallback
	}
	if value < min || value > max {
		return 0, fmt.Errorf("%s must be between %d and %d", name, min, max)
	}
	return value, nil
}

func withDefaultMin(name string, value, fallback, min int) (int, error) {
	if value == 0 {
		value = fallback
	}
	if value < min {
		return 0, fmt.Errorf("%s must be at least %d", name, min)
	}
	return value, nil
}

func buildBulkCSV(reports []BulkReportItem, now time.Time) (string, error) {
	if len(reports) == 0 {
		return "", errors.New("reports must contain at least one row")
	}
	if len(reports) > MaxBulkRows {
		return "", fmt.Errorf("reports must contain at most %d rows", MaxBulkRows)
	}

	var b strings.Builder
	w := csv.NewWriter(&b)
	if err := w.Write([]string{"IP", "Categories", "ReportDate", "Comment"}); err != nil {
		return "", fmt.Errorf("write bulk report header: %w", err)
	}
	for i, report := range reports {
		ip, err := normalizeIP(report.IPAddress)
		if err != nil {
			return "", fmt.Errorf("reports[%d]: %w", i, err)
		}
		categories, err := normalizeCategories(report.Categories)
		if err != nil {
			return "", fmt.Errorf("reports[%d]: %w", i, err)
		}
		timestamp, err := validateTimestamp(report.ReportedAt, true, now)
		if err != nil {
			return "", fmt.Errorf("reports[%d]: %w", i, err)
		}
		comment := strings.TrimSpace(report.Comment)
		if comment == "" {
			return "", fmt.Errorf("reports[%d]: comment is required", i)
		}
		if len(comment) > 1024 {
			return "", fmt.Errorf("reports[%d]: comment must not exceed 1024 bytes", i)
		}
		if err := w.Write([]string{ip, joinCategories(categories), timestamp, comment}); err != nil {
			return "", fmt.Errorf("write reports[%d]: %w", i, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", fmt.Errorf("build bulk report CSV: %w", err)
	}
	if b.Len() >= MaxBulkCSVSize {
		return "", fmt.Errorf("generated CSV must be under %d bytes", MaxBulkCSVSize)
	}
	return b.String(), nil
}

func joinCategories(values []int) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprintf("%d", value)
	}
	return strings.Join(parts, ",")
}
