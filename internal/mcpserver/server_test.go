package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Sma-Das/AbuseIPDB-MCP/internal/abuseipdb"
	"github.com/Sma-Das/AbuseIPDB-MCP/internal/reporting"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeAPI struct {
	lastCall    string
	lastReport  reporting.Report
	lastReports []reporting.Report
	err         error
}

func (f *fakeAPI) result(name string) (*abuseipdb.Response, error) {
	f.lastCall = name
	if f.err != nil {
		return nil, f.err
	}
	limit := int64(1000)
	return &abuseipdb.Response{
		Payload:   map[string]any{"data": map[string]any{"operation": name}},
		RateLimit: abuseipdb.RateLimit{Limit: &limit},
	}, nil
}

func (f *fakeAPI) CheckIP(context.Context, string, int, bool) (*abuseipdb.Response, error) {
	return f.result("check_ip")
}
func (f *fakeAPI) Reports(context.Context, string, int, int, int) (*abuseipdb.Response, error) {
	return f.result("get_ip_reports")
}
func (f *fakeAPI) Blacklist(context.Context, int, int, int, []string, []string) (*abuseipdb.Response, error) {
	return f.result("get_blacklist")
}
func (f *fakeAPI) Report(_ context.Context, report reporting.Report) (*abuseipdb.Response, error) {
	f.lastReport = report
	return f.result("report_ip")
}
func (f *fakeAPI) CheckBlock(context.Context, string, int) (*abuseipdb.Response, error) {
	return f.result("check_block")
}
func (f *fakeAPI) BulkReport(_ context.Context, reports []reporting.Report) (*abuseipdb.Response, error) {
	f.lastReports = reports
	return f.result("bulk_report")
}
func (f *fakeAPI) ClearAddress(context.Context, string) (*abuseipdb.Response, error) {
	return f.result("clear_address")
}

func TestMCPServerListsCompleteSurface(t *testing.T) {
	api := &fakeAPI{}
	session := connectTestClient(t, New(api, "test"))
	ctx := context.Background()

	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{
		"check_ip", "get_ip_reports", "get_blacklist", "report_ip",
		"check_block", "bulk_report", "clear_address", "list_categories",
	}
	if len(listed.Tools) != len(wantNames) {
		t.Fatalf("listed %d tools, want %d", len(listed.Tools), len(wantNames))
	}
	byName := make(map[string]*mcp.Tool, len(listed.Tools))
	for _, tool := range listed.Tools {
		byName[tool.Name] = tool
	}
	for _, name := range wantNames {
		if byName[name] == nil {
			t.Errorf("tool %q is missing", name)
		}
	}
	if !byName["check_ip"].Annotations.ReadOnlyHint {
		t.Error("check_ip is not annotated read-only")
	}
	if byName["clear_address"].Annotations.DestructiveHint == nil || !*byName["clear_address"].Annotations.DestructiveHint {
		t.Error("clear_address is not annotated destructive")
	}
	if byName["report_ip"].Annotations.ReadOnlyHint {
		t.Error("report_ip is incorrectly annotated read-only")
	}
	for _, name := range []string{"report_ip", "bulk_report"} {
		schema, err := json.Marshal(byName[name].InputSchema)
		if err != nil {
			t.Fatalf("marshal %s input schema: %v", name, err)
		}
		if !strings.Contains(string(schema), "not in the future") {
			t.Errorf("%s input schema omits the future-date restriction: %s", name, schema)
		}
	}

	resources, err := session.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources.Resources) != 2 {
		t.Fatalf("listed %d resources, want 2", len(resources.Resources))
	}
	read, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: "abuseipdb://categories"})
	if err != nil {
		t.Fatal(err)
	}
	if len(read.Contents) != 1 || !strings.Contains(read.Contents[0].Text, "DNS Compromise") {
		t.Fatalf("unexpected categories resource: %+v", read.Contents)
	}
	policy, err := session.ReadResource(ctx, &mcp.ReadResourceParams{URI: "abuseipdb://reporting-policy"})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Contents) != 1 || !strings.Contains(policy.Contents[0].Text, "or in the future") {
		t.Fatalf("reporting policy omits the future-date restriction: %+v", policy.Contents)
	}
}

func TestMCPToolsInvokeEveryAPIEndpoint(t *testing.T) {
	api := &fakeAPI{}
	session := connectTestClient(t, New(api, "test"))
	now := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	tests := []struct {
		name string
		args map[string]any
	}{
		{"check_ip", map[string]any{"ip_address": "::ffff:192.0.2.1", "max_age_in_days": 7}},
		{"get_ip_reports", map[string]any{"ip_address": "192.0.2.1", "page": 2, "per_page": 10}},
		{"get_blacklist", map[string]any{"confidence_minimum": 90, "only_countries": []string{"us", "CA"}, "ip_version": 4}},
		{"report_ip", map[string]any{"ip_address": "192.0.2.2", "categories": []int{22, 18}, "comment": "SSH brute-force on tcp/22", "reported_at": now, "confirm": true}},
		{"check_block", map[string]any{"network": "192.0.2.23/24"}},
		{"bulk_report", map[string]any{"reports": []map[string]any{{"ip_address": "192.0.2.3", "categories": []int{14}, "reported_at": now, "comment": "TCP port scan"}}, "confirm": true}},
		{"clear_address", map[string]any{"ip_address": "192.0.2.4", "confirm": true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: tt.name, Arguments: tt.args})
			if err != nil {
				t.Fatal(err)
			}
			if result.IsError {
				t.Fatalf("tool returned error: %+v", result.Content)
			}
			if api.lastCall != tt.name {
				t.Fatalf("API call = %q, want %q", api.lastCall, tt.name)
			}
			if result.StructuredContent == nil {
				t.Fatal("structured content is missing")
			}
		})
	}
	if api.lastReport.IPAddress != "192.0.2.2" || len(api.lastReport.Categories) != 2 ||
		api.lastReport.Categories[0] != 18 || api.lastReport.Categories[1] != 22 {
		t.Fatalf("single report was not normalized: %+v", api.lastReport)
	}
	if len(api.lastReports) != 1 || api.lastReports[0].IPAddress != "192.0.2.3" {
		t.Fatalf("bulk reports were not normalized: %+v", api.lastReports)
	}
}

func TestMutationToolsRequireConfirmation(t *testing.T) {
	api := &fakeAPI{}
	session := connectTestClient(t, New(api, "test"))
	tests := []struct {
		name string
		args map[string]any
	}{
		{"report_ip", map[string]any{"ip_address": "192.0.2.1", "categories": []int{14}, "comment": "scan", "confirm": false}},
		{"bulk_report", map[string]any{"reports": []any{}, "confirm": false}},
		{"clear_address", map[string]any{"ip_address": "192.0.2.1", "confirm": false}},
	}
	for _, tt := range tests {
		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: tt.name, Arguments: tt.args})
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Errorf("%s succeeded without confirmation", tt.name)
		}
	}
	if api.lastCall != "" {
		t.Fatalf("API was called unexpectedly: %s", api.lastCall)
	}
}

func TestToolReturnsAPIRetryInformation(t *testing.T) {
	retry := int64(12)
	api := &fakeAPI{err: &abuseipdb.Error{
		StatusCode: 429, Status: "429 Too Many Requests",
		Items:     []abuseipdb.ErrorItem{{Detail: "rate limited"}},
		RateLimit: abuseipdb.RateLimit{RetryAfterSeconds: &retry},
	}}
	session := connectTestClient(t, New(api, "test"))
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_ip", Arguments: map[string]any{"ip_address": "192.0.2.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "retry after 12 seconds") {
		t.Fatalf("retry information missing: %+v", result)
	}
}

func TestValidationHelpers(t *testing.T) {
	if got, err := normalizeIP(" ::ffff:192.0.2.1 "); err != nil || got != "192.0.2.1" {
		t.Fatalf("normalizeIP = %q, %v", got, err)
	}
	if got, err := normalizeNetwork("192.0.2.99/24"); err != nil || got != "192.0.2.0/24" {
		t.Fatalf("normalizeNetwork = %q, %v", got, err)
	}
	if got, err := normalizeCountries([]string{"us", "CA", "US"}); err != nil || strings.Join(got, ",") != "CA,US" {
		t.Fatalf("normalizeCountries = %v, %v", got, err)
	}
	if _, err := normalizeCountries([]string{"USA"}); err == nil {
		t.Error("invalid country was accepted")
	}
}

func connectTestClient(t *testing.T, server *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		_ = serverSession.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})
	return clientSession
}

func TestWriteToolsRejectFutureReportsBeforeCallingAPI(t *testing.T) {
	api := &fakeAPI{}
	session := connectTestClient(t, New(api, "test"))
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	for _, tt := range []struct {
		name string
		args map[string]any
	}{
		{"report_ip", map[string]any{
			"ip_address": "192.0.2.1", "categories": []int{14}, "comment": "scan",
			"reported_at": future, "confirm": true,
		}},
		{"bulk_report", map[string]any{
			"reports": []map[string]any{{
				"ip_address": "192.0.2.1", "categories": []int{14}, "comment": "scan", "reported_at": future,
			}},
			"confirm": true,
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: tt.name, Arguments: tt.args})
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError || !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "in the future") {
				t.Fatalf("future report result = %+v", result)
			}
		})
	}
	if api.lastCall != "" {
		t.Fatalf("API was called unexpectedly: %s", api.lastCall)
	}
}

func TestAPIResultHandlesGenericError(t *testing.T) {
	_, _, err := apiResult(nil, errors.New("boom"))
	if err == nil || err.Error() != "boom" {
		t.Fatalf("apiResult error = %v", err)
	}
}
