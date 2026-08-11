package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const reportingPolicy = `AbuseIPDB reporting safety summary:
- Report only attacks you directly observed against systems you control.
- Do not report an address based only on its AbuseIPDB confidence score.
- Remove personally identifiable information from comments.
- Do not report traffic whose source is likely spoofed, including SYN or UDP floods.
- Reports must describe the attack and must not be older than 60 days.
- A timestamp, destination port, and relevant payload detail are recommended.

Authoritative policy: https://www.abuseipdb.com/reporting-policy
`

func registerResources(server *mcp.Server) {
	server.AddResource(&mcp.Resource{
		Name: "AbuseIPDB report categories", Title: "AbuseIPDB report categories",
		Description: "The complete category ID reference for AbuseIPDB reports.",
		MIMEType:    "application/json", URI: "abuseipdb://categories",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		data, err := json.MarshalIndent(map[string]any{"categories": Categories}, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("encode categories: %w", err)
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI: req.Params.URI, MIMEType: "application/json", Text: string(data),
		}}}, nil
	})

	server.AddResource(&mcp.Resource{
		Name: "AbuseIPDB reporting policy summary", Title: "AbuseIPDB reporting safety",
		Description: "Safety requirements to review before submitting AbuseIPDB reports.",
		MIMEType:    "text/plain", URI: "abuseipdb://reporting-policy",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI: req.Params.URI, MIMEType: "text/plain", Text: reportingPolicy,
		}}}, nil
	})
}
