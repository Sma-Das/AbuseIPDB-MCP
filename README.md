# AbuseIPDB MCP Server in Go — IP Reputation & Threat Intelligence

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-2026--07--28-6f42c1)](https://modelcontextprotocol.io/)
[![CI](https://github.com/Sma-Das/AbuseIPDB-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/Sma-Das/AbuseIPDB-MCP/actions/workflows/ci.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/smadas/abuseipdb-mcp?logo=docker)](https://hub.docker.com/r/smadas/abuseipdb-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A complete, dockerized **AbuseIPDB MCP server written in Go**. Connect an MCP-compatible AI assistant or security automation workflow to the AbuseIPDB API v2 for IP reputation checks, abuse-report history, CIDR analysis, blacklist retrieval, single and bulk abuse reporting, and report cleanup.

This implementation uses the [official Model Context Protocol Go SDK](https://github.com/modelcontextprotocol/go-sdk), supports stdio and Streamable HTTP, returns structured JSON, preserves AbuseIPDB rate-limit information, and covers every endpoint in the public AbuseIPDB API v2 documentation.

> [!IMPORTANT]
> This is an independent open-source project. It is not affiliated with or endorsed by AbuseIPDB. You need your own [AbuseIPDB API v2 key](https://www.abuseipdb.com/account/api), and your account plan controls API quotas and feature limits.

## Why use this AbuseIPDB MCP server?

- **Complete API coverage:** all seven documented AbuseIPDB v2 endpoints, not only IP check and report.
- **Native Go binary:** fast startup, low runtime overhead, static container image, and no Python or Node.js runtime.
- **Current MCP transports:** local stdio and stateless Streamable HTTP through the official Go SDK.
- **Safety-aware write tools:** explicit MCP annotations, mandatory confirmation, category validation, PII warnings, and AbuseIPDB reporting-policy guardrails.
- **Production-friendly:** non-root scratch container, read-only Compose service, health endpoint, graceful shutdown, response limits, bearer authentication, origin checks, and no API-key logging.
- **LLM-friendly results:** structured AbuseIPDB JSON plus `rate_limit` metadata, with text fallbacks for older MCP clients.
- **IPv4 and IPv6:** single-address and CIDR tools normalize both address families.

## Supported MCP tools

| Tool | AbuseIPDB endpoint | What it does | Side effect |
| --- | --- | --- | --- |
| `check_ip` | `GET /check` | IP reputation, confidence score, network owner, report totals, and optional detailed reports | Read-only |
| `get_ip_reports` | `GET /reports` | Paginated report history for an IPv4 or IPv6 address | Read-only |
| `get_blacklist` | `GET /blacklist` | Plan-aware blacklist with confidence, country, limit, and IP-version filters | Read-only |
| `report_ip` | `POST /report` | Submit one directly observed abuse event | External write; confirmation required |
| `check_block` | `GET /check-block` | Analyze an IPv4 or IPv6 network in CIDR notation | Read-only |
| `bulk_report` | `POST /bulk-report` | Generate and upload an AbuseIPDB CSV from up to 9,999 structured reports | External write; confirmation required |
| `clear_address` | `DELETE /clear-address` | Delete reports submitted by your account for one address | Destructive; confirmation required |
| `list_categories` | Local reference | Return all 23 AbuseIPDB report category IDs and descriptions | Read-only |

The server also publishes `abuseipdb://categories` and `abuseipdb://reporting-policy` as MCP resources. See [the complete tool reference](docs/TOOLS.md) for parameters, defaults, plan constraints, and examples.

## Quick start with Docker

Pull the multi-architecture image from Docker Hub:

```bash
docker pull smadas/abuseipdb-mcp:edge
```

Run it over stdio for a local MCP client:

```bash
docker run --rm -i \
  -e ABUSEIPDB_API_KEY="your-api-v2-key" \
  smadas/abuseipdb-mcp:edge
```

Example MCP client configuration:

```json
{
  "mcpServers": {
    "abuseipdb": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "ABUSEIPDB_API_KEY",
        "smadas/abuseipdb-mcp:edge"
      ],
      "env": {
        "ABUSEIPDB_API_KEY": "your-api-v2-key"
      }
    }
  }
}
```

Some clients pass the parent environment to Docker and do not need the nested `env` object. If your client substitutes environment variables in arguments, use that mechanism instead of storing a key directly in JSON.

Every push to `main` publishes `edge` and an immutable `sha-<commit>` tag to [Docker Hub](https://hub.docker.com/r/smadas/abuseipdb-mcp). Git tags matching `v*` publish semantic-version tags and `latest` to both Docker Hub and GitHub Container Registry. Pull requests build the image without publishing it. To build locally instead, run `docker build -t abuseipdb-mcp:local .`.

## Streamable HTTP with Docker Compose

Copy the environment template and replace both secrets:

```bash
cp .env.example .env
docker compose up --build -d
curl http://127.0.0.1:8080/healthz
```

The MCP endpoint is `http://127.0.0.1:8080/mcp`. When `MCP_HTTP_BEARER_TOKEN` is set, clients must send:

```text
Authorization: Bearer your-token
```

The included Compose configuration publishes only to host loopback, drops Linux capabilities, prevents privilege escalation, uses a read-only filesystem, and runs as an unprivileged numeric user.

## Run the Go binary

Go 1.25 or newer is required because the current official MCP Go SDK requires it.

```bash
go build -o bin/abuseipdb-mcp ./cmd/abuseipdb-mcp
ABUSEIPDB_API_KEY="your-api-v2-key" ./bin/abuseipdb-mcp
```

For HTTP:

```bash
ABUSEIPDB_API_KEY="your-api-v2-key" \
MCP_TRANSPORT=http \
MCP_HTTP_BEARER_TOKEN="use-a-long-random-token" \
./bin/abuseipdb-mcp
```

Command-line flags can override transport settings:

```text
-transport stdio|http
-http-addr 127.0.0.1:8080
-http-path /mcp
-version
```

## Configuration

| Environment variable | Required | Default | Description |
| --- | --- | --- | --- |
| `ABUSEIPDB_API_KEY` | Yes | — | AbuseIPDB API v2 key. Sent only in the upstream `Key` header. |
| `ABUSEIPDB_BASE_URL` | No | `https://api.abuseipdb.com/api/v2` | Override for compatible gateways or testing. Must be an absolute HTTP(S) URL without embedded credentials. |
| `ABUSEIPDB_TIMEOUT` | No | `30s` | Go duration for one upstream request. |
| `ABUSEIPDB_MAX_RESPONSE_BYTES` | No | `16777216` | Maximum upstream response body. Increase cautiously for premium blacklists larger than roughly 100,000 entries. |
| `MCP_TRANSPORT` | No | `stdio` | `stdio` or `http`. |
| `MCP_HTTP_ADDR` | No | `127.0.0.1:8080` | Streamable HTTP listen address. Docker Compose overrides it to `0.0.0.0:8080` inside the container while binding host loopback. |
| `MCP_HTTP_PATH` | No | `/mcp` | Streamable HTTP endpoint path. |
| `MCP_HTTP_BEARER_TOKEN` | Recommended for HTTP | — | Static bearer token required by the MCP route. The health route remains unauthenticated. |

## Abuse reporting safety

`report_ip`, `bulk_report`, and `clear_address` require `confirm: true`. This deliberately makes side effects visible to both the model and the human approval flow.

Before reporting an IP:

- Report only traffic directly observed against a system you control.
- Never report an address solely because its AbuseIPDB confidence score is high.
- Strip names, email addresses, credentials, and other personally identifiable information from comments.
- Do not report traffic whose source can be spoofed, such as SYN floods and UDP floods.
- Describe the event and include a timezone-aware timestamp; reports must not be older than 60 days or dated in the future.
- Remember that AbuseIPDB prevents duplicate reports for the same address within 15 minutes.

Read the authoritative [AbuseIPDB reporting policy](https://www.abuseipdb.com/reporting-policy) before enabling write tools in unattended automation.

## Rate limits and account plans

AbuseIPDB applies daily limits per endpoint and resets API v2 quotas at 00:00 UTC. This server does not retry writes or silently consume additional quota. Every successful tool result includes:

```json
{
  "rate_limit": {
    "limit": 1000,
    "remaining": 999,
    "reset_at": "2026-08-11T00:00:00Z"
  }
}
```

On HTTP 429, the tool error includes `Retry-After` when AbuseIPDB supplies it. Subscription-only filters and plan-dependent CIDR/lookback limits remain enforced by AbuseIPDB and surface as clear tool errors.

## Example tool calls

Check an address without the potentially large verbose report list:

```json
{
  "name": "check_ip",
  "arguments": {
    "ip_address": "198.51.100.42",
    "max_age_in_days": 30,
    "verbose": false
  }
}
```

Report a directly observed SSH brute-force event:

```json
{
  "name": "report_ip",
  "arguments": {
    "ip_address": "198.51.100.42",
    "categories": [18, 22],
    "comment": "Repeated failed SSH authentication against tcp/22; user identifiers removed",
    "reported_at": "2026-08-10T20:15:00Z",
    "confirm": true
  }
}
```

Addresses in the documentation use [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) or [RFC 3849](https://datatracker.ietf.org/doc/html/rfc3849) documentation ranges. Replace them with an address you actually observed before reporting.

## Development and verification

```bash
make check       # formatting check, go vet, and unit/integration tests
make test-race   # race detector
make build       # versioned local binary
make docker-build
```

Tests use only fake AbuseIPDB servers and in-memory MCP transports. They never require an API key and never submit real reports.

Project layout:

```text
cmd/abuseipdb-mcp/  CLI, stdio transport, HTTP transport, health endpoint
internal/abuseipdb/ AbuseIPDB API v2 client and error/rate-limit handling
internal/config/    environment configuration and validation
internal/mcpserver/ MCP tools, resources, and protocol adapters
internal/reporting/ Report intake, categories, and safety validation
examples/           client and tool-call examples
```

## Frequently asked questions

### Does this MCP server support IPv6 and CIDR ranges?

Yes. `check_ip`, `get_ip_reports`, `report_ip`, and `clear_address` accept IPv4 or IPv6. `check_block` accepts IPv4 or IPv6 CIDR notation and normalizes host bits to the network address.

### Can I use it as an AbuseIPDB MCP server for Claude, Cursor, VS Code, or another AI client?

Yes, provided the client supports MCP stdio or Streamable HTTP. The protocol and container configuration are client-neutral. Adapt the generic examples in [`examples/mcp-client-configs.json`](examples/mcp-client-configs.json) to the client's configuration location.

### Does the server cache AbuseIPDB responses?

No. Reputation data changes and API quotas vary by account, so this server returns the upstream result and rate-limit headers directly. Add a trusted caching gateway through `ABUSEIPDB_BASE_URL` if your environment requires one.

### Is the API key exposed to the language model?

No. The key comes from the server process environment and is added only to the upstream HTTP `Key` header. Tool schemas and results do not contain it, and the server does not log request headers.

### Why does a blacklist or CIDR request return HTTP 402?

AbuseIPDB uses HTTP 402 when a requested confidence threshold, lookback, or block size exceeds the authenticated plan. Reduce the requested scope or review your AbuseIPDB plan.

## Discoverability and repository topics

Suggested GitHub topics: `abuseipdb`, `mcp`, `mcp-server`, `model-context-protocol`, `golang`, `go`, `docker`, `cybersecurity`, `threat-intelligence`, `ip-reputation`, `ipv6`, `security-automation`, `soc`, `osint`.

## Contributing and security

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

[MIT](LICENSE) © 2026 Sma Das.

AbuseIPDB is a trademark of its respective owner. Use of the name describes API compatibility only.
