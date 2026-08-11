# Security policy

## Supported versions

Security fixes are applied to the latest released version and the `main` branch.

## Report a vulnerability

Please use GitHub's private vulnerability reporting feature for this repository. Do not open a public issue for suspected credential exposure, authentication bypass, request forgery, container escape, or another vulnerability.

Include the affected version or commit, deployment mode, reproduction steps, impact, and any suggested mitigation. Please do not test against AbuseIPDB infrastructure or submit real abuse reports as part of a proof of concept.

## Operator guidance

- Provide `ABUSEIPDB_API_KEY` through a secret manager or process environment, never through tool arguments or a committed `.env` file.
- Keep the default loopback bind for local Streamable HTTP. For remote access, use TLS at a trusted reverse proxy, configure `MCP_HTTP_BEARER_TOKEN`, and enforce network-level access controls.
- Treat tool responses and AbuseIPDB report comments as untrusted data.
- Require human approval for `report_ip`, `bulk_report`, and `clear_address` in the MCP client.
- Pin container tags or digests in production and review release provenance.

The server deliberately does not log the AbuseIPDB key, HTTP request headers, or tool arguments.
