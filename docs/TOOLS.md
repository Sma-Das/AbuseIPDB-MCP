# AbuseIPDB MCP tool reference

This reference documents the tools exposed by `io.github.sma-das/abuseipdb`. All upstream calls use AbuseIPDB API v2 and return the original JSON envelope with an additional `rate_limit` object.

## Read tools

### `check_ip`

- `ip_address` (string, required): valid IPv4 or IPv6 address.
- `max_age_in_days` (integer, default `30`): `1` through `365`; the account plan may impose a lower maximum.
- `verbose` (boolean, default `false`): includes country name and individual reports. AbuseIPDB caps this report array at 10,000 items.

### `get_ip_reports`

- `ip_address` (string, required): valid IPv4 or IPv6 address.
- `max_age_in_days` (integer, default `30`): `1` through `365`.
- `page` (integer, default `1`): one-based page number.
- `per_page` (integer, default `25`): `1` through `100`.

The upstream reports endpoint is documented by AbuseIPDB as open beta.

### `get_blacklist`

- `confidence_minimum` (integer, default `100`): `25` through `100`; thresholds below `100` require a subscription.
- `limit` (integer, default `10000`): at least `1`. AbuseIPDB truncates the response to the plan maximum: 10,000, 100,000, or 500,000.
- `only_countries` (string array): ISO alpha-2 codes to include; subscription feature.
- `except_countries` (string array): ISO alpha-2 codes to exclude; subscription feature. Mutually exclusive with `only_countries`.
- `ip_version` (integer): `4`, `6`, or omitted for both.

The tool always requests JSON rather than the optional plaintext blacklist so clients receive confidence and timestamp fields.

### `check_block`

- `network` (string, required): IPv4 or IPv6 CIDR block.
- `max_age_in_days` (integer, default `30`): `1` through `365`.

AbuseIPDB plan limits include network size and lookback. Its documented IPv4 block maxima are `/24` for Standard, `/20` for Basic, and `/16` for Premium.

### `list_categories`

Takes no arguments and returns all 23 report categories. The same data is available from the `abuseipdb://categories` MCP resource.

## Write tools

Write tools require `confirm: true`. MCP clients should still show their normal tool approval UI.

### `report_ip`

- `ip_address` (string, required): directly observed source IPv4 or IPv6 address.
- `categories` (integer array, required): one or more category IDs from `1` through `23`.
- `comment` (string, required by this server): detailed description, at most 1,024 bytes, with PII removed.
- `reported_at` (string): optional RFC 3339 timestamp with timezone, no older than 60 days.
- `confirm` (boolean, required): must be `true`.

The API prevents the same account from reporting the same IP more than once in 15 minutes.

### `bulk_report`

- `reports` (array, required): `1` through `9,999` structured rows.
  - `ip_address`: valid IPv4 or IPv6 address.
  - `categories`: one or more IDs from `1` through `23`.
  - `reported_at`: required RFC 3339 timestamp with timezone, no older than 60 days.
  - `comment`: required description, at most 1,024 bytes, with PII removed.
- `confirm` (boolean, required): must be `true`.

The server sorts and deduplicates categories, writes a standards-compliant CSV with the official headings, enforces the 10,000-line cap including the header, and rejects a generated file of 8 MiB or larger.

### `clear_address`

- `ip_address` (string, required): address whose reports should be removed.
- `confirm` (boolean, required): must be `true`.

This endpoint deletes only reports created by the authenticated AbuseIPDB account. It cannot delete reports submitted by other users.

## Error behavior

Invalid arguments are rejected before quota is consumed. Non-2xx AbuseIPDB responses become MCP tool errors and retain the upstream status/detail. HTTP 429 errors include the `Retry-After` duration when present. The API key is never included in an error.

Authoritative references:

- [AbuseIPDB API v2 documentation](https://docs.abuseipdb.com/)
- [AbuseIPDB report categories](https://www.abuseipdb.com/categories)
- [AbuseIPDB reporting policy](https://www.abuseipdb.com/reporting-policy)
- [AbuseIPDB bulk reporter format](https://www.abuseipdb.com/bulk-report)
