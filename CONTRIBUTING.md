# Contributing

Thank you for improving the AbuseIPDB MCP server.

## Development setup

1. Install Go 1.25 or newer, Docker, and `rg` (ripgrep).
2. Fork and clone the repository.
3. Run `make check` before submitting a pull request.
4. Run `make test-race` for changes involving concurrency, transports, or shared state.

Tests must use `httptest`, fake APIs, documentation IP ranges, or in-memory MCP transports. Never put an AbuseIPDB API key in source, fixtures, logs, issues, or pull requests, and never submit a real report from a test.

## Pull requests

- Keep changes focused and include tests for behavior changes.
- Preserve stdio output discipline: protocol messages go to stdout and logs go to stderr.
- Validate untrusted input before consuming upstream quota.
- Mark MCP tools accurately with read-only, destructive, idempotent, and open-world annotations.
- Update `README.md` and `docs/TOOLS.md` when configuration or tool schemas change.
- Use conventional, imperative commit subjects where practical.

By contributing, you agree that your contribution is licensed under the MIT License.

## Releases

Release tags must be annotated, exact semantic versions such as `v1.2.3` or `v1.2.3-rc.1`. Tag only reviewed commits merged to `main`, and never move or reuse an existing release tag. See [RELEASING.md](RELEASING.md) for the complete checklist.
