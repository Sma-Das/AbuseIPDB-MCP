# syntax=docker/dockerfile:1.7
FROM golang:1.27-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${BUILD_DATE}" \
    -o /out/abuseipdb-mcp ./cmd/abuseipdb-mcp

FROM scratch
LABEL org.opencontainers.image.title="AbuseIPDB MCP Server in Go" \
      org.opencontainers.image.description="MCP server for AbuseIPDB IP reputation and threat intelligence" \
      org.opencontainers.image.source="https://github.com/Sma-Das/AbuseIPDB-MCP" \
      org.opencontainers.image.licenses="MIT" \
      io.modelcontextprotocol.server.name="io.github.sma-das/abuseipdb"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/abuseipdb-mcp /abuseipdb-mcp

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/abuseipdb-mcp"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/abuseipdb-mcp", "-healthcheck"]
