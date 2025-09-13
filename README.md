# Matrix Federation Tester (Rust)

A simple web service to test the federation setup of a Matrix homeserver. This tool checks DNS, `.well-known`
configuration, server keys, TLS certificates, and federation endpoints for a given Matrix server name.

## Features

- Resolves both IPv4 and IPv6 addresses for the target server.
- Fetches and validates the `/.well-known/matrix/server` endpoint for all resolved IPs.
- Checks DNS SRV, A, and AAAA records.
- Validates server keys and TLS certificates.
- Reports detailed results as JSON.

## Usage

### Running the Service

```sh
cargo run --release
```

The service will listen on `0.0.0.0:8080` by default.

### API Endpoints

#### `GET /api/report?server_name=<server_name>&no_cache=<true|false>`

Returns a detailed JSON report about the federation status of the given server.

**Example:**

```text
GET /api/report?server_name=matrix.org
```

#### `GET /api/federation-ok?server_name=<server_name>&no_cache=<true|false>`

Returns `GOOD` if federation is OK, otherwise `BAD`.

**Example:**

```text
GET /api/federation-ok?server_name=matrix.org
```

## Differences in the JSON Response to matrix-org/matrix-federation-tester

- The WellKnown section is now an object mapping each IP address to its corresponding `.well-known/matrix/server`
  response.

## Building

Requires Rust (edition 2021 or later).

```sh
cargo build --release
```

## Test & Coverage

Run all tests:

```sh
cargo test --workspace
```

Generate coverage (requires `cargo install cargo-llvm-cov`):

```sh
chmod +x coverage.sh
./coverage.sh
```

Open `target/coverage/html/index.html` in a browser for a detailed report.

## Debug & Observability

The application exposes additional observability capabilities when run in *debug mode* (controlled by environment variables).

### Environment Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `RFT_DEBUG` | `1`, `true` (case-insensitive) | unset (debug off) | Enables debug mode: extra logging, debug-only routes, periodic cache stats logging. |
| `RFT_LOG_FORMAT` | `text`, `json` | `text` | Selects log output format (JSON only active if compiled with a `json` feature). |
| `RFT_TRACE_SPANS` | `close` | unset | When `close`, emits span close events for latency measurements. |

### Debug Cache Stats Endpoint

When `RFT_DEBUG` is enabled a non-documented endpoint becomes available:

```
GET /api/federation/debug/cache-stats
```

It returns current cache metrics and connection pool size. Example response:

```json
{
  "dns": { "hits": 120, "misses": 15, "evictions": 2, "inserts": 135 },
  "well_known": { "hits": 45, "misses": 5, "evictions": 0, "inserts": 50 },
  "version": { "hits": 60, "misses": 4, "evictions": 1, "inserts": 64 },
  "connection_pools": 3
}
```

> Note: This endpoint is intentionally omitted from the OpenAPI spec and is only registered when debug mode is active.

### Access Control (`debug_allowed_nets`)

Access to the debug endpoint is restricted by a CIDR allowlist configured in `config.yaml`:

```yaml
debug_allowed_nets:
  - 127.0.0.1/32
  - 10.0.0.0/8
  - 192.168.0.0/16
  - fc00::/7
```

If `debug_allowed_nets` is omitted, the following defaults apply:

```
127.0.0.1/32, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1/128, fc00::/7
```

Requests whose source IP does not fall inside any configured CIDR receive `403 Forbidden`.

### Periodic Cache Metrics Logging

While in debug mode the service emits a `cache_stats` debug log line every 60 seconds summarizing hit/miss/eviction counters for each cache and the active connection pool count. This helps correlate performance or anomalies with cache behavior.

### Example: Running in Debug Mode

```sh
RFT_DEBUG=1 cargo run
```

Then (from an allowed IP):

```sh
curl http://localhost:8080/api/federation/debug/cache-stats
```

If you need JSON logs (enable the `json` feature):

```sh
cargo run --features json --release
```

Or combined with debug mode:

```sh
RFT_DEBUG=1 RFT_LOG_FORMAT=json cargo run --features json
```

### Enabling JSON Logs via Feature Flag

The server crate defines an optional `json` feature which activates the `tracing-subscriber` JSON formatter. Without the feature, requesting `RFT_LOG_FORMAT=json` logs a warning and falls back to text output. Build with:

```sh
cargo run --features json
```

Or for tests:

```sh
cargo test --features json
```

---

## License

AGPL-3.0-or-later

---

This project is inspired
by [matrix-org/matrix-federation-tester](https://github.com/matrix-org/matrix-federation-tester), but implemented in
Rust and with a slightly different JSON response format.
