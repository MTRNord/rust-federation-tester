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

The application supports advanced debugging and observability through tokio-console and standard Rust logging.

### Tokio Console Integration

The application supports [tokio-console](https://github.com/tokio-rs/console), a debugger for async Rust programs that provides real-time task and async resource monitoring.

#### Prerequisites

First, install `tokio-console`:

```sh
cargo install --locked tokio-console
```

#### Tokio Console Usage

1. **Build with console support:**

   ```sh
   cargo build --features console --release
   ```

2. **Run the application with console enabled:**

   ```sh
   cargo run --features console --release
   ```

3. **Connect with tokio-console (in another terminal):**

   ```sh
   tokio-console
   ```

   By default, tokio-console connects to `127.0.0.1:6669`. The console-subscriber will automatically bind to this address when the console feature is enabled.

The console provides real-time insights into:

- Active tasks and their states
- Async resource usage (mutexes, channels, etc.)
- Task spawn rates and durations
- Resource contention and blocking

#### Configuration

The application automatically configures the necessary `tokio_unstable` compilation flags via `.cargo/config.toml`.

No additional environment variables are required - simply build with `--features console` to enable tokio-console support.

**Note:** The `.cargo/config.toml` file in the project root automatically adds the required `--cfg tokio_unstable` rustflag for all builds. This is necessary for tokio-console integration but doesn't affect normal operation when the console feature is disabled.

#### Environment Variables

| Variable | Values | Description |
|----------|--------|-------------|
| `RUST_LOG` | Log level directives | Controls standard logging output. Examples: `debug`, `rust_federation_tester=debug`, `trace` |

**Note:** When using the `console` feature, both tokio-console and standard logging output are available simultaneously. Standard logs will appear in your terminal while tokio-console provides the async runtime inspection interface.

**Important:** For tokio-console to display detailed task information, the application automatically enables `tokio=trace,runtime=trace` when built with the console feature. This ensures tokio-console receives the necessary runtime instrumentation data.

#### Production Considerations

⚠️ **Important:** The `console` feature should **not** be enabled in production builds as it:

- Adds runtime overhead for task tracking
- Exposes debugging endpoints
- Is intended for development and debugging only

For production, use standard logging with `RUST_LOG`:

```sh
RUST_LOG=info cargo run --release
```

### Standard Logging

When the `console` feature is not enabled, the application uses standard tracing-subscriber logging.

**Examples:**

- **Default logging:**

  ```sh
  cargo run --release
  ```

- **Debug logging:**

  ```sh
  RUST_LOG=debug cargo run --release
  ```

- **Module-specific logging:**

  ```sh
  RUST_LOG=rust_federation_tester=debug,hyper=warn cargo run --release
  ```

### Debug Cache Stats Endpoint

When debug logging is enabled (e.g., `RUST_LOG=debug` or `RUST_LOG=rust_federation_tester=debug`), a non-documented endpoint becomes available:

```http
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

```text
127.0.0.1/32, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1/128, fc00::/7
```

Requests whose source IP does not fall inside any configured CIDR receive `403 Forbidden`.

### Periodic Cache Metrics Logging

While in debug mode, the service emits a `cache_stats` debug log line every 60 seconds summarizing hit/miss/eviction counters for each cache and the active connection pool count. This helps correlate performance or anomalies with cache behavior.

### Example: Running in Debug Mode

```sh
RUST_LOG=debug cargo run --release
```

Then (from an allowed IP):

```sh
curl http://localhost:8080/api/federation/debug/cache-stats
```

---

## License

AGPL-3.0-or-later

---

This project is inspired
by [matrix-org/matrix-federation-tester](https://github.com/matrix-org/matrix-federation-tester), but implemented in
Rust and with a slightly different JSON response format.
