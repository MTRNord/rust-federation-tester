# Matrix Federation Tester (Rust)

A simple web service to test the federation setup of a Matrix homeserver. This tool checks DNS, `.well-known`
configuration, server keys, TLS certificates, and federation endpoints for a given Matrix server name.

## Features

- Resolves both IPv4 and IPv6 addresses for the target server.
- Fetches and validates the `/.well-known/matrix/server` endpoint for all resolved IPs.
- Checks DNS SRV, A, and AAAA records.
- Validates server keys and TLS certificates.
- Reports detailed results as JSON.
- Optional anonymized, opt-in federation request statistics with Prometheus export.

## Usage

### Running the Service

First you should take a look at `config.yaml.example`
and create your own `config.yaml` file.
The service will look for `config.yaml` in the current working directory.

After that, run the database migrations and start the service:

```sh
cargo run --package migration -- up --database-url <sqlite or postgres URL>
cargo run --release --bin rust-federation-tester
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

## Federation Statistics & Prometheus Metrics

The service can (optionally) record per-request federation statistics on a strict opt-in basis and expose anonymized aggregates via `GET /metrics` in Prometheus text format.

### Opt-In Model

Statistics are only recorded if **both** of these are true:

1. `statistics.enabled` is `true` in `config.yaml`.
2. The incoming request to `/api/report` (or other future endpoints) includes the query parameter `stats_opt_in=1`.

If either condition is not met, the request is processed normally but no event is persisted.

### Anonymization

Server names are never stored or exported in raw form to Prometheus. Instead, each server name is hashed using: `blake3(anonymization_salt || "::" || server_name)`.

To prevent correlation across deployments, you MUST configure a unique, secret `anonymization_salt`. Changing the salt will rotate (invalidate) all previously emitted anonymized identifiers.

If `statistics.enabled` and `statistics.prometheus_enabled` are both `true` but `anonymization_salt` is empty, startup will fail (validation error).

### Configuration (`statistics` block)

```yaml
statistics:
  enabled: false                 # Master switch. When false, nothing is recorded.
  prometheus_enabled: true       # Expose /metrics with anonymized counters.
  anonymization_salt: "change-me" # REQUIRED (non-empty) when both enabled + prometheus_enabled are true.
  raw_retention_days: 30         # Inactive rows (no updates for > N days) are pruned periodically.
```

Only aggregate counters are stored currently; there is no raw per-event table yet. A pruning task runs every 12h and deletes rows whose `last_seen_at` is older than `raw_retention_days`.

### Metrics Exposed

`federation_request_total{server="<anon>",result="success|failure",software_family="<family>",software_version="<version>"}`

Per anonymized server + outcome. `software_family` and `software_version` are heuristically extracted from the Matrix server's reported version string (currently detects `synapse`, `conduit`, `dendrite`). Missing values are omitted.

`federation_request_family_total{software_family="<family>",result="success|failure"}`

Aggregated by software family (allows trends without per-instance granularity).

Both counters are monotonic and backed by a lightweight aggregate table maintained through high-level SeaORM entity operations (no manual SQL upsert logic). Each opted-in request results in either an insert (first time a server is seen) or an update (incrementing existing counters and refreshing last_seen_at).

### Example Request with Opt-In

```sh
curl "http://localhost:8080/api/report?server_name=example.org&stats_opt_in=1"
```

Then scrape metrics:

```sh
curl http://localhost:8080/metrics
```

## Contribution using the mailinglist

For non github contributors as well as a place to discuss we offer a mailinglist:

<https://lists.midnightthoughts.space/mailman3/lists/matrix-connectivity-tester.lists.midnightthoughts.space/>

It is meant to be used for the projects at:

- <https://github.com/MTRNord/rust-federation-tester>
- <https://github.com/MTRNord/matrix-connection-tester-ui>
- <https://connectivity-tester.mtrnord.blog>
- <https://stage.connectivity-tester.mtrnord.blog>

Patches are welcome. Have a look at <https://git-send-email.io/> or
<https://www.youtube.com/watch?v=mjYac9SwIK0> and
<https://www.youtube.com/watch?v=p79IjNay4mY> regarding how to do mailinglist based contributions.

Curently PRs via github are also welcome however this may change in the future.

---

## License

AGPL-3.0-or-later

---

This project is inspired
by [matrix-org/matrix-federation-tester](https://github.com/matrix-org/matrix-federation-tester), but implemented in
Rust and with a slightly different JSON response format.
