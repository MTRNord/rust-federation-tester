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

```
GET /api/report?server_name=matrix.org
```

#### `GET /api/federation-ok?server_name=<server_name>&no_cache=<true|false>`

Returns `GOOD` if federation is OK, otherwise `BAD`.

**Example:**

```
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

## License

AGPL-3.0-or-later

---

This project is inspired
by [matrix-org/matrix-federation-tester](https://github.com/matrix-org/matrix-federation-tester), but implemented in
Rust and with a slightly different JSON response format.
