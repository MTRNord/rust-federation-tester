FROM rustlang/rust:nightly AS builder

WORKDIR /app
COPY . .
RUN cargo build --release --package rust-federation-tester
RUN cargo build --release --package migration

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY --from=builder /app/target/release/rust-federation-tester /usr/local/bin/rust-federation-tester
COPY --from=builder /app/target/release/migration /usr/local/bin/migration

EXPOSE 8080
CMD ["sh", "-c", "migration up && rust-federation-tester"]