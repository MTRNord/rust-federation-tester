FROM rust:1.87 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/rust-federation-tester /usr/local/bin/rust-federation-tester
EXPOSE 8080
CMD ["rust-federation-tester"]