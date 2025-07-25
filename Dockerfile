FROM --platform=$BUILDPLATFORM rustlang/rust:nightly AS builder
WORKDIR /app
COPY . .

# Install cross-compiler if needed for ARM
RUN if [ \"$TARGETPLATFORM\" = \"linux/arm64\" ]; then \
      apt-get update && apt-get install -y gcc-aarch64-linux-gnu; \
    fi

# Add Rust target for cross-compiling
RUN rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu

# Build for the target platform
RUN cargo build --release --package rust-federation-tester --target ${TARGETPLATFORM#linux/}-unknown-linux-gnu
RUN cargo build --release --package migration --target ${TARGETPLATFORM#linux/}-unknown-linux-gnu

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Copy the correct binary for the target platform
COPY --from=builder /app/target/$(echo $TARGETPLATFORM | sed 's/linux\\///')-unknown-linux-gnu/release/rust-federation-tester /usr/local/bin/rust-federation-tester
COPY --from=builder /app/target/$(echo $TARGETPLATFORM | sed 's/linux\\///')-unknown-linux-gnu/release/migration /usr/local/bin/migration

EXPOSE 8080
CMD ["sh", "-c", "migration up && rust-federation-tester"]