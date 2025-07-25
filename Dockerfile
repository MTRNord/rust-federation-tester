FROM --platform=$BUILDPLATFORM rustlang/rust:nightly AS builder
ARG TARGETPLATFORM
WORKDIR /app
COPY . .

# Install cross-compiler if needed for ARM
RUN if [ \"$TARGETPLATFORM\" = \"linux/arm64\" ]; then \
      apt-get update && apt-get install -y gcc-aarch64-linux-gnu; \
    fi

# Add Rust target for cross-compiling
RUN rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu

# Build for the target platform
RUN echo $TARGETPLATFORM
RUN case \"$TARGETPLATFORM\" in \
      \"linux/amd64\") TARGET_TRIPLE=x86_64-unknown-linux-gnu ;; \
      \"linux/arm64\") TARGET_TRIPLE=aarch64-unknown-linux-gnu ;; \
      *) echo \"Unsupported platform: $TARGETPLATFORM\"; exit 1 ;; \
    esac && \
    cargo build --release --package rust-federation-tester --target $TARGET_TRIPLE && \
    cargo build --release --package migration --target $TARGET_TRIPLE

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Copy the correct binary for the target platform
COPY --from=builder /app/target/x86_64-unknown-linux-gnu/release/rust-federation-tester /usr/local/bin/rust-federation-tester
COPY --from=builder /app/target/x86_64-unknown-linux-gnu/release/migration /usr/local/bin/migration
COPY --from=builder /app/target/aarch64-unknown-linux-gnu/release/rust-federation-tester /usr/local/bin/rust-federation-tester
COPY --from=builder /app/target/aarch64-unknown-linux-gnu/release/migration /usr/local/bin/migration

EXPOSE 8080
CMD ["sh", "-c", "migration up && rust-federation-tester"]