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
RUN case "$TARGETPLATFORM" in \
      "linux/amd64") TARGET_TRIPLE=x86_64-unknown-linux-gnu; \
        cargo build --release --package rust-federation-tester --target $TARGET_TRIPLE && \
        cargo build --release --package migration --target $TARGET_TRIPLE ;; \
      "linux/arm64") TARGET_TRIPLE=aarch64-unknown-linux-gnu; \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
        CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
        cargo build --release --package rust-federation-tester --target $TARGET_TRIPLE && \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
        CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
        cargo build --release --package migration --target $TARGET_TRIPLE ;; \
      *) echo "Unsupported platform: $TARGETPLATFORM"; exit 1 ;; \
    esac

# Copy the binaries to a common location
RUN mkdir -p /app/target/dist
RUN case \"$TARGETPLATFORM\" in \
      \"linux/amd64\") TARGET_TRIPLE=x86_64-unknown-linux-gnu ;; \
      \"linux/arm64\") TARGET_TRIPLE=aarch64-unknown-linux-gnu ;; \
      *) echo \"Unsupported platform: $TARGETPLATFORM\"; exit 1 ;; \
    esac && \
    cp /app/target/$TARGET_TRIPLE/release/rust-federation-tester /app/target/dist/rust-federation-tester && \
    cp /app/target/$TARGET_TRIPLE/release/migration /app/target/dist/migration

FROM debian:bookworm-slim
ARG TARGETPLATFORM

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY --from=builder /app/target/dist/rust-federation-tester /usr/local/bin/rust-federation-tester
COPY --from=builder /app/target/dist/migration /usr/local/bin/migration

EXPOSE 8080
CMD ["sh", "-c", "migration up && rust-federation-tester"]