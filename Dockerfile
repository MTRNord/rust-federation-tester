# Stage 1: Chef - Create a dependency-only layer for caching
FROM --platform=$BUILDPLATFORM rustlang/rust:nightly AS chef
RUN cargo install cargo-chef
WORKDIR /app

# Stage 2: Plan - Analyze dependencies
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Build - Build with cached dependencies
FROM chef AS builder
ARG TARGETPLATFORM

# Install cross-compiler if needed for ARM
RUN if [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
      apt-get update && apt-get install -y gcc-aarch64-linux-gnu && rm -rf /var/lib/apt/lists/*; \
    fi

# Add Rust targets for cross-compiling
RUN rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu

# Copy recipe and build dependencies only (this layer gets cached!)
COPY --from=planner /app/recipe.json recipe.json

# Build dependencies based on target platform
RUN case "$TARGETPLATFORM" in \
      "linux/amd64") TARGET_TRIPLE=x86_64-unknown-linux-gnu; \
        cargo chef cook --release --target $TARGET_TRIPLE --recipe-path recipe.json ;; \
      "linux/arm64") TARGET_TRIPLE=aarch64-unknown-linux-gnu; \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
        CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
        cargo chef cook --release --target $TARGET_TRIPLE --recipe-path recipe.json ;; \
      *) echo "Unsupported platform: $TARGETPLATFORM"; exit 1 ;; \
    esac

# Copy source and build the actual project (dependencies already cached)
COPY . .

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
RUN case "$TARGETPLATFORM" in \
      "linux/amd64") TARGET_TRIPLE=x86_64-unknown-linux-gnu ;; \
      "linux/arm64") TARGET_TRIPLE=aarch64-unknown-linux-gnu ;; \
      *) echo "Unsupported platform: $TARGETPLATFORM"; exit 1 ;; \
    esac && \
    cp /app/target/$TARGET_TRIPLE/release/rust-federation-tester /app/target/dist/rust-federation-tester && \
    cp /app/target/$TARGET_TRIPLE/release/migration /app/target/dist/migration

# Stage 4: Runtime - Minimal final image
FROM debian:trixie-slim
ARG TARGETPLATFORM

# Create a non-root user for the application
RUN groupadd -r appuser && useradd -r -g appuser -u 1001 appuser

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Create application directory with proper ownership
WORKDIR /app
RUN chown appuser:appuser /app

COPY --from=builder --chown=appuser:appuser /app/target/dist/rust-federation-tester /usr/local/bin/rust-federation-tester
COPY --from=builder --chown=appuser:appuser /app/target/dist/migration /usr/local/bin/migration

# Switch to non-root user
USER appuser

EXPOSE 8080

# Add security labels for container runtime
LABEL security.capabilities.drop="ALL"
LABEL security.no-new-privileges="true"
LABEL security.read-only-rootfs="true"

CMD ["sh", "-c", "migration up && rust-federation-tester"]
