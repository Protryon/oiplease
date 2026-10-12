# The planner and builder run on the build host's native platform and cross-compile for
# TARGETARCH, so multi-arch builds don't run rustc under emulation.
FROM --platform=$BUILDPLATFORM lukemathwalker/cargo-chef:0.1.78-rust-1.97.1-slim-trixie AS planner
WORKDIR /plan

COPY ./src ./src
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo chef prepare --recipe-path recipe.json

FROM --platform=$BUILDPLATFORM lukemathwalker/cargo-chef:0.1.78-rust-1.97.1-trixie AS builder
ARG BUILDARCH
ARG TARGETARCH

# Writes /cross.env with the rust target and, when cross-compiling, the cross toolchain
# settings; installs the target arch's libssl-dev via Debian multiarch for openssl-sys.
RUN set -eux; \
    case "$TARGETARCH" in \
        amd64) rust_target=x86_64-unknown-linux-gnu; gnu_triple=x86_64-linux-gnu ;; \
        arm64) rust_target=aarch64-unknown-linux-gnu; gnu_triple=aarch64-linux-gnu ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH"; exit 1 ;; \
    esac; \
    echo "export RUST_TARGET=$rust_target" > /cross.env; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
        dpkg --add-architecture "$TARGETARCH"; \
        apt-get update; \
        apt-get install -y --no-install-recommends \
            "gcc-$(echo $gnu_triple | tr _ -)" "libc6-dev-$TARGETARCH-cross" "libssl-dev:$TARGETARCH"; \
        target_env=$(echo $rust_target | tr a-z- A-Z_); \
        { \
            echo "export CARGO_TARGET_${target_env}_LINKER=$gnu_triple-gcc"; \
            echo "export CC_$(echo $rust_target | tr - _)=$gnu_triple-gcc"; \
            echo "export PKG_CONFIG_ALLOW_CROSS=1"; \
            echo "export PKG_CONFIG_LIBDIR=/usr/lib/$gnu_triple/pkgconfig:/usr/share/pkgconfig"; \
        } >> /cross.env; \
        rm -rf /var/lib/apt/lists/*; \
    fi; \
    . /cross.env; \
    rustup target add "$RUST_TARGET"

WORKDIR /build

COPY --from=planner /plan/recipe.json recipe.json

RUN . /cross.env && cargo chef cook --release --target "$RUST_TARGET" --recipe-path recipe.json -p oiplease

COPY ./src ./src
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN . /cross.env && cargo build --release --target "$RUST_TARGET" -p oiplease && mv "/build/target/$RUST_TARGET/release/oiplease" /build/target/oiplease

FROM debian:trixie-slim
WORKDIR /runtime

COPY --from=builder /build/target/oiplease /runtime/oiplease

RUN apt-get update && apt-get install libssl3t64 ca-certificates -y && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/runtime/oiplease"]
