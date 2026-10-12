FROM lukemathwalker/cargo-chef:0.1.78-rust-1.97.1-slim-trixie AS planner
WORKDIR /plan

COPY ./src ./src
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo chef prepare --recipe-path recipe.json

FROM lukemathwalker/cargo-chef:0.1.78-rust-1.97.1-trixie AS builder

WORKDIR /build

COPY --from=planner /plan/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json -p oiplease

COPY ./src ./src
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo build --release -p oiplease && mv /build/target/release/oiplease /build/target/oiplease

FROM debian:trixie-slim
WORKDIR /runtime

COPY --from=builder /build/target/oiplease /runtime/oiplease

RUN apt-get update && apt-get install libssl3t64 ca-certificates -y && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/runtime/oiplease"]