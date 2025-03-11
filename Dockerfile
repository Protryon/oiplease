FROM lukemathwalker/cargo-chef:0.1.68-rust-1.83-slim-bullseye AS planner
WORKDIR /plan

COPY ./src ./src
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo chef prepare --recipe-path recipe.json

FROM lukemathwalker/cargo-chef:0.1.68-rust-1.83-bullseye AS builder

WORKDIR /build

COPY --from=planner /plan/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json -p oiplease

COPY ./src ./src
COPY ./Cargo.lock .
COPY ./Cargo.toml .

RUN cargo build --release -p oiplease && mv /build/target/release/oiplease /build/target/oiplease

FROM debian:bullseye-slim
WORKDIR /runtime

COPY --from=builder /build/target/oiplease /runtime/oiplease

RUN apt-get update && apt-get install libssl1.1 ca-certificates -y && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/runtime/oiplease"]