FROM rust:1.75 as base
RUN cargo install cargo-chef --version ^0.1
 
FROM base AS planner
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json
 
FROM base as builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build

ENV WS_URL="ws://127.0.0.1:9944"
CMD ["/bin/murmur"]