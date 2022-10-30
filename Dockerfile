FROM rust:1.64.0 AS builder
WORKDIR /usr/src

RUN rustup target add x86_64-unknown-linux-musl

RUN USER=root cargo new comproxity
WORKDIR /usr/src/comproxity
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

COPY src ./src

RUN cargo install --target x86_64-unknown-linux-musl --path .

FROM scratch
COPY --from=builder /usr/local/cargo/bin/comproxity .
ENTRYPOINT ["/comproxity"]
