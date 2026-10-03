FROM rust:1.81-bookworm as builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin anonguard-daemon

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/anonguard-daemon /usr/local/bin/
CMD ["anonguard-daemon"]
