FROM rust:latest

WORKDIR /app
COPY . .

RUN cargo install cargo-audit
RUN make verify
