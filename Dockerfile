FROM rust:latest

WORKDIR /app
COPY . .

# Install cargo-audit as required by make verify
RUN cargo install cargo-audit

# Verify command to run when container starts (if they just run `docker run`)
CMD ["make", "verify"]
