# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS builder
WORKDIR /build

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
# Touch main.rs so cargo doesn't reuse the dummy build's stale object file.
RUN touch src/main.rs && cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN groupadd --system counterparser && useradd --system --gid counterparser counterparser \
    && mkdir -p /run/counterparser && chown counterparser:counterparser /run/counterparser

COPY --from=builder /build/target/release/counterparser /usr/local/bin/counterparser
COPY config.example.toml /etc/counterparser/config.example.toml

# Pre-create the config.toml mount point as an empty *file* in the image. Without this, bind-
# mounting a host file onto a target path that doesn't exist in the image at all can make
# Docker auto-create the mountpoint as a directory instead, causing a file-vs-directory bind
# mount error at container start. The bind mount fully replaces this placeholder's contents.
RUN touch /etc/counterparser/config.toml && chown counterparser:counterparser /etc/counterparser/config.toml

USER counterparser
ENV COUNTERPARSER_CONFIG=/etc/counterparser/config.toml
ENV RUST_LOG=info

# The socket directory (/run/counterparser) is meant to be bind-mounted from the host so
# nginx, running outside this container, can reach it. umask 000 makes the socket file
# world-rw (0777) so nginx's user, which is unrelated to this container's UID, can connect
# to it regardless — the socket path itself isn't network-exposed, so this is local-IPC-only
# exposure, not a network-facing widening. See DEPLOY.md.
ENTRYPOINT ["/bin/sh", "-c", "umask 000 && exec /usr/local/bin/counterparser"]
