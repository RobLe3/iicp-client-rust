# IICP Rust node — runs an iicp-client provider node out of the box.
#
#   docker build -t iicp-node-rust .
#   docker run -p 8020:8020 \
#     -e IICP_BACKEND_URL=http://host.docker.internal:11434 \
#     -e IICP_BACKEND_MODEL=qwen2.5:0.5b \
#     -e IICP_PUBLIC_ENDPOINT=http://<your-public-ip>:8020 \
#     iicp-node-rust
#
# Required env vars:
#   IICP_BACKEND_URL    — OpenAI-compatible backend (Ollama / vLLM / LM Studio)
#   IICP_BACKEND_MODEL  — model name (e.g. qwen2.5:0.5b)
#   IICP_PUBLIC_ENDPOINT — externally reachable URL of this node
#
# See https://iicp.network/docs/sdk-quickstart-docker for the full setup guide.

FROM rust:1.83-slim AS build
WORKDIR /app
# Cache deps separately from source so subsequent rebuilds are quick.
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY examples ./examples
# Build the iicp-node binary release-optimised. Includes default features
# (no IICP TCP / NAT — HTTP /v1/task is enough for an MVP node; operators
# who want native TCP can rebuild with --features iicp-tcp,nat).
RUN cargo build --release --bin iicp-node

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/iicp-node /usr/local/bin/iicp-node
EXPOSE 8020
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
  CMD curl -fsS http://localhost:8020/iicp/health || exit 1
ENTRYPOINT ["iicp-node"]
CMD ["serve"]
