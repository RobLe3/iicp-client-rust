# IICP Rust node — runs an iicp-client provider node out of the box.
#
#   docker build -t iicp-node-rust .
#   docker run --restart on-failure -p 8020:8020 \
#     -e IICP_BACKEND_URL=http://host.docker.internal:11434 \
#     -e IICP_BACKEND_MODEL=qwen2.5:0.5b \
#     -e IICP_PUBLIC_ENDPOINT=http://<your-public-ip>:8020 \
#     iicp-node-rust
#
# Required env vars:
#   IICP_BACKEND_URL    — OpenAI-compatible backend (Ollama / vLLM / LM Studio)
#   IICP_BACKEND_MODEL  — model name (e.g. qwen2.5:0.5b)
#
# Optional:
#   IICP_PUBLIC_ENDPOINT — externally reachable URL of this node. If omitted,
#                          the node tries automatic reachability (Quick Tunnel
#                          first, relay last-resort) before staying local.
#   IICP_TUNNEL_DEAD_POLICY — auto|retry|exit|log-only; default auto exits when
#                          supervised so Docker can restart, manual runs retry.
#   IICP_SUPERVISED   — default 1 in this image; keep with --restart on-failure.
#
# See https://iicp.network/docs/sdk-quickstart-docker for the full setup guide.

FROM rust:1.86-slim AS build
WORKDIR /app
# Cache deps separately from source so subsequent rebuilds are quick.
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY examples ./examples
# Build the iicp-node binary release-optimised. Default features include NAT
# detection and native IICP TCP; library consumers can still opt out with
# --no-default-features outside this Docker image.
RUN cargo build --release --bin iicp-node

# Keep the Rust toolchain in the runtime image so the default-on provider
# self-updater can run `cargo install iicp-client --force` inside Docker and
# re-exec onto the newer binary. This is intentionally larger than a scratchy
# binary-only image; operators who prefer immutable containers can disable the
# updater with IICP_AUTO_UPDATE=0 and rebuild from source instead.
FROM rust:1.86-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
  && arch="$(dpkg --print-architecture)" \
  && case "$arch" in \
      amd64) cf_arch=amd64 ;; \
      arm64) cf_arch=arm64 ;; \
      *) echo "unsupported architecture for cloudflared: $arch" >&2; exit 1 ;; \
    esac \
  && curl -fsSL "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${cf_arch}" -o /usr/local/bin/cloudflared \
  && chmod +x /usr/local/bin/cloudflared \
  && cloudflared --version >/dev/null \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/iicp-node /usr/local/bin/iicp-node
ENV IICP_SUPERVISED=1 \
    IICP_TUNNEL_DEAD_POLICY=auto \
    IICP_PORT=8020
EXPOSE 8020
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
  CMD curl -fsS http://localhost:8020/iicp/health || exit 1
ENTRYPOINT ["iicp-node"]
CMD ["serve"]
