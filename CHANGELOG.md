# Changelog

All notable changes to the IICP Rust SDK (`iicp-client`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
within the scope of the IICP Software axis (see [`VERSIONING.md`](https://github.com/RobLe3/iicp.network/blob/main/project/VERSIONING.md)
in the main repo).

## [0.7.51] — 2026-06-10

### Added — health_models heartbeat reporting (#494)

- **`backend_url` / `backend_api_key`** in `NodeConfig` — when set, each heartbeat probes
  the backend's live model list (`/api/tags` for Ollama, `/v1/models` for OpenAI-compatible
  backends) and sends `health_models=[...]` in the heartbeat payload.
- The directory (≥ v1.10.28) uses `health_models` to filter `?model=` discover queries
  to nodes whose backend actually has that model loaded, eliminating stale-model routing.
- Probe failures are soft — heartbeat still fires without `health_models` (backward compat).
- 2 behavior tests added (`node_tests.rs`).

## [0.7.40] — 2026-06-07

### Fixed — CLI usability hardening (no friction for new operators)

- **`proxy` now listed in `iicp-node --help`** + all serve flags documented.
- **Every subcommand `--help`/`-h` prints usage** instead of panicking.
- **Friendly parse errors** — unknown flags print `error: …` (exit 2).
- **`iicp-node serve --model X` works without `--backend-url`** — `localhost:11434` default applied unconditionally.
- **`--no-auto-detect-nat`** off-switch; `iicp-node help` prints usage; `credits` auto-resolves single node. Cross-flavour CLI parity (3-C).

## [0.7.39] — 2026-06-07

### Added — unified client: local OpenAI/Ollama/Anthropic-compat proxy (ADR-050, #476)

- **`iicp-node proxy`** — a local compat gateway on `127.0.0.1:9483` (axum, `proxy` feature).
  Speaks OpenAI, Ollama, and Anthropic protocols; routes requests across the IICP mesh.
- **`iicp-node serve --with-proxy`** — co-host the proxy next to a provider node.
- **CIP consumer gating** — `IICP-E036` → 402, `IICP-E022` → 503.
- One client binary does **node + query + proxy**; standalone `iicp-proxy` retired.

## [0.7.36–0.7.38] — 2026-06-03..06

- Maintenance + lockstep version alignment across Python/TS/Rust SDKs (3-C). No API changes.

## [0.7.35] — 2026-06-03

### Added — native Anthropic backend + audio chat modality (#414)

- **`BackendType::Anthropic`** — speaks the Anthropic Messages API directly.
- **Audio modality detection** — model names containing `audio`, `voxtral`, or `omni`
  advertise `input_modalities: ["audio"]`.

### Added — heartbeat liveness challenge (ADR-047 Part A, #411)

- The heartbeat loop answers the directory's HMAC liveness challenge.

## [0.7.34] — 2026-06-03

### Added — operator delegation at registration (ADR-045 Phase A, #407)

- Ed25519 operator delegation signed and attached on `register`.

## [0.7.33] — 2026-06-03

### Added — multimodal capability advertising (ADR-046, #408)

- `build_capabilities` advertises `input_modalities` (text + image for vision models).

## [0.7.32] — 2026-06-03

### Added — multi-intent advertising (#409)

- Node advertises every intent its backend serves (chat + embedding).

## [0.7.31] — 2026-06-02

### Fixed — backend_url precedence regression-lock (#410)

## [0.7.30] — 2026-06-02

### Added — Bearer auth for OpenAI-compat backends (#5)

- **`--backend-api-key` / `IICP_BACKEND_API_KEY`**.

## [0.7.29] — 2026-06-02

### Fixed — single-instance lock prevents duplicate-node thrash (#405)

- Per-node lockfile; `--force` / `IICP_FORCE` to take over.

## [0.7.28] — 2026-06-02

### Fixed — node no longer needs restart to reconnect (#404, reliability)

- Registration retries with backoff; heartbeat re-registers on 401.

## [0.7.27] — 2026-06-02

### Fixed — CIP policy now enforced on incoming tasks (#403, security)

- `cip_gate` rejects tool-execution-domain intents unless opted in.

## [0.7.26] — 2026-06-02

### Added — transport on parsed discover nodes (#397)

- `Node.transport: Vec<String>` — protocols each node speaks.

## [0.7.25] — 2026-06-02

### Fixed — node recovers after the directory drops it (#399)

- Heartbeat loop re-registers on node-unknown rejection.

## [0.7.24] — 2026-06-02

### Changed — onboarding clarity

- `iicp-node init` distinguishes optional capabilities from real problems.

## [0.5.x] — 2026-05-27

- 0.5.3: CBOR wire-compat fix (ciborium/integer keys); 3×3 cross-SDK matrix verified.
- 0.5.2: ConcurrencyGate parity port (Tier 2 Item 5).
- 0.5.1: CONF self-conformance probes (Tier 2 Item 4).
- 0.5.0: ADR-019 declarative pricing + HMAC signing (Tier 2 Item 3).

## Earlier 0.x releases

See git log — the Tier 1 ports (transport_endpoint, IICP TCP, UPnP, openai_compat,
NAT observability) and Tier 2 items (CIP policy, pricing, conformance, ConcurrencyGate)
shipped across iter-1409..1440 of the main repo's FORGE loop.
