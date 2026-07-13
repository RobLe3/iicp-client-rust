# Changelog

All notable changes to the IICP Rust SDK (`iicp-client`).

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
within the scope of the IICP Software axis (see [`VERSIONING.md`](https://github.com/RobLe3/iicp.network/blob/main/project/VERSIONING.md)
in the main repo).

## [0.7.88] — 2026-07-13

### Added — MeshLLM provider compatibility
- `iicp-node serve --backend-type meshllm` uses MeshLLM's local OpenAI-compatible gateway at `http://localhost:9337/v1` for stable chat capability.
- Readiness requires both MeshLLM `/readyz` and the selected model in `/v1/models`; the experimental `mesh` ensemble remains explicit opt-in.

### Fixed — relay recovery evidence
- A successfully bound relay worker is treated as a live public route while directory evidence converges; a disconnected worker returns to normal limited-reach recovery.

## [0.7.87] — 2026-07-11

### Added — operator data-rights self-service
- `iicp-node operator dsr export --output FILE` requests a short-lived directory challenge, signs it locally with the existing operator identity, and writes a redacted, owner-only receipt (mode `0600` on Unix).
- `iicp-node operator dsr restrict --yes` and `iicp-node operator dsr anonymize --yes` require explicit confirmation and report the directory retention boundary; they never transmit the operator secret or node tokens.
- Docker release coverage now verifies the signed, redacted DSR flow against a fake directory for Python, TypeScript, and Rust alongside existing registration and recovery checks.

## [0.7.86] — 2026-07-10

### Added — operator-signed node policy publishing
- `iicp-node serve --policy-manifest FILE` signs a local public policy document with the existing operator identity and advertises it on every registration and recovery re-registration.
- Canonical JSON and Ed25519 output share a fixed known-answer vector with the Python, TypeScript, and directory verifier tests.
- Relay operator guidance now documents the available strict directory-signed bind-ticket cutover instead of describing bind authentication as pending.

## [0.7.85] — 2026-07-10

### Security — one-use relay bind tickets
- Directory-signed relay bind tickets now require a signed 128-bit `jti`; relay accept paths atomically consume it and reject replay after disconnect until ticket expiry.
- Replay protection covers native RELAY_BIND and browser-compatible HTTP-poll binds without changing the opt-in strict-bind cutover.

## [0.7.84] — 2026-07-10

### Added — MCP safety controls and operator self-service signing
- The packaged MCP gateway now denies all named non-benign risk classes unless explicit operator opt-in, caller authorization policy, an accepted sandbox profile, and redacted audit are configured together.
- Gateway registration now uses the current directory `capabilities`/`limits` contract and advertises only tools that passed the local risk gate.
- Added a canonical operator-key signing helper for challenge-based acceptance and DSR self-service requests.
- Added a packaged canonical MCP risk taxonomy and redacted policy receipts that exclude tool arguments.

## [0.7.83] — 2026-07-09

### Added — policy-manifest identity routing
- Added `required_manifest_identity_level` to routing policies so strict callers can require `signed_valid`, `operator_bound`, or `known_operator` node policy manifests before any prompt is dispatched.
- Rejected or rotated/revoked manifests fail closed with redacted routing-policy reasons and no task POST to the rejected node.
- Expanded the packaged `mcp-gateway` dangerous-tool denylist for public-unknown callers and redacted upstream MCP error details to avoid echoing tool-input or secret text.
- Prefer short-lived ticketed route discovery with bounded failed-node exclusion and controlled legacy fallback.
- Refuse prohibited and high-risk declared intents locally and mark model responses through additive metadata/headers.

## [0.7.82] — 2026-07-09

### Fixed — saved credential recovery
- Successful provider re-registration now persists refreshed `node_token` and `node_hmac_key` back to the saved node identity, so read-only commands such as `iicp-node credits` do not drift behind a healthy running node.
- `iicp-node doctor` now reports stale saved credentials separately from serving health and explains `backend_cold` as normal idle/warmup rather than an automatic restart condition.

## [0.7.81] — 2026-07-02

### Changed — cross-SDK release parity
- Parity release aligned with Python 0.7.81 so operators and adopters can keep all official clients on the same published version baseline.
- No Rust runtime behaviour changed beyond the 0.7.80 remote-routing policy profile baseline.

## [0.7.80] — 2026-07-02

### Added — remote-routing policy profiles
- Added client-side routing policies that filter discovered nodes before any prompt is dispatched: `standard`, `sensitive`, `eu_restricted`, `strict_policy`, and `debug_override`.
- `iicp-node query` now exposes `--routing-profile`, `--region-allowlist`, and `--allow-remote-executor`, and prints a plain privacy reminder that remote executors can read prompts they run.

## [0.7.79] — 2026-07-02

### Fixed — direct IPv6 route promotion recovery
- Provider heartbeat recovery now treats `http_ipv6` + self-attested + browser-unusable registry evidence as limited reach, so supervised nodes restart and retry Quick Tunnel or relay fallback instead of staying indefinitely in “Direct IPv6 — unverified”.
- Rust relay workers now re-register their path-scoped relay endpoint after a successful bind, allowing relay fallback to replace the old self-attested direct route.

## [0.7.78] — 2026-07-01

### Fixed — relay-capable public fallback guard
- Relay-capable nodes no longer fall back through another relay when their own public tunnel is cooling down or unavailable. They preserve relay capacity and, under supervision, fail visibly so launchd/systemd/Docker can retry the public route.
- Automatic relay election now excludes the node's own `node_id`, avoiding self-election loops during transient Quick Tunnel rate-limit recovery.
- Ordinary provider nodes can still use relay fallback as the last-resort path; this guard only applies to nodes explicitly advertising relay service.

## [0.7.77] — 2026-07-01

### Added — supervised recovery and Docker release validation
- Added `iicp-node doctor` so operators can check local health, directory presence, and the deterministic recovery action without reading raw logs.
- Provider heartbeat loops now classify recovery state, re-register when directory evidence disappears, and only exit for supervisor restart after configured grace checks.
- Docker images default to `IICP_PORT=8020`, matching the exposed port and healthcheck used by low-friction container runs.
- Release validation now includes the cross-SDK Docker gate for CLI help, no-network update checks, fake-directory registration, `/iicp/health`, `/v1/task`, and heartbeat 401 recovery.

## [0.7.76] — 2026-06-30

### Changed — operator-wallet credit display
- `iicp-node credits` now shows the operator wallet summary before per-node ledgers when the directory provides `operator_wallet`, making earned and spendable credits easier to understand across multiple nodes.
- JSON output preserves per-node ledgers while exposing the pooled wallet fields for tooling and future give-and-get accounting.

## [0.7.75] — 2026-06-28

### Fixed — host-wide Quick Tunnel pacing
- Accountless Cloudflare Quick Tunnel creation now uses host-wide create spacing, a short create lease, and persistent provider-rate-limit cooldown so Dockerized or launchd-managed nodes do not retry-storm while Cloudflare limits recover.
- When tunnel creation is paced, cooling down, or held by another local node, providers fall back to the next safe reachability path instead of advertising an unverified public route.

## [0.7.74] — 2026-06-28

### Fixed — supervised Quick Tunnel recovery
- Persisted accountless Cloudflare Quick Tunnel cooldown state so supervised restarts do not immediately re-trigger a `429` / `1015` storm.
- Managed tunnel retry now honors Cloudflare `paused for Ns` hints instead of falling back to the shorter generic retry delay.
- Supervised provider services now exit instead of advertising an unverified direct route when a required public tunnel or relay fallback cannot be established.
- Public fallback exits sleep through parsed Cloudflare cooldown hints first, reducing launchd/systemd/Docker restart churn.

## [0.7.73] — 2026-06-27

### Fixed — Quick Tunnel rate-limit backoff
- Accountless Cloudflare Quick Tunnel startup now opens a process-local cooldown when `cloudflared` reports rate limiting (`429` / `1015`) so retries do not hammer Cloudflare; operators should use a named tunnel or `IICP_PUBLIC_ENDPOINT` for persistent relay infrastructure.

## [0.7.72] — 2026-06-26

### Fixed — Quick Tunnel DNS-lag stability
- Quick Tunnel verification now avoids destructive tunnel rotation when local
  DNS has not resolved a freshly-created `trycloudflare.com` hostname yet but
  Cloudflare DoH already publishes the A/AAAA record.
- This prevents local macOS resolver lag from causing provider nodes to churn
  public endpoints and disappear from the directory even though local
  `/iicp/health` is healthy.

## [0.7.71] — 2026-06-26

### Fixed — supervised Quick Tunnel dead-state recovery
- Added `IICP_TUNNEL_DEAD_POLICY=auto|retry|exit|log-only` so operators can choose whether confirmed Quick Tunnel Dead state retries, exits, or only logs.
- Generated launchd/systemd units and Docker images now set `IICP_SUPERVISED=1`; default `auto` exits non-zero under a supervisor so launchd/systemd/Docker can restart instead of leaving a publicly unreachable process alive.
- Foreground/manual runs keep retrying with backoff by default, preserving a low-friction local development experience.
- Dockerfiles default to `IICP_SUPERVISED=1` and the `auto` dead policy, matching generated launchd/systemd service units.
- README and contributing docs now describe Docker restart-policy expectations, current issue trackers, and the one-time manual-upgrade caveat for nodes older than 0.7.67.

## [0.7.70] — 2026-06-25

### Added — elastic Quick Tunnel recovery
- Quick Tunnel providers now mark themselves unavailable while the public tunnel URL is in twilight/recovery and only re-register a rotated URL after public `/iicp/health` verifies.
- Added a tunnel state callback (`ready`, `twilight`, `recovering`, `dead`) so service heartbeats reflect real public reachability instead of local process liveness.

## [0.7.68] — 2026-06-25

### Fixed — fail-closed IICP-CX routing
- Consumers now skip keyless discovered nodes by default and refuse plaintext when no keyed node remains.
- Transitional plaintext requires explicit `IICP_CX_ALLOW_PLAINTEXT=1` for debugging only.
- Updater environment-variable unit tests now serialize env mutation to avoid false release-gate failures.

## [0.7.67] — 2026-06-25

### Changed — updater observability
- Auto-update checks default to hourly and provider heartbeats report update
  evidence so directories can identify downlevel nodes that are stuck.

## [0.7.66] — 2026-06-21

### Fixed — discover CX key duplicate-field tolerance
- Rust discovery now tolerates transitional directory responses that contain both canonical `cx_public_key` and deprecated `public_key`, preferring `cx_public_key` instead of failing with `duplicate field cx_public_key`.
- Kept the deprecated alias path for older directory responses and retained the new browser/routing signal parsing.

## [0.7.65] — 2026-06-21

### Fixed — discover CX key alias
- Consumers prefer canonical `cx_public_key` and treat a directory `public_key` field as a deprecated alias, so keyed live nodes are encrypted instead of receiving the
  transitional plaintext fallback warning.
- Added regression coverage for the alias path.

## [0.7.64] — 2026-06-20

### Changed — provider-side IICP-CX
- Provider nodes now persist an X25519 CX key locally and advertise the public half as
  `cx_public_key` during registration.
- `POST /v1/task` decrypts incoming `iicp_conf` envelopes before invoking the task handler,
  closing the missing provider-side half of mandatory payload confidentiality.
- Added regression coverage for CX key advertisement and encrypted task handling.

## [0.7.63] — 2026-06-20

### Changed
- Tier-3+ reachability now tries the node's own Quick Tunnel before electing a third-party relay; `--no-tunnel` retains relay-first behavior.
- The background updater performs its first check within five minutes of startup, then returns to the configured cadence.

### Fixed
- `--tunnel` help now describes the actual tunnel-first reachability order.
- Reachability order is produced by the same pure planner covered by unit tests.
- Added a targeted test for the updater's initial-delay rule.

## [0.7.62] — 2026-06-13

### Changed — privacy-first (mandatory E2E, no opt-out)
- IICP-CX payload encryption is now **on by default with no opt-out**: the client always encrypts to
  a node advertising a `cx_public_key` (`use_confidentiality` is a deprecated no-op). Directory,
  relays, and network see only ciphertext; a node without a key yet gets a transitional plaintext
  warning. The executing node still decrypts to run the model (run locally for full privacy).
- Added Tier-2 response-encryption primitives (`encrypt_response`/`decrypt_response`) — not yet wired.

## [0.7.61] — 2026-06-13

### Fixed — self-healing tunnel (resilience, #538)
- The `--tunnel` watchdog now actively health-checks the tunnel's OWN public URL (GET
  `/iicp/health` through the Cloudflare edge) every 30s, not just watch for the cloudflared
  process to exit. A Quick Tunnel can keep its process alive while its edge connection drops,
  leaving a dead public endpoint the directory still serves (the recurring "can't talk to the
  mesh"). After 3 consecutive unreachable probes the watchdog restarts cloudflared → new URL →
  re-register. The respawn cap now resets when a fresh tunnel passes a health check, so a
  long-running relay self-heals indefinitely (the cap only catches a truly broken cloudflared).

## [0.7.60] — 2026-06-13

### Added — background self-updater (#521 P2)
- A node running `serve` keeps itself current automatically: it periodically checks crates.io
  and, on a newer release, `cargo install --force`s and re-execs onto the new version — no
  operator intervention in covered service paths. Early Docker/normal-serve coverage was hardened
  in 0.7.67, so older nodes may need one manual upgrade/restart first. Default-on; opt
  out with `IICP_AUTO_UPDATE=0` (`IICP_AUTO_UPDATE_INTERVAL_S` sets cadence, default 1h,
  min 5m). Loop-safe and failure-isolated. NB: the Rust upgrade recompiles from
  source, so it can take a few minutes; the node keeps serving until the re-exec.

### Added
- Live re-register on Quick-Tunnel URL rotation (#527) — when a `--tunnel` node's public URL
  rotates, the node now updates its endpoint and re-registers automatically (proving ownership
  with `current_node_token`, IICP-E050) instead of logging restart-advice. Parity with the
  Python/TypeScript clients, which already self-heal on rotation.

### Security
- Expand the `mcp-gateway` dangerous-tool denylist backstop (red-team pass 3, Rust parity).

## [0.7.59] — 2026-06-12

### Security

- **Per-Origin `/v1/task` rate limit (F4, #524)** — caps browser-origin task
  dispatch (the CORS confused-deputy vector); non-browser callers (the
  operator's own authed traffic) are never throttled. 429 IICP-E023; default
  120/60s, `IICP_TASK_RATE_LIMIT` overrides (0 disables).

### Added — re-registration ownership proof (#529)

- The node now sends `current_node_token` on re-registration when it holds a
  cached token, so an endpoint change after a tunnel/CGNAT rotation is accepted
  via the directory's IICP-E050 ownership path. Additive + backwards-compatible
  (directory accepts-but-does-not-require it).

## [0.7.58] — 2026-06-12

### Security — relay session cap (red-team F5)

- The relay caps concurrent worker sessions (default 256); new binds past the
  cap are rejected (HTTP 503 `IICP-E039` / TCP `RELAY_ACK` error), closing a
  bind-flood memory-exhaustion DoS. A rebind of an existing worker_id is exempt.

### Added — `iicp-node update --check`

- Read-only check for a newer published release (numeric version compare) with
  the exact upgrade command. Exit 10 when a newer release exists, 0 otherwise.

## [0.7.57] — 2026-06-12

### Added — automatic Quick-Tunnel escalation (NAT ladder rung 5, #520)

- When every NAT path fails (no direct endpoint, no UPnP pinhole, no IPv6
  GUA, no relay-capable peer in the directory), the node now exposes itself
  via a zero-account Cloudflare Quick Tunnel automatically: detect
  `cloudflared` on PATH (never auto-installed — one actionable install hint
  when missing), spawn it, register the issued `https://*.trycloudflare.com`
  URL as the endpoint (`transport_method=external_tunnel`), supervise the
  child (bounded respawn ×3), and tear it down with the node on every exit
  path.
- `--tunnel` forces the rung regardless of NAT tier (e.g. to get an https
  endpoint for browser consumers without touching the router);
  `--no-tunnel` / `IICP_TUNNEL=0` disables the automatic escalation.

## [0.7.56] — 2026-06-12

(Also includes the never-published 0.7.55 changes: MCP gateway as a built-in
`iicp-node mcp-gateway` feature.)

### Added — HTTP long-poll relay worker transport (#450)

- Relay-capable nodes accept browser-compatible workers over plain HTTP:
  `POST /v1/relay/bind` (bearer session token; 409 on alive-rebind, #510
  interim-C), `GET /v1/relay/pull` (long-poll ≤25 s), `POST /v1/relay/result`,
  `POST /v1/relay/unbind` — same session registry as TCP RELAY_BIND workers.
- Path-scoped worker endpoints `{relay}/v1/relay-for/<worker_id>/v1/task` +
  `/iicp/health`: published consumers route through the relay with no client
  changes. RELAY_ACK gains additive field 4 (the relay's HTTP task port).

### Fixed — relay-bound workers were silently misattributed

- Relay workers previously advertised the bare relay endpoint, so consumer
  dispatches executed **on the relay itself** instead of forwarding (and used
  the non-HTTP accept port). Workers now register the path-scoped endpoint.

### Changed — CORS on every node HTTP endpoint

- All node responses carry `Access-Control-Allow-Origin: *` and every path
  answers `OPTIONS` preflights. Web pages (e.g. iicp.network/browser-node)
  are first-class consumers: an https-exposed node now serves browser
  dispatches directly. No new capability — CORS only ever gated browsers;
  curl was never restricted.

## [0.7.54] — 2026-06-11

### Fixed — `iicp-node credits` resilience

- Transient failures (network error, 5xx, undecodable body) are retried once after
  a 2s pause — deploy windows / shared-hosting blips no longer surface as one-shot
  CLI errors (`HTTP 500` / `bad response: error decoding response body`).
- All-nodes listing (bare `iicp-node credits` with multiple saved nodes): one
  node's failure no longer aborts the whole listing — every node is shown and the
  command exits non-zero with an `N/M node(s) failed` summary.
- All-nodes listing now honors each node's saved `directory_url` instead of the
  global default (parity with Python/TypeScript).

## [0.7.53] — 2026-06-11

### Added — model-drift re-registration (#494)

- Each heartbeat tick compares the backend's live model list against the registered
  set and automatically re-registers when they diverge — directory registration no
  longer goes stale when Ollama loads/unloads models.
- Background heartbeat loop (inside `serve()`) now sends `health_models` — it was
  missing from the inlined heartbeat payload even in 0.7.52.

## [0.7.52] — 2026-06-10

### Added

- #496 Phase-2 consumer token support.
- `models[]` array on the `/iicp/health` endpoint (#494).
- #503 loud CLI notice when serving without an operator identity.

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
