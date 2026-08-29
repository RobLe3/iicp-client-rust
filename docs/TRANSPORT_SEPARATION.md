# Transport-separation boundary

The coordinated stable client path is HTTP. Native TCP remains an explicitly
enabled plaintext development profile, and QUIC remains post-1.0 research.
Those support decisions do not make IICP task semantics depend on TCP.

The transport-neutral boundary is enforced as follows:

- `TaskRequest`, routing policy, eligibility, ranking and provider selection do
  not expose TCP connection state.
- `task_id`, `call_id` and idempotency bindings are validated independently of a
  socket by `native_call_identity`.
- cancellation and terminal task states are owned by `service_lifecycle`;
  ordered partial and terminal native responses are validated by
  `native_response_sequence`.
- framing reads an announced byte length and does not treat a TCP packet as a
  frame boundary. The TCP module is an experimental binding around that frame
  contract.
- admission is bounded by the reusable `ConcurrencyGate`; it is not a
  one-request-per-process assumption.
- the public library compiles with `--no-default-features --lib`. The operator
  CLI is qualified with its declared feature set and is not promised as a
  featureless binary.

Introducing QUIC later may add a transport implementation and stream mapping.
It must not change the application intent, policy, task identity, cancellation,
terminal-response or provider-selection contracts.
