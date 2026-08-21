# Restricted peer admission

Restricted peer admission is a development candidate for private and
federated-private IICP deployments. It is disabled in public mode and does not
change the existing public mesh behavior.

In a restricted deployment, selecting a private directory is not sufficient.
The runtime verifies a directory-signed membership assertion for every peer
before storing or using that peer. Gossip is signed by the sending member,
bound to the advertised payload and protected by a short-lived replay ID. A
peer learned from an accepted member does not inherit that member's authority:
it must present its own valid assertion.

## Configuration boundary

Private and federated-private configurations name a
`secret_refs.restricted_peer_bundle`. The reference must resolve through the
existing environment or protected-file secret resolver. The portable runtime
configuration contains only the reference, never the membership bearer,
private signing seed or full assertion bundle.

The resolved JSON bundle contains four elements:

- the trusted directory authority and domain policy;
- the local node's signed membership assertion;
- the local Ed25519 signing seed matching that assertion; and
- a directory membership bearer used for authenticated bootstrap.

The runtime rejects an absent, malformed, expired, not-yet-valid, revoked or
wrong-domain assertion before starting network activity. It also rejects a
signing seed that does not match the asserted node key and an empty directory
credential. Do not commit a real bundle, print it in logs or place it directly
in portable configuration.

## Admission and revocation behavior

Bootstrap and gossip use separate assertion scopes. Restricted gossip cannot
fall back to the legacy tokenless or shared-HMAC compatibility path. An
authenticated exchange is accepted only when its sender, domain, membership
assertion, payload digest, timestamp and replay identifier all verify.

The peer manager can advance a domain's minimum accepted membership generation.
When it does, peers from older generations are removed immediately. Expired
assertions are also removed during normal pruning. Connecting this update to a
live directory revocation feed remains separate work; until then, operators
must not claim automatic revocation propagation.

## Current limits

- This is a Rust reference implementation, not yet a cross-SDK guarantee.
- Environment and protected-file secret references are supported for this
  bundle. Other configured secret-provider types are not yet resolved here.
- Federation authorization and CIP worker inheritance require their own
  acceptance evidence.
- No production deployment is implied by the presence of this code.

The canonical semantics and fixtures live in the IICP specification repository.
Public operation remains the compatibility baseline.
