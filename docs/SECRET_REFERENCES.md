# Secret references

Runtime configuration stores a `SecretRef`, not the secret value. Resolution is
explicit and returns a zeroized value whose `Debug` and `Display` output is
redacted. A missing or unsafe reference is an error; the runtime does not fall
back to a plaintext field.

## Current provider behavior

| Source | Read | Store, rotate and delete |
| --- | --- | --- |
| Environment variable | Yes | No; the parent environment remains externally managed |
| Owner-only file | Unix | Unix, using a same-directory atomic replacement |
| macOS Keychain | Yes on macOS | macOS, using the native Security framework |
| Windows Credential Manager | Yes on Windows | Windows, using the native Credential Manager API |
| Linux Secret Service | Yes on Linux | Linux, using `secret-tool` with secret input on stdin |
| External provider | Provider-defined | Provider-defined through the mutation interface |

The file source rejects symbolic links, non-files, files owned by another user
and files readable by a group or other users. A write creates an owner-only
temporary file beside the destination, synchronizes it, replaces the destination
and synchronizes the parent directory. Rotation therefore does not expose a
partially written destination. Deletion also refuses unsafe paths.

## Migrating a saved node

Add mutable `node_token` and `node_hmac_key` entries to the canonical runtime
configuration's `secret_refs`, then run:

```text
iicp-node config migrate-node-secrets --node NAME --file runtime-config.json
```

The command snapshots any previous provider values, writes both legacy values,
verifies retrieval, and only then atomically replaces the saved identity with
references. A provider or identity-commit failure restores the previous provider
values and leaves the legacy identity unchanged. Environment-variable references
cannot be migration destinations because the process cannot safely mutate its
parent environment.

After migration, start the node with the same canonical configuration. Refreshed
registration credentials rotate through the stored references and are not added
back to the saved identity as plaintext. Keep the original protected identity
backup until the first supervised restart and registration cycle has passed.
