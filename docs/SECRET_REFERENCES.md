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
| macOS Keychain | Yes on macOS | Not yet implemented |
| Windows Credential Manager | Yes on Windows | Not yet implemented |
| Linux Secret Service | Yes on Linux | Not yet implemented |
| External provider | Provider-defined | Provider-defined through the mutation interface |

The file source rejects symbolic links, non-files, files owned by another user
and files readable by a group or other users. A write creates an owner-only
temporary file beside the destination, synchronizes it, replaces the destination
and synchronizes the parent directory. Rotation therefore does not expose a
partially written destination. Deletion also refuses unsafe paths.

Portable legacy migration is not complete. Existing node identity files remain
readable for migration, but operators should not delete them until a migration
command has stored each secret, verified retrieval and atomically replaced the
legacy value with its reference. Rust issue #106 tracks that remaining work and
the native mutation paths for the three operating-system stores.
