# Windows dispatch trust-store boundary

The opt-in dispatch-ticket v2 file store requires an absolute Windows path.
The store creates its private directory with a protected DACL for the current
Windows identity and LocalSystem. Lock and state files receive an explicit owner and restricted DACL during
exclusive creation. Existing directories are verified, not silently repaired.

Creation and load checks reject reparse-point paths, unexpected owners, broad
access rules, deny rules, missing owner access, and unavailable verification tools.
The Windows adapter uses the same ACL rules as the maintained TypeScript store.
It invokes the system Windows PowerShell executable with an encoded path and a
fixed operation, no interactive profile, and a ten-second timeout. Verification
failure refuses the store operation. This is a local platform adapter, not a
second trust-policy engine. It does not prevent administrators from exercising
Windows ownership/recovery privileges.

The state file is flushed before atomic replacement. Unix additionally flushes
the parent directory. Windows does not attempt Unix directory-handle flushing;
this implementation does not claim an equivalent parent-directory crash-durability
barrier. Ordinary install/recovery tests are not power-loss tests.

ACL verification starts bounded local processes and has measurable overhead.
It is not part of candidate ranking, but callers should account for it when
choosing an explicit store-lock timeout. No performance or qualification claim
is made until Windows positive and negative tests pass on the frozen artifact.
