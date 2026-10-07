# Robustness evidence

The protocol specification and production-readiness document describe the current design. Tests establish specific checked behaviors, not universal anonymity, memory safety of dependencies, immunity to crashes, or classifier resistance.

Verified properties require evidence for the exact commit: pinned TLS links; transcript-bound circuit authentication; canonical snapshot quorum; persisted rollback rejection; bounded flow credit; large responses after upload EOF; DNS/address policy; and namespace isolation before and after proxy failure.

Rust source forbids unsafe code, but cryptographic and networking dependencies have their own implementations. Atomic writes reduce partial-state risk; filesystem behavior, ACLs, backups and operator recovery still matter. Fuzzing searches for failures and does not mathematically prove their absence.

The local status command reports key-file presence; it does not establish daemon health. Logs and metrics must be reviewed for privacy before public operation.
