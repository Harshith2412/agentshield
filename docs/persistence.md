# Persistence

`SQLiteProvenanceStore` is an experimental local store for runs, ordered events, checkpoints, lineage, and normalized traces. Content is redacted by default. Explicit content storage should be limited to non-sensitive controlled data.

Every event participates in a canonical-JSON SHA-256 chain. Optional HMAC-SHA-256 uses a caller-held key. Verification detects changed, removed, reordered, or reparented events. Hashes do not provide confidentiality; unkeyed hashes do not protect against an attacker who can rewrite both records and the trusted head.

Checkpoint generations are monotonic. Loading a stale checkpoint rejects by default; read-only and explicitly approved rollback policies are available. Authority ledgers persist consumed one-shot grants and checkpoint-bound lifetimes.
