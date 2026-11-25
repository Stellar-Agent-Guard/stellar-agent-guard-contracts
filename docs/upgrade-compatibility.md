# Upgrade compatibility matrix — SDK, Rust, WASM, schema, and storage across releases

Security verification of this contract is only meaningful against a specific
toolchain and a specific set of storage assumptions. A release that moves the
compiler, the SDK, the WASM target, the policy schema, or the storage layout can
change the artifact hash, the ABI, or the on-chain state — sometimes silently.
This page records the current compatibility surface in one place so an operator
or auditor can answer "what do I need to reproduce / migrate / verify for this
release?" without hunting through `Cargo.toml`, `rust-toolchain.toml`,
`SECURITY.md`, and `policy.schema.json` separately.

> **Source-of-truth rule.** The versions in this matrix are *copied from the
> repository files*, never invented here. When a version changes, update the file
> that owns it first, then update this matrix in the same PR. If this page and the
> owning file ever disagree, the owning file is correct and this page is stale —
> report the drift rather than trusting the stale number. The full procedure is in
> [SECURITY.md § When a version changes](../SECURITY.md#when-a-version-changes).

## Current compatibility surface

| Component | Version | Source of truth | What it means for verification |
|---|---|---|---|
| Rust MSRV | **1.91.0** | `rust-version` in [`Cargo.toml`](../Cargo.toml) | The tested *floor*. The `msrv` CI job installs exactly this release (with the WASM target) and runs clippy, tests, and the WASM build. The floor is set by the dependency graph — `soroban-sdk` 27.0.6 itself declares `rust-version = "1.91.0"` — not by preference. |
| Rust toolchain (release channel) | **1.99.0** | `channel` in [`rust-toolchain.toml`](../rust-toolchain.toml) | The *pinned* compiler that builds the released artifact. `rustup` reads this file, so local builds and the `release` workflow use this exact toolchain; the `wasm-reproducible` CI job proves the hash is deterministic. |
| `soroban-sdk` | **27.0.6** | `[dependencies]` in [`Cargo.toml`](../Cargo.toml), pinned in `Cargo.lock` | The host surface the contract relies on (CustomAccountInterface, Context, ContractContext) is quoted from this exact release in [SPEC §1.1](../SPEC.md#11-sdk-and-host-surface-this-is-built-on-soroban-sdk-27). The host-routed tests exercise `__check_auth` through the real Soroban host on this version. |
| WASM target | **`wasm32v1-none`** | `targets` in [`rust-toolchain.toml`](../rust-toolchain.toml) | The only target the released contract builds for. The `release` workflow builds `--target wasm32v1-none`; provenance and the SHA-256 checksum are computed against that build. |
| Policy schema | **draft 2020-12** | `$schema` in [`policy.schema.json`](../policy.schema.json) | The JSON Schema the example policies and the CLI config are validated against. The contract's `validate_config` remains authoritative; the schema is a mirror for tooling (see the note in the schema's `description`). |
| Decision table | **schema_version 1** | `schema_version` in [`decision-table.json`](../decision-table.json) | The machine-readable source of the SPEC §4 decision table. `tests/decision_table.rs` fails `cargo test` if the table, the SPEC, or `src/engine.rs` drift. |
| Stellar protocol (verified) | **28** (testnet) | `network.protocol` in [`tests/fixtures/index.json`](../tests/fixtures/index.json) | The protocol the five Phase-1 scenarios were recorded on (2026-09-08). Verification does not carry forward to a later protocol without re-running the fixtures. |
| Storage layout | see [Storage Rent and TTL](rent-and-ttl.md) and [SPEC §10](../SPEC.md) | contract state keys | Any change to the storage keys or their TTL handling is a breaking contract release (see the note in SECURITY.md about the absence of a per-event version field). |

## What changes with each component

The matrix is not static; each row has a distinct blast radius. Reading it as a
single "the contract depends on these versions" list hides which changes are
routine and which are breaking. The table below separates them.

| Component | Routine bump | Breaking change | Verify by |
|---|---|---|---|
| Rust MSRV | raise only when a dependency requires it, in the same PR as that dependency | never higher than the release channel | `msrv` CI job green |
| Rust toolchain | re-record the release hash; `wasm-reproducible` proves determinism | any channel change changes the released WASM hash | `wasm-reproducible` + `provenance.txt` |
| `soroban-sdk` | re-verify SPEC §1.1 quotes; update SECURITY.md in the same PR | majors are isolated (dependabot separates them) because they can change the ABI | host-routed `integration_tests` |
| WASM target | none — fixed for v1 | a target change is a new artifact, not an upgrade | release build + checksum |
| Policy schema | keep in sync with any `PolicyConfig`/validation change | adding/removing/renaming a field breaks older CLI configs | `tests/policy_schema.rs` |
| Decision table | edit `condition`/`result` here, then paste the rendered row into SPEC | adding/removing an `Error::` branch in `src/engine.rs` fails until the table is updated | `tests/decision_table.rs` |
| Stellar protocol | re-run the recorded scenarios, update the fixture network fields | do not bump the number without new evidence; mark SECURITY.md STALE if unverified | fixture re-run on the new protocol |
| Storage layout | none — see [Storage Rent and TTL](rent-and-ttl.md) | any storage-key/TTL change is a breaking release (no per-event version field) | storage-key audit + migration guidance |

## Relationship to SECURITY.md

[`SECURITY.md` § Verified against](../SECURITY.md#verified-against) is the
security-model statement: it names the protocol, SDK, and Rust versions the
guarantees were *checked* against, with the on-chain evidence in
[`tests/fixtures/`](../tests/fixtures/). This matrix is the *broader* surface:
it also tracks the schema, the decision table, the WASM target, and storage —
the pieces a migration or a tooling upgrade has to keep consistent. Where the
two pages overlap (protocol, SDK, Rust), they must agree; update both in the
same PR when a version moves.

## Migration guidance

For a step-by-step upgrade of a *deployed* guard, use the
[migration guide](operations/migration-guide.md). That page covers the custody
transfer and the policy-install order; this matrix is the reference it points
back to when a version change is part of the migration. When the two interact —
for example, a `soroban-sdk` bump during a migration — resolve the version
questions here first, then follow the migration steps.

## See also

- [SECURITY.md § Verified against](../SECURITY.md#verified-against)
- [SECURITY.md § When a version changes](../SECURITY.md#when-a-version-changes)
- [Storage Rent and TTL](rent-and-ttl.md)
- [Migration guide](operations/migration-guide.md)
- [CONTRIBUTING.md § Dependency drift check](../CONTRIBUTING.md#dependency-drift-check)
- [SPEC §1.1 — SDK and host surface](../SPEC.md#11-sdk-and-host-surface-this-is-built-on-soroban-sdk-27)
