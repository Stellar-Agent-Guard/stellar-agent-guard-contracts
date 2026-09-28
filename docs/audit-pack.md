# Audit Pack — Inventory and Status

This page is the **single inventory** of what a professional auditor needs before review, and
how much of it exists today. It exists so that [issue #6](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/6)
("audit readiness: property tests, invariants-as-executable-checks, audit pack") closes only
when the pack is genuinely complete — and so parallel contributors can see which items are
claimed.

**Status of this pack: incomplete.** The contract is unaudited and gates fund movement
([SECURITY.md](../SECURITY.md)). Items marked 🔲 are the blocking work.

## How to read this

| Status | Meaning |
|---|---|
| ✅ | In-repo and usable by an auditor today |
| 🟡 | Partial — some evidence exists, but the item is not audit-grade yet |
| 🔲 | Not done; tracking issue is open (filed, unclaimed or in progress) |
| ⬜ | Not done and **not yet filed** — follow-up issue required |

Each item has a tracking issue link. Where an item is fed by several issues, all are listed.

## Inventory

### Executables — checks an auditor can run

| # | Pack item | Status | Tracking | Evidence today |
|---|---|---|---|---|
| 1 | **Property suite** — randomized `PolicyConfig` × context sequences asserting SPEC invariants | ⬜ | none filed (demanded by #6) | Unit/integration tests only, hand-picked cases: `src/engine.rs` (11), `src/window.rs` (7), `src/integration_tests.rs` (20). No `proptest` dev-dependency. |
| 2 | **Invariants as executable checks** — rolling-window invariant (SPEC §3.1), default-deny, decision-table ordering | 🟡 | [#76](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/76), [#139](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/139) | Window pruning + decision ordering are asserted in `src/window.rs` / `src/engine.rs` tests, but the decision table is not yet extracted to one generated source of truth, so SPEC ↔ code agreement is manual. |
| 3 | **Fuzz targets** — `PolicyConfig` deserialization, and `__check_auth` full path with hostile contexts | 🔲 | [#65](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/65), [#140](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/140) | None. No `cargo-fuzz` setup. |
| 4 | **Coverage report with enforced floor** | 🔲 | [#64](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/64) | None wired into CI. |
| 5 | **Denial-path gas evidence** — cost of a *blocked* authorization | ✅ | [#149](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/149) (closed) | `benches/denial_path_gas.rs` + measured gate-cost order in SPEC §4.1. |
| 6 | **Decision-path cost regression guard** — worst-case list cardinality, benchmark trend | 🟡 | [#75](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/75), [#118](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/118) | A bench harness exists (`benches/denial_path_gas.rs`); no tracked regression threshold and no worst-case-cardinality case. |
| 7 | **Panic-safety guard** — CI check for new `unwrap`/`expect`/`panic!` outside contract errors | 🟡 | [#66](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/66) | CI runs `cargo clippy --all-targets --all-features -- -D warnings` (all + pedantic denied in `Cargo.toml`); no dedicated deny-list gate. |
| 8 | **Reproducible WASM build** — pinned toolchain + deterministic hash | 🔲 | [#67](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/67), [#91](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/91) | Build is fixed to `wasm32v1-none` in CI; toolchain is `stable` (unpinned) and no hash comparison. |
| 9 | **WASM size budget** | 🔲 | [#68](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/68) | None. |

### Documents — what the auditor reads

| # | Pack item | Status | Tracking | Evidence today |
|---|---|---|---|---|
| 10 | **Threat model** — SPEC §10 cross-check, plus the compromised-admin delta | 🟡 | [#45](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/45), [#79](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/79) | SPEC §10 is written and in-repo (including the explicit "guards against silence, not live attackers" framing). Compromised-admin delta and signature-payload-binding (replay / cross-context confusion) analysis are not written. |
| 11 | **Reason glossary / denial-reason vocabulary** | ✅ | [#143](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/143) (closed) | [`docs/reason-glossary.md`](reason-glossary.md) — what each blocked reason means for agent vs operator vs auditor. |
| 12 | **SPEC/code consistency proof** — error-variant ↔ decision-table parity | 🟡 | [#132](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/132) (closed), [#159](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/159) (closed), [#76](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/76), [#146](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/146), [#110](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/110) | SPEC §4/§6 tables list every `Error` variant exactly once (#132); SPEC §1.1 verified against `soroban-sdk` 27.0.6 sources (#159). Still manual — not a generated check; SPEC has no revision tagging. |
| 13 | **Testnet fixture evidence** — on-chain proof, not simulation | 🟡 | [#42](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/42), [#92](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/92), [#156](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/156), [#131](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/131) | [`tests/fixtures/README.md`](../tests/fixtures/README.md) + [`docs/verification.md`](verification.md): 5 scenarios, deployed contract addresses, tx hashes, Horizon-verified ledgers. Prose only — no golden JSON fixtures, no machine-readable scenario index, no live re-verification script. |
| 14 | **SECURITY.md audit status and disclosure channels** | 🟡 | [#78](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/78), [#6](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/6) | [`SECURITY.md`](../SECURITY.md) states the contract is unaudited and must not hold mainnet funds. Outcome/status section arrives with the audit; reporting is Telegram-only. |
| 15 | **Enforcement-scope honesty statement** | ✅ | [#84](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/84) | [`docs/enforcement-scope.md`](enforcement-scope.md) — the SAC-vs-arbitrary-call boundary plus the framing rules. |
| 16 | **Event payload audit** — every event's topics/data documented and asserted | 🔲 | [#105](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/105), [#41](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/41), [#42](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/42) | Event emission exists and is asserted within scenario tests; no complete documented-vs-emitted contract. |
| 17 | **Runtime/custody analysis** — replay and nonce semantics, `auth_contexts` handling | 🟡 | [#79](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/79), [#114](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/114), [`docs/research/wire-format.md`](research/wire-format.md) | Wire format and nonce behaviour are documented in `tests/fixtures/README.md` and `docs/research/wire-format.md`; adversarial analysis is pending. |

### Evidence and supply chain

| # | Pack item | Status | Tracking | Evidence today |
|---|---|---|---|---|
| 18 | **SBOM (CycloneDX)** | ✅ | [#125](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/125) (closed) | `.github/workflows/release.yml` runs `cargo cyclonedx` and attaches `sbom.cdx.json` to the release. |
| 19 | **Dependency audit** — `cargo-audit` / `cargo-deny` gate, update automation | 🔲 | [#69](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/69), [#72](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/72), [#130](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/130) (closed) | No advisory gate, no dependabot config. `#130` was a manual Soroban host-change watch, now closed. |
| 20 | **Release provenance** — tag → build → WASM + checksums attached | 🟡 | [#73](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/73) | `release.yml` exists and produces the SBOM; artifact/checksum attachment and the versioning policy ([#146](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/146)) are incomplete. |
| 21 | **ABI / version-compatibility snapshot** | 🔲 | [#74](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/74) | None (`cargo semver-checks` or ABI snapshot not wired). |

## Pack completeness

- **Blocking gaps (must land before #6 closes):** items 1, 3, 4, 6, 8, 10, 13, 16, 19, 21.
- **Ready today:** items 5, 11, 15, 18 — the auditor can read a threat model, the reason
  glossary, the enforcement boundary, and consume a CycloneDX SBOM from a release.
- **Coordination rule:** an item moves to 🟡/✅ only when the linked issue is linked back to
  #6 in return, so the inventory and the tracker stay in both directions.

## Items not yet filed → follow-up issues

These pack items have no tracking issue and are proposed as new issues (also listed in the
PR description for #155):

1. **Property-test suite for `PolicyConfig` × context sequences** (item 1) — `proptest`
   dev-dependency, generated policies and call sequences, assertions on the SPEC §3.1
   rolling-window invariant and default-deny. This is the #6 acceptance criterion with no
   issue of its own.
2. **Generator + CI check for the SPEC §4/§6 decision table** (items 2, 12) — extends #76
   from a one-off extraction to a check that fails when SPEC and codes drift.
3. **Auditor-facing repro guide** — one page an auditor can execute end-to-end: toolchain
   pin → build → `cargo test` → fixture re-verification (ties items 8, 13, 20 together).

## Links

- [Issue #6 — audit readiness](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/6) · [Issue #155 — this inventory](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/155)
- [SPEC.md](../SPEC.md) · [SECURITY.md](../SECURITY.md) · [Enforcement Scope](enforcement-scope.md)
- [Reason Glossary](reason-glossary.md) · [Testnet Verification](verification.md) · [Fixture evidence](../tests/fixtures/README.md)
