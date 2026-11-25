# Sample release note — v0.2.0 (illustrative)

This is a worked example of the release-notes template used by the
[release workflow](.github/workflows/release.yml). Replace the placeholder
sections with the actual changes for each release.

## Security-impacting changes
Indicate which categories this release touches (check all that apply):

- [ ] **Policy** — policy semantics, caps, allowlists, pause/freeze, dead-man switch,
  or `__check_auth` admission.
- [x] **ABI** — `PolicyConfig` gained the `asset_caps` field; field order changed,
  so `policy_hash` and off-chain encoders are affected (SPEC §3.2).
- [ ] **Storage** — storage keys, types, footprint, or TTL management.
- [ ] **Events** — emitted events, event names, topics, or diagnostic payloads.

Because the **ABI** box is checked, this release requires migration review: see the
[migration guide](migration-guide.md) before upgrading, and record the impact below.

## Changelog
- `set_policy` now accepts per-asset `per_tx_cap` overrides via `asset_caps` (additive;
  the global `per_tx_cap` remains the fallback).
- `policy_hash()` changes when `asset_caps` changes; off-chain consumers re-compute the
  hash from the canonical ScVal encoding.
- `Error` discriminants are unchanged (append-only convention preserved).

## Verification
- Full CI gate green (format, clippy, tests, wasm build).
- SBOM and build provenance attached.
