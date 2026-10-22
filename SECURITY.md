# Security Policy

## Disclaimer — read this first

This contract is **unaudited** and it **gates fund movement**. Unlike read-only
tooling, a bug or a subtle policy-semantics flaw in `__check_auth` can result in
the loss of the funds held by a deployed instance of this contract.

**Do not deploy this contract to mainnet with real funds until it has been
independently audited.** Testnet use only until then. This is a security
contract; assume the worst about the current code.

## Reporting a Vulnerability

**Primary — GitHub private vulnerability reporting.** Open a draft security
advisory from this repository's **Security → Advisories → Report a
vulnerability** (private: visible only to you and the maintainers):

<https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/security/advisories/new>

This is the preferred path: it is private, creates a trackable `GHSA` advisory,
and keeps the whole discussion and fix in one auditable place. It requires the
maintainer to have enabled **Private vulnerability reporting** once (see the
[maintainer checklist](#maintainer-checklist-outside-repo-actions) below).

**Fallback — email.** If you cannot use the advisory flow, email the maintainer
at **`aigbagbobila@users.noreply.github.com`** (the address linked to their
GitHub account). If your report is sensitive, say so and ask for a PGP key in
your first message; we will provide one before you send details.

**Community — Telegram, for non-sensitive questions only.** The
[Telegram group](https://t.me/+EzSusj-2vVhhNmI0) remains the community channel,
but it is **not** a private or trackable disclosure path. Do not post
vulnerability details there. If you only have a Telegram contact for the
maintainers, send a one-line request for the private route (advisory link or
PGP) and put the report itself in the private channel — the template below
applies whichever channel you end up using. See
[SUPPORT.md](SUPPORT.md) for which channel is meant for what.

### What to include in a report

Five short fields are enough for triage to start without a round of follow-up
questions. Copy the block below and fill it in; write "unknown" rather than
guessing, and skip `Suggested fix` entirely if you do not have one.

```text
Affected version / commit:
  <release tag (e.g. v0.1.x), commit SHA, or "main at <date>">
Description:
  <what the flaw is, in a few sentences>
Impact:
  <what an attacker gains>
  Funds at risk: yes / no / unclear — <one line on why>
Reproduction:
  <the smallest reliable way to trigger it: inputs, policy configuration,
   ledger/time conditions, and the failing test or transaction if you have one>
Suggested fix:
  <optional — even a direction is useful>
```

`Impact` is the field that sets triage order, so please be explicit about
whether funds can actually move: a `__check_auth` bypass, a cap that can be
exceeded, or an allowlist that can be walked through is a funds-at-risk report,
while a panicking read path or a misleading `check` pre-flight result usually is
not. Also tell us if your report touches a *deployed instance's configuration*
rather than this repository's code — see [Scope](#scope) — because that goes to
the operator, not to us.

### What you'll get back

- **Acknowledgement within 48 hours** of the report landing in the private
  channel, confirming a maintainer has it and who is looking at it.
- **Assessment and remediation plan (or a status update) within 7 days**: whether
  we reproduce it, whether we agree it is a vulnerability in this repository's
  scope, and what the fix path looks like.
- **Whether an advisory or a CVE is expected.** If we confirm the flaw and it
  affects released artifacts, we publish a `GHSA` security advisory for the
  affected versions and request a CVE through the GitHub advisory flow; the
  advisory — not a chat message — is the announced channel. If we decline the
  report (out of scope, operator misconfiguration, or a v1 design boundary
  already documented in SPEC §2/§10), we say so and give the reason, so the
  decision is auditable rather than silent.
- **Coordination.** Please do not disclose publicly until a fix is released, or
  90 days from your report — whichever comes first. We will tell you which of the
  two we are aiming for, and we ask for a heads-up before any earlier
  publication on your side.
- **Credit.** Named credit in the advisory is on request; anonymous reports are
  fine and are handled the same way. There is
  [no bug bounty at this time](#bug-bounty).

## Scope

**In scope (this repository):**

- The guard contract source in `src/` — `__check_auth` policy enforcement,
  per-transaction and rolling-window caps, recipient/asset/protocol allowlists,
  pause, admin freeze, and dead-man-switch logic.
- The agent-side tooling under `tools/agent-tx/` (auth-entry construction and
  signing).
- Build/release integrity of the contract artifacts published from this repo.

**Out of scope — report to the right place instead:**

- **Deployed instances.** A misconfigured *policy* on a running (testnet or
  mainnet) instance is an operator-configuration issue, not a contract
  vulnerability. Report it to that instance's operator.
- **Sibling repositories.** `stellar-agent-guard-sdk` and
  `stellar-agent-guard-dashboard` are separate repositories with their own
  `SECURITY.md` and disclosure process; report issues there.
- **Third-party dependencies.** Report upstream. Our release SBOM (below)
  documents exactly which crates and versions a deployed instance contains.

## Bug bounty

There is **no bug bounty programme at this time**. Reports are handled on a
best-effort, goodwill basis by the maintainers. This is stated up front so
researchers can decide whether to invest; if a programme launches, it will be
announced here and in the README.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Verified against

A security model is only meaningful relative to a platform. This revision of
the model was verified against:

| Component | Version | Evidence |
|---|---|---|
| Stellar protocol | **28** (testnet, `Test SDF Network ; September 2015`) | The five Phase-1 scenarios were run on protocol 28 and recorded on 2026-09-08 — [`tests/fixtures/README.md`](tests/fixtures/README.md), and `network.protocol: 28` in [`tests/fixtures/index.json`](tests/fixtures/index.json). |
| `soroban-sdk` | **27.0.6** (`Cargo.toml`, pinned in `Cargo.lock`) | The host surface this contract relies on is quoted from that exact release in [SPEC §1.1](SPEC.md#11-sdk-and-host-surface-this-is-built-on-soroban-sdk-27); the host-routed tests in `src/integration_tests.rs` exercise `__check_auth` through the real Soroban host on this version. |
| Rust | MSRV **1.91.0**; released artifacts built on the pinned **1.99.0** channel | `rust-version` in `Cargo.toml` (proven by the `msrv` CI job), `channel` in `rust-toolchain.toml` (used by the `release` workflow and proven deterministic by `wasm-reproducible`), and `provenance.txt` attached to every release. |

**What "verified against" means here:** the guarantees in the next section were
checked against a deployed contract on that protocol, with that SDK, by the
recorded testnet transactions. It does **not** mean audited (see the disclaimer
at the top), and it does not automatically carry forward to a later protocol or
a different build.

The on-chain evidence is deliberately outside this file: the scenario table,
transaction hashes, ledgers, and emitted `auth_checked` topics live in
[`tests/fixtures/README.md`](tests/fixtures/README.md) and its machine-readable
twin [`tests/fixtures/index.json`](tests/fixtures/index.json). Read them before
relying on this table; if the two disagree, the fixture index is the record of
what actually happened.

### When a version changes

- **Stellar protocol changes** (testnet/mainnet upgrade, or any host change that
touches custom-account dispatch, authorization contexts, or `__check_auth`):
  re-run the recorded scenarios against the new protocol, update the table above
  and the fixture network fields in the same PR, then release. Do not bump the
  number without new evidence. If a release must ship before re-verification,
  mark this section **STALE — verified against protocol <old> only** here and in
  the release notes, so nobody deploys under a false assumption.
- **`soroban-sdk` changes:** the dependency-drift ratchet in
  [CONTRIBUTING.md § Dependency drift check](CONTRIBUTING.md#dependency-drift-check)
  requires re-verifying the SPEC §1.1 quotes against the new source. Update the
  SDK row here in the same PR as the bump. A bump that changes authorization or
  context semantics also re-runs the fixtures; if that has not happened, mark
  this section stale rather than leaving a stale version named as verified.
- **Rust toolchain / MSRV changes:** update the Rust row from `Cargo.toml` and
  `rust-toolchain.toml` in the same PR as the bump. Re-verification of the
  security model is not implied, but the released WASM hash changes when the
  build channel changes, so treat the artifact as a new release (the
  reproducibility job and `provenance.txt` cover that separately).

**Absence of an explicit version is itself the signal:** if this section does
not name the protocol and SDK you are deploying, treat the model as unverified
for that deployment, regardless of the supported-versions table above.

### Where the drift watch lives

- [`CONTRIBUTING.md` § Dependency drift check](CONTRIBUTING.md#dependency-drift-check)
  — the review-time ratchet: a `soroban-sdk` bump must re-verify SPEC §1.1 and
  update this section.
- [`.github/dependabot.yml`](.github/dependabot.yml) — weekly Cargo and Actions
  update PRs; `soroban-sdk` majors are isolated because they can change the ABI.
- [`.github/workflows/host-watch.yml`](.github/workflows/host-watch.yml) — the
  weekly live compatibility watch: it reports the Futurenet protocol version and
  exercises a real `__check_auth` on Futurenet. A protocol change shows up there
  first; when it does, this section is the document to update.

## Security Model (what the contract guarantees — and does not)

Guarded on-chain, inside `__check_auth`, unbypassable by a compromised agent key:

- Per-transaction and rolling-window spend caps
- Recipient / asset allowlists on SAC transfers
- Protocol / function allowlist (default-deny) on all other calls
- Pause switch, admin freeze, dead-man switch (heartbeat + admin-attested reversal)

Not guarded by v1 (documented in SPEC §2 / §10, not hidden):

- Per-call amount/recipient limits on non-SAC protocol calls (v2 item)
- A live attacker who keeps the agent key heartbeating (caps still bind them)
- Admin compromise (admin can rewrite policy/keys/freeze — by design; it still
  cannot move funds)
- Availability griefing by a holder of the agent key: such a key can generate
  policy-denied transactions on demand, at no cost to the guarded account, which
  makes the account look broken. It cannot move funds, cannot consume the rolling
  window (denied batches commit nothing — SPEC §6.0), and cannot write state; the
  admin stops it with one `rotate_agent_key`. See SPEC §10.3 for the reasoning,
  the bound, and the telemetry signature that distinguishes it.

### When a rejection happens, what the operator can actually see

A policy denial is not a revert string a caller can print — the guard returns the
reason through the Soroban host, and it surfaces differently on each interface.
Triaging an incident (or a bounty report claiming "the agent was blocked for no
reason") requires knowing which surface produced which observation:

- **Pre-broadcast simulation** (`soroban-rpc` `simulateTransaction`) is the only
  surface that carries the reason legibly: it is the **third topic** of the
  `auth_checked` diagnostic event (`topics: [event_auth_checked, blocked,
  <reason_symbol>]`), and the same diagnostics nest the contract error code
  (`Error(Contract, #N)`, SPEC §7.1) inside an outer `Error(Auth, InvalidAction)`
  wrapper. Decode the topic, never the wrapper.
- **A submitted transaction** fails as `txFAILED` ("one of the operations
  failed, none were applied"), the fee is still charged, and the reason exists
  only inside `result_xdr` / `diagnosticEventsXdr`. Nothing on Horizon's
  transaction resource spells out a reason symbol.
- **A bad signature never reaches the engine.** There is no `auth_checked`
  event and no `fn_call … __check_auth` diagnostic line at all — the absence of
  both is what distinguishes a signature failure from a policy denial.

The full mapping — observable error → policy reason → reversal path, with a
verbatim live capture and the rejection classes — is
[`docs/functions/check-auth.md`](docs/functions/check-auth.md#what-an-operator-sees-when-this-rejects-issue-425).
The reason-symbol vocabulary is [docs/reason-glossary.md](docs/reason-glossary.md);
the reversal procedure for a frozen account — including the two-gate case where
`unfreeze` alone is not enough — is SPEC §5.2 and the recovery runbook / incident
variant of [`docs/key-rotation.md`](docs/key-rotation.md#incident-variant-suspected-agent-key-leak).
`tools/agent-tx preflight --secret …` is the enforced pre-broadcast path (exit
`0` admitted, `1` blocked, `2` indeterminate) and it never submits.

## Supply chain — software bill of materials (SBOM)

Every tagged release (`v*`) attaches a **CycloneDX** SBOM — `sbom.cdx.json` —
to the GitHub Release. It is generated by
[`cargo-cyclonedx`](https://github.com/CycloneDX/cyclonedx-rust-cargo)
(cyclonedx-rust) from Cargo metadata plus `Cargo.lock` for the
`wasm32v1-none` build, so it inventories every crate and version compiled into
the **shipped WASM** — not the host toolchain. This is the artifact that lets an
auditor or bug-bounty reviewer know exactly what a deployed instance contains.

Reproduce it locally:

```bash
cargo install cargo-cyclonedx --locked
cargo build --release --target wasm32v1-none
cargo cyclonedx --format json --describe binaries --target wasm32v1-none
# -> stellar_agent_guard_contracts_lib-cdylib.cdx.json  (one SBOM per binary target)
```

To verify what a deployment contains:

1. Download `sbom.cdx.json` from the release that matches the deployed WASM
   (compare the WASM SHA-256 if the release publishes one).
2. Regenerate the SBOM from that tag's source and diff the component lists.
3. Check those component versions against an advisory database (e.g.
   `cargo audit` / `cargo deny check advisories`). The SBOM is the inventory
   artifact; the advisory scan is a separate gate.

## Release artifact verification

Every tagged release (`v*`) publishes four assets, built only after the full
gate suite (format, clippy, tests) went green — a failed gate blocks the
release (see `.github/workflows/release.yml`):

- `stellar_agent_guard_contracts.wasm` — the deployable contract build.
- `stellar_agent_guard_contracts.wasm.sha256` — its SHA-256 checksum.
- `provenance.txt` — the git tag, commit SHA, exact build command, toolchain
  version (`rustc`/`cargo`), and runner the WASM was built on.
- `sbom.cdx.json` — the CycloneDX inventory described above.

Before deploying a released artifact:

1. Verify the checksum: `sha256sum -c stellar_agent_guard_contracts.wasm.sha256`
   must print `OK`. A mismatch means the download is corrupt or tampered with —
   do not deploy it.
2. Confirm `provenance.txt` pins the git tag and commit you expect, then
   rebuild that tag yourself (`cargo build --release --target wasm32v1-none`)
   and compare hashes for a reproducibility check. The compiler is pinned in
   `rust-toolchain.toml`, so `rustup` builds that tag with the same `rustc`
   version the release used; run `./scripts/check-wasm-reproducible.sh` to
   confirm your environment is deterministic before trusting the comparison
   (issue #67). Hashes published **before** that pin existed cannot be
   reproduced from this repository — the toolchain that produced them was never
   recorded — so verify those by checksum and provenance only, and prefer a
   release cut after the pin.
3. Diff the SBOM component list against a locally regenerated one as described
   above.

## Security Considerations

- The policy admin holds **no fund-moving authority**; only the registered agent
  key moves funds, and only within policy. Losing the admin key means losing the
  ability to change policy or unfreeze — it does not put funds at risk.
- The account is **default-deny**: unlisted contracts and functions are blocked.
  Adding a protocol is an explicit policy act.
- Contract creation by the account is denied in v1.
- Read functions are public (no DoS on reads); policy writes are admin-only.
- This contract is **unaudited**. An audit is a prerequisite for mainnet use;
  track it via the issue backlog.

## Maintainer checklist (outside-repo actions)

These cannot be done from a pull request and must be performed by a maintainer
with admin rights on the repository:

- [ ] **Enable Private vulnerability reporting**: **Settings → Code security and
      analysis → Private vulnerability reporting → Enable**. This turns on the
      Security-tab "Report a vulnerability" button and the advisory API linked in
      [Reporting a Vulnerability](#reporting-a-vulnerability).
- [ ] **Confirm the security email**: the fallback in this document uses the
      maintainer's GitHub-linked address. Replace it with a monitored security
      mailbox (e.g. `security@…`) if one exists, and keep it in sync here.
- [ ] **State the bug-bounty position** as it evolves (currently: none).
