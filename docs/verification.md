# Testnet Verification

All five enforcement scenarios were proven against a **real deployed contract** on Stellar testnet (protocol 28, `Test SDF Network ; September 2015`). Nothing here is simulated — every transaction was actually submitted to or enforced against live testnet state.

## Deployed contracts

| Component | Address |
|---|---|
| Guard (custom account) | `CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7` |
| SAC token (`GUARD:GD5S5...`) | `CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7` |

## Accounts

| Role | Address |
|---|---|
| Admin | `GD5S5O2MZ6FSMFH6QILG37KSQNRVR3RPSWBTTV4JOUJ7J6TWLLL5LAVS` |
| Agent (guarded keypair) | `GAOLI6NMXG5X3GZ2ASTIMX24IQQW7CSGHVSOU7HOWFCH73RBZXGAKSPP` |
| Allowed recipient | `GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX` |
| Non-allowlisted address | `GDMVA2IQH63BYCFZMOVDYCUDGJZYSUCDGCVFDPU5BLTHFUEZ6BF5EPP7` |

## Setup transactions

| Step | Tx hash |
|---|---|
| Upload guard WASM | `d43edd086ac9b376371f33b72ad89b37a9b6b4d43bf34dfea9717a29688b887c` |
| Create guard contract | `a968bc517af34b0cb1ed53a4523d1cb8b9e562e9a9b1e8367acfabcbf18211b1` |
| Create token (SAC) | `19f1e36cf4c67feab4e6eb490b4ef424a7fbcc978fcbfa2cad96a079e93ec828` |
| Mint 100,000 to guard | `bdeab1808f83c8db3c7a8cf675690afa7039a7aaae5e92fdc9fb7d6700adfeb2` |
| Initialize guard | `cb17b7b1c65bff74b6bc99f67fe3cf1070c7a28f14bdd71527ba60c9d4a81264` |
| Policy (scenarios 1–4) | `6f17c5707d86754cc64f7f5adf6d9b9840904f0bea4d10ae5620ffe065c61174` |
| Trustline (recipient) | `81479a058dd03457fb91e7b129f941eef64e0bc0752a7f0a5fb3928d5f644fb4` |
| Policy (DMS grace 60s) | `1ddad388f914e267b282855ddc8e5478fabfb8542e7798e4402447e5341e3f9a` |
| Unfreeze (DMS reversal) | `dd327d32b18bfc6cebdf6c956503fe5318e28f8a8bc86a88cb7ee42c5d46b5e5` |

The policies installed:

```
# Scenarios 1–4 (6f17c570…):
per_tx_cap: 1000, window_cap: 150, window_secs: 60,
assets: [token], recipients: [GDUYLF…], blocked_recipients: [], dms_grace_secs: 0 (DMS off)

# DMS scenario (1ddad388…): same policy with dms_grace_secs: 60
```

## How scenarios were executed

The `stellar` CLI cannot sign Soroban auth entries whose address is a **contract** (the guard) — it only signs for the transaction source account and errors with "Missing signing key for account C..." (known CLI limitation). So submissions go through the repo's `tools/agent-tx` helper, which:

1. Builds the `SorobanAuthorizationEntry` for the **guard** address with the agent's registered Ed25519 key.
2. Simulates the call — the enforced simulation runs the **real** `__check_auth` against live testnet state, so policy blocks surface pre-broadcast.
3. On approval, submits and reports the on-chain result.

Each invocation uses a fresh tx sequence as the auth nonce.

---

## Scenario 1: Allowed transaction — ✅ PASSED on-chain

A policy-respecting asset transfer succeeds.

```bash
agent-tx transfer --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
    --token CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
    --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX --amount 50
# → submitted: hash=4c5759298c0364b01d386a5935b964532b04978ea595d96d904d9011f58d64b8 status=PENDING
# → RESULT: ALLOWED tx=4c5759298c0364b01d386a5935b964532b04978ea595d96d904d9011f58d64b8
```

**Horizon verification:** `successful: true`, ledger 4566285, created 08:10:12Z. The guard's `event_auth_checked, allowed` event was emitted, and the SAC `transfer` event fired on-chain. Funds moved from the guard account to the allowed recipient.

---

## Scenario 2: Per-tx cap violation — ✅ BLOCKED (pre-broadcast)

Transfer above `per_tx_cap` is blocked on-chain.

```bash
agent-tx transfer --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
    --token CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
    --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX \
    --amount 1100 --expect-blocked   # 1100 > per_tx_cap 1000
# → BLOCKED (pre-broadcast, enforced simulation)
```

Guard diagnostic event (from the enforced simulation, real `__check_auth`):

```
[Contract Event] topics: [event_auth_checked, blocked, per_tx_cap_exceeded]
```

No transaction was broadcast — the violation was caught by `__check_auth` before the SAC call could be authorized.

---

## Scenario 3: Rolling-window cap violation — ✅ BLOCKED (pre-broadcast)

After scenario 1 spent 50 in the window, a second transfer of 110 (50 + 110 = 160 > window_cap 150) within the 60s window:

```bash
agent-tx transfer --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
    --token CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
    --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX \
    --amount 110 --expect-blocked   # window 50+110=160 > 150
# → BLOCKED (pre-broadcast, enforced simulation)
```

Guard diagnostic event:

```
[Contract Event] topics: [event_auth_checked, blocked, window_cap_exceeded]
```

This is a **genuinely rolling** 60-second window — expired entries are pruned at evaluation time (see `src/window.rs`), not a fixed-bucket reset.

---

## Scenario 4: Allowlist violation — ✅ BLOCKED (pre-broadcast)

Transfer to a non-allowlisted address is blocked.

```bash
agent-tx transfer --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
    --token CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
    --to GDMVA2IQH63BYCFZMOVDYCUDGJZYSUCDGCVFDPU5BLTHFUEZ6BF5EPP7 \
    --amount 10 --expect-blocked
# → BLOCKED (pre-broadcast, enforced simulation)
```

Guard diagnostic event:

```
[Contract Event] topics: [event_auth_checked, blocked, recipient_not_allowed]
```

The recipient is not in the policy's `recipients` allowlist; the transfer never reached the token contract.

---

## Scenario 5: Dead-man switch — ✅ FROZEN, then UNFROZEN

### Trigger

Policy with `dms_grace_secs: 60` was installed (tx `1ddad388…`), which starts the DMS clock (`LastHeartbeat = now` at install). After the 60s grace lapsed with no heartbeat:

```bash
agent-tx transfer --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
    --token CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
    --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX \
    --amount 10 --expect-blocked   # 65s after policy install, no heartbeat
# → BLOCKED (pre-broadcast, enforced simulation)
```

Guard diagnostic event:

```
[Contract Event] topics: [event_auth_checked, blocked, heartbeat_expired]
```

### Reversal

Admin `unfreeze()` — the SPEC §5 reversal path (silence cannot self-revive; heartbeats are also blocked once expired, so only the admin attestation restores the account):

```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
    --network testnet --source guard_admin --send=yes -- unfreeze
# → ✅ Transaction submitted successfully!
#    tx=dd327d32b18bfc6cebdf6c956503fe5318e28f8a8bc86a88cb7ee42c5d46b5e5
# → Event: EventUnfrozen (event_unfrozen),
#    by: "GD5S5O2MZ6FSMFH6QILG37KSQNRVR3RPSWBTTV4JOUJ7J6TWLLL5LAVS"
```

### Post-reversal

Immediately after unfreeze, the agent's transfer works again:

```bash
agent-tx transfer --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
    --token CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
    --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX --amount 10
# → submitted: hash=b39457afa59f20d6ac90cd137e917c7efd51e27af4913c6c6308a6e5d0eff512
# → RESULT: ALLOWED tx=b39457afa59f20d6ac90cd137e917c7efd51e27af4913c6c6308a6e5d0eff512
```

**Horizon verification:** `successful: true`, ledger 4566327, created 08:13:42Z.

---

## How to re-run

1. Build the contract and submission helper:

```bash
cargo build --release --target wasm32v1-none   # contract WASM
cd tools/agent-tx && cargo build --release      # submission helper
```

2. Fund fresh accounts via Friendbot, deploy the guard + token, mint, and `initialize` (see setup txs above).

3. Install the scenario policies (JSON in `--config`), then run the `agent-tx` invocations above. Use `--expect-blocked` for scenarios 2–5.

The five blocked/emitted events above are the contract's own `event_auth_checked` topics — grep the enforced-simulation output for `blocked, <reason>` to confirm each.

---

## Reproducible release verification recipe

This recipe lets you confirm that a published release WASM is **byte-for-byte
identical** to what you get when you build from the same tag with the same
pinned toolchain. It is the auditor's end-to-end check: source → build →
hash → compare.

### Prerequisites

- **Rust toolchain** — `rustup` will install the pinned compiler automatically
  from `rust-toolchain.toml` when you run `cargo build` inside the repository;
  no manual version selection is needed.
- **`wasm32v1-none` target** — installed on first build, or manually:
  `rustup target add wasm32v1-none`.
- `sha256sum` (Linux) or `shasum -a 256` (macOS) — available in any standard
  shell environment.
- A tagged release on GitHub with the four assets described below.

### Step 1 — download and inspect the release artifacts

Every `v*` tag publishes four assets. Download them from the **Releases** page
(or via `gh release download <tag> -R Stellar-Agent-Guard/stellar-agent-guard-contracts`):

| File | Purpose |
|---|---|
| `stellar_agent_guard_contracts.wasm` | The deployable contract build |
| `stellar_agent_guard_contracts.wasm.sha256` | Its SHA-256 checksum |
| `provenance.txt` | Git tag, commit SHA, exact build command, toolchain, and runner |
| `sbom.cdx.json` | CycloneDX supply-chain inventory for the WASM |

### Step 2 — verify the published checksum

```bash
sha256sum -c stellar_agent_guard_contracts.wasm.sha256
# Expected: stellar_agent_guard_contracts.wasm: OK
```

A "FAILED" means the download is corrupt or tampered with — stop here and
re-download. Do not deploy an artifact whose checksum does not match.

### Step 3 — confirm provenance

Open `provenance.txt` and check that:

- The `tag:` line names the release you downloaded.
- The `commit:` SHA matches `git rev-parse <tag>` in your local clone (or
  the commit shown on GitHub for that tag).
- The `toolchain:` line names a Rust version. Record it — you will verify
  reproducibility with the same channel in step 4.
- The `build_command:` is
  `cargo build --release --locked --target wasm32v1-none` (the `--locked`
  flag proves the exact dependency tree in `Cargo.lock` was used).

### Step 4 — build from the same tag

Clone the repository (or reuse an existing clone) and check out the exact tag:

```bash
git clone https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts.git
cd stellar-agent-guard-contracts
git checkout <tag>           # e.g. v0.1.3
```

Build with the locked dependency tree:

```bash
cargo build --release --locked --target wasm32v1-none
```

`rustup` reads `rust-toolchain.toml` and downloads the pinned compiler
automatically. The build is deterministic when the toolchain, `Cargo.lock`,
and source tree are identical to those the release used.

### Step 5 — compare hashes

```bash
# Hash your local build:
sha256sum target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm

# Hash the downloaded release artifact (should be identical to the .sha256 file):
sha256sum stellar_agent_guard_contracts.wasm
```

The two digests must be identical. A match proves:

- The downloaded WASM came from the same source tree and toolchain as your
  local build.
- No post-build modification was made to the released artifact.

### Step 6 — confirm local build determinism with the CI script

Before trusting the comparison above, verify that your local environment
produces the same hash on two independent builds:

```bash
./scripts/check-wasm-reproducible.sh
# Expected: build A and build B hashes match.
# Exit 0 = your environment is deterministic.
# Exit 1 = hashes differ (see § Common mismatch causes below).
```

The script builds twice into separate `CARGO_TARGET_DIR` directories so no
artifact is shared between runs. It is the same check the `wasm-reproducible`
CI job runs, so a local pass and a CI pass are the same statement.

### Step 7 — verify the SBOM (optional but recommended for auditors)

```bash
# Regenerate the SBOM from the same tag and diff the component list:
cargo install cargo-cyclonedx --locked
cargo build --release --target wasm32v1-none
cargo cyclonedx --format json --describe binaries --target wasm32v1-none
# → stellar_agent_guard_contracts_lib-cdylib.cdx.json

diff <(jq -r '.components[].name' sbom.cdx.json | sort) \
     <(jq -r '.components[].name' stellar_agent_guard_contracts_lib-cdylib.cdx.json | sort)
# A clean diff means the released SBOM inventory matches your local rebuild.
```

Then check those component versions against an advisory database:

```bash
cargo audit
cargo deny check advisories
```

### Common mismatch causes

| Symptom | Likely cause | Fix |
|---|---|---|
| Local build ≠ release artifact | Different Rust channel or `Cargo.lock` state | Confirm `rustc --version` matches `provenance.txt`; ensure you built from exactly the tagged commit with `--locked` |
| `check-wasm-reproducible.sh` exits 1 | Non-deterministic build environment | Check for `SOURCE_DATE_EPOCH` overrides, unstable `codegen-units`, or a custom `RUSTFLAGS` that enables non-deterministic optimizations |
| Hashes existed before toolchain pin (pre-pin releases) | The toolchain was `stable` (floating) when those releases were cut | Verify by checksum and `provenance.txt` only; reproducible rebuild is not possible without an exact toolchain record |
| `sha256sum -c` prints "FAILED" | Download corrupt or truncated | Re-download over a fresh connection; check disk space |

### Linking back to the audit pack

Reproducible-build evidence (item 8 in
[`docs/audit-pack.md`](audit-pack.md#inventory)) depends on this recipe and
the CI `wasm-reproducible` job. The SBOM (item 18) is generated and attached by
the same `release.yml` workflow. Run this recipe as part of an audit engagement
before relying on the published checksum alone.

---

## WASM size budget & investigating growth

CI enforces a hard ceiling on the compiled release artifact
(`target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm`) against the
budget committed in [`scripts/wasm-size-budget.txt`](../scripts/wasm-size-budget.txt).
On every CI run — pass or fail — [`scripts/check-wasm-size.sh`](../scripts/check-wasm-size.sh)
parses the WASM binary directly and prints a deterministic per-section report
sorted by byte size (with section name tie-breaking), both to stdout and to the
GitHub Actions job summary:

- `code` — compiled WebAssembly function bodies (typically the largest section)
- `data` — static byte literals and initialized linear-memory segments
- `custom (<name>)` — Soroban metadata and ABI spec sections such as
  `contractspecv0`, `contractenvmetav0`, and `contractmetav0`
- `type`, `import`, `function`, `table`, `memory`, `global`, `export`, `element`, `data_count`, and the 8-byte `header`

### Run the section report locally

```bash
cargo build --release --target wasm32v1-none
./scripts/check-wasm-size.sh
```

### How to investigate section growth

1. **Compare against `main` first.** Run `./scripts/check-wasm-size.sh` on both
   `main` and your branch to see which exact section absorbed the delta.
2. **If `code` grew:**
   - Look for duplicated generic or `soroban_sdk::Vec` helpers, newly monomorphized
     paths, or large inline functions in `src/lib.rs`, `src/engine.rs`, and `src/window.rs`.
   - Profile symbol-level bloat with `twiggy` (`twiggy top -n 30 <wasm>` /
     `twiggy paths <wasm>`) or `cargo bloat --release --target wasm32v1-none --crates`
     (note: `release` profile in `Cargo.toml` strips symbols unless inspecting an
     unstripped/debug build with `twiggy`).
3. **If `data` grew:**
   - Check for new static byte tables, error/diagnostic strings, or unexpected panic
     strings — run `bash scripts/check-wasm-panic-strings.sh` to catch new panic
     sites or format strings pulled into `.rodata`.
4. **If `custom (contractspecv0)` or other `custom` sections grew:**
   - New `#[contractimpl]` entry points, `#[contracttype]` structs/enums, or verbose
     docstrings on exported types/functions are serialized into Soroban's `contractspecv0`
     custom section. Trim redundant spec prose or verify that every new exported item
     belongs on the public ABI.
5. **Updating the budget:** Only raise `bytes=` in
   [`scripts/wasm-size-budget.txt`](../scripts/wasm-size-budget.txt) when the growth
   is intentional and justified (following the steps in that file and explaining the
   section-level delta in the PR body). Never bump the budget solely to turn CI green.
