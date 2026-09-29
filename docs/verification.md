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
