# Stellar Agent Guard — Contracts

Non-custodial, account-level spending firewall for autonomous AI agents on Stellar.

An autonomous agent holding a wallet has a single point of failure: one prompt-injection or one buggy loop can drain it. Stellar Agent Guard makes that impossible on-chain — the agent's funds stay in its own smart account, and *every* transaction the account must authorize is intercepted by the contract's `__check_auth` and rejected pre-broadcast unless it satisfies a policy the operator installed: per-transaction spend caps, a genuinely rolling window cap, recipient/asset allowlists, a protocol/function allowlist, a pause switch, and a dead-man switch (heartbeat with admin-attested reversal).

## What makes this different

Enforcement happens **inside the account itself**, via Soroban's native Custom Account Abstraction — not in a wrapper contract in front of funds, not in an off-chain service. The guard is a Soroban contract implementing the `CustomAccountInterface`; the agent's Ed25519 public key is registered at `initialize`, and from then on the agent's address *is* the contract's address. Any transaction that requires the agent's authorization is routed by the host through `__check_auth`, which verifies the agent's signature over the transaction auth payload and then evaluates the policy decision table over every auth context.

Funds never leave the agent's own account — there is no deposit step, no vault, no `top_up`. The policy admin holds **no fund-moving authority of any kind**: admin functions change policy and freeze state only. Only the registered agent key can move funds, and only within the policy enforced in `__check_auth`.

## Glossary

Short definitions of the Stellar and Soroban terms this project relies on, each
pointing at the section that defines the behaviour normatively. Where a term has
a protocol meaning, [`SPEC.md`](../SPEC.md) governs; this list only orients.

- **SAC (Stellar Asset Contract)** — the built-in Soroban contract that wraps a
  Stellar asset and exposes `transfer`/`transfer_from`. In this project SAC
  transfers are the calls whose amounts and recipients are fully enforced,
  unlike other contract calls, which are allowlist-only. See
  [SPEC §2](../SPEC.md#2-enforcement-scope--sac-token-calls-vs-every-other-soroban-call-required-framing),
  [SPEC §6.2](../SPEC.md#62-asset-sac-calls--fully-enforced), and
  [`concepts/spend-limits.md`](concepts/spend-limits.md).
- **SCVal** — the XDR-encoded Soroban value type used for contract arguments,
  storage keys and values, return values, and events. Policy encoding is
  normative in
  [SPEC §3.2](../SPEC.md#32-exact-scval-encoding-of-policyconfig-for-non-typescript-consumers)
  and explained for non-Rust consumers in
  [`research/wire-format.md`](research/wire-format.md).
- **Authorization entry** (`SorobanAuthorizationEntry`) — the host object that
  proves an address approved a specific invocation subtree. For the guard it
  names the **contract** address (a custom account), so the host routes the
  decision to `__check_auth`; the signature covers the
  `HashIdPreimage::SorobanAuthorization` payload. See
  [SPEC §7](../SPEC.md#7-public-surface--exact-signatures-and-auth-placement),
  [SPEC §10.1](../SPEC.md#101-signature-binding), and
  [`functions/check-auth.md`](functions/check-auth.md).
- **Custom account** (Soroban Custom Account Abstraction) — a contract that
  implements `CustomAccountInterface`; the host calls its `__check_auth`
  whenever a transaction requires that address's authorization. The guard *is*
  the agent's account, not a wrapper in front of one. See
  [SPEC §1](../SPEC.md#1-mechanism-and-non-custodial-guarantee) and
  [`concepts/custom-account-enforcement.md`](concepts/custom-account-enforcement.md).
- **Ledger sequence** — the monotonically increasing number identifying a
  ledger. It is a position in the chain, not a clock: signature expiration and
  replay windows count ledgers, while policy time gates (heartbeats, active
  windows) use the **ledger timestamp**. See
  [SPEC §3](../SPEC.md#3-storage-model) and
  [SPEC §5](../SPEC.md#5-dead-man-switch--precise-definition).
- **TTL (time to live)** — how many ledgers a Soroban storage entry stays live
  before it is archived; rent extends it, and reads may refresh it when it falls
  below the threshold, so an idle guard's policy does not silently disappear.
  See [SPEC §9.5](../SPEC.md#95-persistent-storage-ttl-liveness) and
  [`rent-and-ttl.md`](rent-and-ttl.md).

## Status

Phase 1 is complete. All five enforcement scenarios were proven against live Stellar testnet (protocol 28) with real contract IDs and transaction hashes — evidence is recorded in the [Testnet Verification](verification.md) page.

| Feature | Status |
|---|---|
| Custom-account `__check_auth` enforcement | ✅ |
| Per-transaction spend cap | ✅ |
| Rolling window spend cap | ✅ |
| Recipient allowlist (SAC transfers) | ✅ |
| Protocol/function allowlist (any call) | ✅ |
| Dead-man switch (freeze on missed heartbeat) | ✅ |
| Admin unfreeze | ✅ |
| Verified against live testnet (cross-checked) | ✅ |
| Fine-grained amount/recipient enforcement for non-SAC calls | 🔲 (v2) |

## Contracts and tooling

| Component | Purpose |
|---|---|
| `stellar-agent-guard-contracts` (this repo) | The on-chain policy engine: a Soroban custom account contract |
| `tools/agent-tx` | CLI helper that signs Soroban auth entries for the guard address and submits real testnet transactions |

> ⚠️ **Disclaimer:** This is unaudited security tooling that gates real fund access. Do not deploy to mainnet without an independent audit. See [SECURITY.md](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/SECURITY.md).
