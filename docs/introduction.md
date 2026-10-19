# Stellar Agent Guard — Contracts

Non-custodial, account-level spending firewall for autonomous AI agents on Stellar.

An autonomous agent holding a wallet has a single point of failure: one prompt-injection or one buggy loop can drain it. Stellar Agent Guard makes that impossible on-chain — the agent's funds stay in its own smart account, and *every* transaction the account must authorize is intercepted by the contract's `__check_auth` and rejected pre-broadcast unless it satisfies a policy the operator installed: per-transaction spend caps, a genuinely rolling window cap, recipient/asset allowlists, a protocol/function allowlist, a pause switch, and a dead-man switch (heartbeat with admin-attested reversal).

## What makes this different

Enforcement happens **inside the account itself**, via Soroban's native Custom Account Abstraction — not in a wrapper contract in front of funds, not in an off-chain service. The guard is a Soroban contract implementing the `CustomAccountInterface`; the agent's Ed25519 public key is registered at `initialize`, and from then on the agent's address *is* the contract's address. Any transaction that requires the agent's authorization is routed by the host through `__check_auth`, which verifies the agent's signature over the transaction auth payload and then evaluates the policy decision table over every auth context.

Funds never leave the agent's own account — there is no deposit step, no vault, no `top_up`. The policy admin holds **no fund-moving authority of any kind**: admin functions change policy and freeze state only. Only the registered agent key can move funds, and only within the policy enforced in `__check_auth`.

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
