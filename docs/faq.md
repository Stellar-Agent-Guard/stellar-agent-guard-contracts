# FAQ

## Why don't non-SAC protocol calls get amount/recipient enforcement?

The Soroban auth context exposes `contract`, `fn_name`, and raw `args` for every call. For SAC token calls (`transfer`/`transfer_from`), the arguments are at fixed, known positions — we can read the recipient and amount directly.

For arbitrary protocol calls (DEX swaps, lending operations, etc.), there is no fixed argument schema. The "amount" may be a return value, an internal ledger effect, or encoded differently by each protocol. There is no reliable way to determine "how much value is moving" or "who is the recipient" from the raw `args` of an arbitrary contract call.

This is an inherent property of the platform, not something this project can work around. OpenZeppelin's Soroban `spending_limit` plugin observes the same boundary.

See [Enforcement Scope](enforcement-scope.md) for the full picture.

## Why isn't `__check_auth` called directly?

`__check_auth` is a trait method on `CustomAccountInterface`. The **Soroban host** calls it automatically when an authorization is needed — you never invoke it yourself. The host supplies the signature payload, the presented signature, and the list of auth contexts.

If you try to call `__check_auth` directly, it won't work — it's not in the contract's public function table. The enforcement is transparent to the agent: the agent signs a transaction, and the host intercepts the authorization to run the policy engine.

## What happens on a missed heartbeat?

If `dms_grace_secs > 0` and the agent has not heartbeated within the grace window:

1. The account is **automatically frozen** — no transaction needed, no background process. The freeze is derived lazily from `LastHeartbeat` and ledger time on every authorization.
2. All subsequent authorizations are blocked with `HeartbeatExpired` — transfers, protocol calls, and even `heartbeat` itself.
3. The agent **cannot self-revive** — a heartbeat arriving after the grace expired is rejected.
4. Only the admin's `unfreeze()` can restore the account. It clears the freeze and restarts the heartbeat clock.

This is the dead-man switch — it guards against agent silence. See [Dead-Man Switch](concepts/dead-man-switch.md).

## Can a compromised agent key bypass the policy?

No. The agent key can only authorize transactions — it cannot change the policy, freeze/unfreeze, or rotate itself. These are all admin-only functions. The compromised key can attempt to transact, but every transaction is still intercepted by `__check_auth` and must pass the full policy check.

A compromised key *can* keep the dead-man switch from firing (by heartbeating), but spend caps, allowlists, and the default-deny environment still bind it. The threat model is documented in SPEC §10.

## What does the admin control?

The admin can:
- Install/replace the policy (`set_policy`)
- Revoke the policy (`revoke_policy`)
- Freeze the account (`freeze`)
- Unfreeze the account (`unfreeze`)
- Rotate the agent key (`rotate_agent_key`)

The admin **cannot** move funds. Fund movement requires the agent's Ed25519 signature through `__check_auth`, which enforces the policy. The admin is a policy authority, not a fund authority.

## Why does `set_policy` reset the rolling window?

A fresh policy gets a fresh window by design. This prevents an old window's accumulated spend from carrying over into a new policy's cap. If you change the window cap from 1000 to 500, you don't want the old 800 in spend to immediately block you — the new policy starts with a clean slate.

This is an explicit admin-attested action: by calling `set_policy`, the admin is saying "I trust this new policy from this moment."

## Why can't the agent heartbeat after the grace expires?

Because that would defeat the purpose. If a compromised key could heartbeat after the grace expired, the dead-man switch would be useless — an attacker who stole the key could keep the account alive indefinitely. The dead-man switch is designed to catch exactly this scenario: only the admin's `unfreeze()` (which requires the admin's own auth) can revive the account.

## What is the `check` function for?

`check(asset, to, amount)` is a **pure pre-flight** of the SAC-transfer decision path. It runs the same code as `__check_auth` for a transfer context, but without writing anything to storage. It's meant for agents and SDKs to simulate a transfer *before* signing, so they can detect policy violations without submitting a transaction.

It emits the same `auth_checked` events as an in-path decision, so telemetry sees one vocabulary.

## Why does `agent-tx` exist?

The `stellar` CLI can build Soroban transactions and sign them with the transaction source key. But for a **custom account**, the auth entry's address is a **contract** (the guard), not the source account. The CLI refuses to sign auth entries for contract addresses — it errors with "Missing signing key for account C...".

The `agent-tx` tool fills this gap: it builds the `SorobanAuthorizationEntry` for the guard address, signs it with the registered agent Ed25519 key, and submits the transaction. This is exactly what the Phase 2 SDK will do programmatically.

## Is this audited?

No. This is unaudited security tooling that gates real fund access. Do not deploy to mainnet without an independent audit. See [SECURITY.md](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/SECURITY.md).
