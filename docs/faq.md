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
- Pause/resume the policy's kill switch in place (`pause` / `resume`)
- Explicitly zero the rolling spend window (`reset_window`)
- Rotate the agent key (`rotate_agent_key`)

The admin **cannot** move funds. Fund movement requires the agent's Ed25519 signature through `__check_auth`, which enforces the policy. The admin is a policy authority, not a fund authority.

## Does `set_policy` reset the rolling window?

No — not since [issue #289](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/289).
A policy *edit* (any `set_policy` while a policy is installed) **preserves the rolling
window and the dead-man-switch clock**: pausing or tightening a policy no longer hands the
agent a fresh budget or a fresh grace period. Accumulated spend keeps counting against the
new cap.

Only a *first* install (no policy stored — including an install after `revoke_policy`)
starts from an empty window with a freshly armed DMS clock: a genuinely new policy gets a
fresh window.

When a fresh budget really is the intent, the admin says so explicitly with
`reset_window()` — an admin-attested, idempotent call that zeroes the window and emits an
`event_window_reset` for the audit trail. See [set-policy](functions/set-policy.md) and
SPEC §5.1/§7.

## How do `pause` and `freeze` differ?

They are two different levers:

- `pause()` / `resume()` (issue #290) flip the *policy's* `paused` flag in place. The
  rolling window and the DMS clock are untouched. They bind only while a policy is
  installed. This is the routine halt/restart.
- `freeze()` / `unfreeze()` set the account-level `AdminFrozen` brake, which binds even a
  policyless account — the emergency lever. Note `unfreeze` also re-arms the
  dead-man-switch clock, while `resume` touches nothing but the flag.

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
