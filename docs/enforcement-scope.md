# Enforcement Scope

This page states the exact enforcement boundary for v1. This is not a gap to close before shipping — it is a documented boundary stated honestly.

## The confirmed scope

Full recipient/amount enforcement — spend caps, allowlists, per-transaction limits — is native and automatic for SAC token transfers (`transfer`/`transfer_from`), since these are the calls whose arguments the Soroban auth context exposes for inspection. For other Soroban contract calls, per-call amount/recipient limits are not yet enforced — full statement: [SPEC §2](../SPEC.md#2-enforcement-scope--sac-token-calls-vs-every-other-soroban-call-required-framing), the canonical scope wording. The rest of this page elaborates that statement; it does not restate it.

This boundary is an inherent property of the platform (the auth context does not expose arbitrary call arguments generically), not a gap this project hides or overclaims.

## Why this boundary exists

The `auth_contexts` argument to `__check_auth` exposes `contract`, `fn_name`, and raw `args` for every call the account authorizes. The Stellar Asset Contract interface is fixed and known, so for SAC token calls the arguments are meaningful:

- `transfer(from, to, amount)` — recipient at args[1], amount at args[2]
- `transfer_from(from, spender, to, amount)` — recipient at args[2], amount at args[3]

No other Soroban contract exposes a fixed, knowable argument schema, and per-call value moved is frequently a return value or an internal effect that is not readable at authorization time.

This is the same boundary observed in the broader Soroban ecosystem: OpenZeppelin's Soroban `spending_limit` plugin likewise only meters transfer contexts and rejects non-transfer calls outright.

## What IS enforced for all calls

For **every** call the guarded account makes — SAC transfers, protocol calls, and self-calls — these gates apply equally:

- ✅ Admin freeze check
- ✅ Dead-man switch check
- ✅ Pause check
- ✅ Active window check
- ✅ Protocol/function allowlist check (default-deny: unlisted contracts blocked)
- ✅ Self-call restriction (only `heartbeat` allowed)

## What is enforced ONLY for SAC transfers

These apply exclusively to `transfer`/`transfer_from` calls on allowlisted assets:

- ✅ Recipient allowlist
- ✅ Per-transaction amount cap
- ✅ Rolling window spend accounting
- ✅ Amount > 0 validation

## What is NOT enforced for non-SAC calls

For arbitrary protocol calls (DEX swaps, lending operations, etc.):

- ❌ Per-call amount limits (the amount is not available in the auth context)
- ❌ Recipient limits (the recipient is not interpretable from arbitrary call args)
- ❌ Rolling-window spend accounting

## The two-tier summary

| Enforcement | SAC transfers | Protocol calls |
|---|---|---|
| Contract allowlist | ✅ (`assets`) | ✅ (`protocols`) |
| Function allowlist | ✅ (transfer/transfer_from only) | ✅ |
| Recipient allowlist | ✅ | ❌ |
| Per-tx amount cap | ✅ | ❌ |
| Rolling window cap | ✅ | ❌ |
| Pause | ✅ | ✅ |
| Active window | ✅ | ✅ |
| Admin freeze | ✅ | ✅ |
| Dead-man switch | ✅ | ✅ |
| Default deny | ✅ | ✅ |

## v2 tracking

Extending fine-grained enforcement to arbitrary Soroban calls is tracked as a v2 item. The classification that produces this boundary (`AssetTransfer` vs `Protocol` vs `Unknown` default-deny) is spelled out in the [Architecture](architecture.md) page.

## Framing rules

The canonical scope wording lives in SPEC §2; this page, like the README,
quotes it briefly and links there (CONTRIBUTING rule 2). When writing about
scope, follow these framing rules:

- **Do not** write unqualified claims like "enforces spend limits on any Soroban call" or "protocol-level enforcement for all contract interactions" — these overclaim what v1 actually does.
- **Do not** undersell it either (e.g., burying the limitation in a footnote after a headline claim that reads as unconditional) — the limitation belongs in the same paragraph as the capability claim.
- **Do** state the accurate framing in the same paragraph as the capability claim, not appended as a caveat elsewhere.
