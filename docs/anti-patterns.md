# Policy anti-patterns — unsafe-but-valid configurations and their safer alternatives

The guard validates a `PolicyConfig` against [SPEC §8](../SPEC.md#8-config-validation-set_policy),
not against good judgment. A policy that passes validation can still be unsafe:
the validator rejects *malformed* configs (`InvalidConfig`), but it deliberately
does not reject *risky intent*. A broad allowlist, a disabled cap, or an oversized
list is a legal configuration — the contract has no way to know the operator's
actual threat model. This page names the configurations that are valid but
dangerous, explains why the contract does not refuse them, and gives the safer
alternative for each.

This page complements, and does not replace, the [policy templates](policy-templates.md).
The templates show the recommended starting points; this page shows the mistakes to
avoid. Both share the same framing: the guard is an enforcement boundary, not a
fraud detector and not a custody layer (see [Enforcement scope](enforcement-scope.md)).

> ⚠️ **The contract cannot judge intent.** Every anti-pattern below is *admitted*
> by the engine. Treat this page as operator guidance, not as a promise that the
> contract will stop a risky configuration.

## 1. Broad `allow_any_recipient` with meaningful caps

**What it looks like.** Setting `allow_any_recipient: true` so the agent can pay
"whoever it needs to", while relying on `per_tx_cap` and `window_cap` as the only
controls.

**Why it is unsafe.** The recipient allowlist is the entire *authorization*
boundary for transfers. With `allow_any_recipient: true`, the caps bind the
*amount* per window but not the *destination*: a compromised or buggy agent can
drain up to `window_cap` every `window_secs` to any address an attacker chooses,
continuously. Caps are ceilings, not alarms — the contract rejects a violation
but does not page anyone (see the warnings on [policy templates](policy-templates.md)).

**Why the contract admits it.** `allow_any_recipient` is an explicit,
admin-attested feature. The validator cannot know whether the operator has a
legitimate reason to pay arbitrary recipients, so it refuses only the malformed
case (a self-address, a duplicate, a negative amount), not the broad one.

**Safer alternative.** Keep `allow_any_recipient: false` and enumerate the
recipients you actually expect to pay in `recipients`. When the destination set
is genuinely unbounded, reduce `window_cap` and `window_secs` so the maximum
sustained drain rate is bounded, and wire the `auth_checked` event stream into
off-chain monitoring — the cap limits the loss, the monitoring notices it.

## 2. Zero caps on a live, spend-capable policy

**What it looks like.** `per_tx_cap: 0` and `window_cap: 0` on a policy whose
agent is expected to transact, on the assumption that "0 means the lowest
possible limit".

**Why it is unsafe.** In this policy schema, `0` *disables* the corresponding
cap (see [`policy.schema.json`](../policy.schema.json): "0 disables it"). A
policy with both caps at zero and a non-empty `assets` list allows unlimited
SAC transfers within the allowlists — the only remaining gates are the account
level (freeze, dead-man switch, pause, active window). For a policy that is
meant to be spend-capable, this is the opposite of the intended posture.

**Why the contract admits it.** Zero is a legitimate value for an operator who
wants a pure allowlist policy with no numeric ceiling. The validator enforces
the *shape* (`window_cap != 0` implies `window_secs != 0`), not the
*risk appetite*.

**Safer alternative.** If you want a policy that can barely spend, use the
[max-security preset](policy-templates.md#4-max-security--tiny-caps-short-dms)
(100 units per transaction, 500 per hour) instead of zero. If you genuinely want
zero spend, use `paused: true` or leave `assets` empty — that blocks transfers
by default-deny rather than by disabling a cap, and it reads as intentional to
any reviewer. Reserve `0` caps for a policy where the allowlists alone are the
intended control and you have measured that risk.

## 3. Oversized lists (assets, recipients, protocols)

**What it looks like.** Enumerating hundreds of assets, recipients, or protocol
rules "to be safe", or pasting a large generated allowlist into `set_policy`.

**Why it is unsafe.** Large lists expand the attack surface and make review
impossible. A recipient list with hundreds of entries can no longer be audited
by eye; a stray entry is a live authorization the operator has forgotten. The
schema caps certain collections (`recipient_window_caps`, `asset_caps`, and
`blocked_recipients` have `maxItems: 256` in
[`policy.schema.json`](../policy.schema.json)), but `assets` and `recipients`
grow without a validator-imposed ceiling — the burden of keeping them
reviewable is on the operator. A wide list also defeats the point of default
deny: the more you allowlist, the closer you get to an allow-anything policy
with extra bookkeeping.

**Why the contract admits it.** The engine is designed to scan allowlists, not
to judge their size. A large list is neither malformed nor ambiguous to the
enforcement path, so there is nothing to reject.

**Safer alternative.** Enumerate the minimum set that the agent's actual job
requires, and keep the list in version control next to the policy so changes are
reviewed as diffs. For recipients that change frequently, prefer `allow_any_recipient`
*with a tight window cap* over a giant static list, and document which seats may
edit each list. Review the allowlist on every `set_policy` edit — an allowlist
entry is an authorization, not a bookmark.

## 4. Stale heartbeat (dead-man switch left unarmed or armed too loose)

**What it looks like.** Leaving `dms_grace_secs: 0` (dead-man switch disabled)
on a long-running agent, or setting a very long grace so that a silent,
compromised agent can keep spending for days.

**Why it is unsafe.** The dead-man switch is the only control that fires when
the agent *stops* heartbeating — it is what freezes the account after silence.
With `dms_grace_secs: 0` it is off: a lost agent key that was still valid, or an
agent that keeps transacting without the operator's knowledge, is bounded only by
the caps. A very long grace has the opposite failure: it tolerates operator
absence but also gives an attacker (or a runaway agent) a long window before the
account freezes. Both directions trade safety for convenience.

**Why the contract admits it.** `dms_grace_secs: 0` is the documented way to run
without the dead-man switch, and a long grace is a legitimate choice for an
operator who accepts the exposure. The validator checks the value's range, not
whether the trade-off is wise.

**Safer alternative.** Arm the switch with a production-appropriate grace. The
[policy templates](policy-templates.md) call for **≥ several days** in
production (SPEC §5) — long enough to tolerate restarts and operator absence,
short enough that silence is noticed. Pair the heartbeat with the `auth_checked`
event stream so that both silence *and* spend are observable. If you must run
with `dms_grace_secs: 0` (for example during the migration rehearsal in the
[migration guide](operations/migration-guide.md)), treat it as a temporary
posture and arm it as a deliberate later edit, not a permanent default.

## 5. Non-SAC protocol calls mistaken for spend enforcement

**What it looks like.** Assuming a `protocols` entry with a `fns` list gives the
same amount/recipient enforcement on a DEX or lending call as it does on a SAC
transfer.

**Why it is unsafe.** Fine-grained enforcement — recipient allowlist, per-tx cap,
rolling-window accounting — applies *only* to SAC `transfer`/`transfer_from`
calls. For arbitrary protocol calls the engine still enforces the account-level
gates (freeze, dead-man switch, pause, active window) and the
protocol/function allowlist, but it does **not** meter the amount or the
destination, because the auth context does not expose arbitrary call arguments
generically (see [Enforcement scope](enforcement-scope.md) and SPEC §2). An
operator who believes a swap call is capped at `per_tx_cap` has a false sense of
the boundary.

**Why the contract admits it.** This is a platform property, not a validator
gap: the `auth_contexts` argument exposes `contract`, `fn_name`, and raw `args`,
and only the fixed SAC interface has knowable argument positions.

**Safer alternative.** Model the risk correctly: a `protocols` entry authorizes
*which* contract and *which* functions the agent may call, not *how much* moves.
For protocol calls where the value moved matters, keep the protocol allowlist
narrow (one contract, the exact `fns` the agent needs), keep the caps and
allowlists tight on the SAC side, and monitor the off-chain event stream. Treat
fine-grained protocol-call metering as a v2 item, not as something the current
policy provides.

## Summary

| Anti-pattern | The wrong instinct | The right control |
|---|---|---|
| Broad `allow_any_recipient` | "caps alone are enough" | enumerate `recipients`, or tighten the window and add monitoring |
| Zero caps on a spend policy | "0 means lowest" | use the max-security preset, or `paused`/empty `assets` |
| Oversized allowlists | "list everything to be safe" | minimum viable set, reviewed as diffs |
| Stale heartbeat | "grace 0 / very long is simpler" | arm with a production grace (≥ days) and watch the events |
| Protocol calls as spend caps | "allowlisted call is capped" | allowlist is `contract`/`fns`, not amount — narrow it and monitor |

Each anti-pattern is valid configuration that the contract will accept. The guard
enforces what you *told* it, not what you *meant*; the difference is the operator's
job to close.

## See also

- [Policy templates](policy-templates.md) — the recommended starting points, with
  explicit "what it does NOT protect against" for each preset.
- [Enforcement scope](enforcement-scope.md) — the SAC-vs-protocol boundary in detail.
- [Reason glossary](reason-glossary.md) — what each denial reason means per seat.
- [SPEC §8 — Config validation](../SPEC.md#8-config-validation-set_policy)
- [SPEC §2 — Enforcement scope](../SPEC.md#2-enforcement-scope--sac-token-calls-vs-every-other-soroban-call-required-framing)
