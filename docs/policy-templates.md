# Policy templates / presets — named starter configs for common operator personas

Every new operator faces a blank `PolicyConfig` and must learn the semantics from
[SPEC §8](../SPEC.md#8-config-validation-set_policy). This page documents six named
presets for the most common operator personas and incident postures, each with a
one-paragraph rationale and an explicit list of what it does **not** protect against.
The presets themselves are loadable JSON files in
[`examples/policies/`](../examples/policies/) — that directory, not this page, is the
source of truth. A CI test discovers every file there, validates it against
`policy.schema.json`, and installs it via `set_policy`.

> ⚠️ **Read first — these are unaudited starting points, not security advice.**
>
> - **Unaudited code.** This contract is unaudited security tooling that gates real
>   fund access. Do not deploy to mainnet without an independent audit. See
>   [SECURITY.md](../SECURITY.md) and the README disclaimer.
> - **Mainnet.** Every preset below is written for **testnet** evaluation. The example
>   addresses are either the real Phase-1 testnet fixture addresses (the SAC token
>   `CBLQLJAG…` and recipient `GDUYLF…`) or clearly-marked placeholder strkeys with valid
>   checksums — replace them with your own asset, recipient, and protocol addresses
>   before any real deployment.
> - **DMS grace.** The short grace values (minutes) exist so the dead-man switch is
>   observable in testing. **Production guidance is ≥ several days** (SPEC §5) — a
>   multi-day grace tolerates agent restarts and operator absence without freezing the
>   account. Raise `dms_grace_secs` accordingly before mainnet.

## How to install a preset

Each preset file is valid JSON in the exact shape the `stellar` CLI expects for
`set_policy --config`. Copy the file, substitute your own addresses, and:

```bash
stellar contract invoke --id GUARD_CONTRACT_ID --network testnet \
  --source-account guard_admin --send=yes -- set_policy --config '<PASTE JSON>'
```

A *first* `set_policy` (no policy stored — including after `revoke_policy`) starts an
empty rolling window and arms the dead-man-switch clock at install time (full grace). A
policy *edit* preserves both the window and the clock (issue #289); use `reset_window()`
for an explicit, admin-attested window reset. Invalid configs are rejected with
`InvalidConfig` and leave the existing policy unchanged (fail-closed, SPEC §8).

## The presets

### 1. Day-trader agent — high per-tx, tight window

**File:** [`examples/policies/day-trader-agent.json`](../examples/policies/day-trader-agent.json)

**Rationale.** A high-frequency trading agent needs room to move: large per-transaction
caps and a tight rolling window so that even a fully-compromised agent key cannot drain
more than `window_cap` units inside any `window_secs` span. The dead-man grace matches
the window (5 minutes) so a frozen or killed trading agent stops spending almost
immediately, and a DEX protocol rule lets the agent call only the specific swap/liquidity
functions it needs — everything else is default-deny.

**What it does NOT protect against:**

- A live attacker who keeps the agent key heartbeating — the caps still bind them to
  250,000 units per 5-minute window; the dead-man switch only fires on *silence*
  (SPEC §5, §10).
- Fine-grained amount/recipient limits on non-SAC protocol calls (v2 item) — the DEX
  rule allowlists functions, not arguments.
- Admin compromise — the admin can rewrite the policy or rotate the agent key (that is
  its function; it still cannot move funds).
- Transfers to an allowlisted recipient that is itself compromised — the recipient
  allowlist is an authorization boundary, not a judgment of the recipient's security.

### 2. Payments bot — fixed recipients, modest caps

**File:** [`examples/policies/payments-bot.json`](../examples/policies/payments-bot.json)

**Rationale.** A payroll/vendor payments bot sends known amounts to known recipients on
a schedule. Modest caps bound the blast radius of any single buggy run, the recipient
allowlist is the whole security model (only the payroll, vendor, and treasury addresses
can ever receive funds), and a 1-day dead-man grace tolerates a weekend outage without
freezing the account.

**What it does NOT protect against:**

- Payments to an allowlisted recipient that is itself compromised — the allowlist
  authorizes the *address*, not the legitimacy of the payment.
- A live, heartbeating attacker — still bounded to 10,000 units/hour and the two
  fixed recipients.
- Non-SAC protocol calls — `protocols` is empty, so every non-transfer contract call
  is default-deny (which is the point for a payments bot).
- Admin compromise (policy rewrite / key rotation; funds still cannot move).

### 3. Watch-only + heartbeat — paused baseline

**File:** [`examples/policies/watch-only-heartbeat.json`](../examples/policies/watch-only-heartbeat.json)

**Rationale.** The safest possible baseline: `paused: true` blocks **every**
authorization — transfers, protocol calls, and even `heartbeat` (SPEC §4 gate #4 runs
before the self-call allowance in gate #6). Deploy in this posture while you audit the
agent, then flip to a live preset with a fresh `set_policy`. Caps are disabled and the
allowlists are empty, so even an unpause without further edits cannot move funds. The
7-day dead-man grace gives you a week to notice a silent account before it freezes.

**Operational note.** Because `paused` blocks `heartbeat` too, the account will
dead-man-freeze after the grace period and stay frozen until the admin runs `unfreeze`
*and* installs a policy with `paused: false`. If you want the agent to keep
heartbeating while spending stays impossible, drop `paused` to `false` — the empty
`assets`/`recipients` lists still block every transfer.

**What it does NOT protect against:**

- Nothing on the spend side — every authorization is blocked by design.
- Admin compromise — the admin can unpause and rewrite the policy (funds still cannot
  move without allowlists and caps of the admin's choosing).
- Loss of the admin key — a frozen account needs the admin's `unfreeze`; without the
  admin key the account is permanently frozen (no admin = no reversal path).

### 4. Max security — tiny caps, short DMS

**File:** [`examples/policies/max-security.json`](../examples/policies/max-security.json)

**Rationale.** For an account that should barely move: 100 units per transaction, 500
units per hour, a single cold-wallet recipient, and a 1-hour dead-man grace so silence
freezes the account within the hour. This is the right posture for a long-horizon
savings account an agent can top up but never meaningfully spend from.

**What it does NOT protect against:**

- A live, heartbeating attacker — still bounded to 500 units/hour to the one
  recipient; the dead-man switch fires only on silence.
- Slow drainage — 500 units/hour is a *cap*, not a monitoring alert; pair the policy
  with off-chain event monitoring (`auth_checked` events) if you need anomaly
  detection, not just ceilings.
- Admin compromise (policy rewrite / key rotation; funds still cannot move).
- Non-SAC protocol calls — default-deny via the empty `protocols` list.

### 5. Least privilege — one asset, one recipient, one protocol function

**File:** [`examples/policies/least-privilege.json`](../examples/policies/least-privilege.json)

**Rationale.** The narrowest active operating posture for an agent that needs both a
bounded SAC transfer rail and a single protocol interaction: one allowlisted asset
(`assets` of length 1), one allowlisted recipient (`recipients` of length 1 with
`allow_any_recipient: false`), and one allowlisted protocol contract restricted to a
single function (`fns: ["swap"]`, capped at `protocol_calls_per_window: 10` per hour).
Tight spend ceilings (`per_tx_cap: "100"`, `window_cap: "500"` over `window_secs: 3600`)
bound the blast radius of a compromised agent key, and `dms_grace_secs: 3600` freezes
the account if the agent goes silent. Every other asset, recipient, protocol contract,
protocol function, or non-transfer SAC function (`mint`, `burn`, `clawback`, etc.) is
default-deny.

**What it does NOT protect against:**

- Arbitrary amounts or destinations inside the single allowlisted protocol function
  (`swap`) — non-SAC argument inspection is a v2 item ([SPEC §2](../SPEC.md#2-enforcement-scope--sac-token-calls-vs-every-other-soroban-call-required-framing)).
- A live, heartbeating attacker using the agent key within the 100/tx, 500/hour, and
  10-protocol-calls/hour bounds.
- Compromise of the single allowlisted recipient or protocol contract itself.
- Admin compromise (policy rewrite / key rotation; no admin call moves funds directly).

### 6. Emergency freeze — incident lockdown

**File:** [`examples/policies/emergency-freeze.json`](../examples/policies/emergency-freeze.json)

**Rationale.** An incident-response lockdown policy meant to be paired with the admin's
immediate `freeze()` call when an agent key or runtime is suspected compromised. It sets
`paused: true` (blocking every authorization, including `heartbeat`, at SPEC §4 gate #4)
and clears `assets`, `recipients`, `protocols`, and `allow_any_recipient` so that even
an accidental `resume()` or `unfreeze()` before a vetted policy is reinstalled leaves
every transfer and protocol call default-denied (`UnknownContract`). Setting
`dms_grace_secs: 0` avoids stacking a separate `heartbeat_expired` gate on top of
`admin_frozen`/`paused` while operators investigate and rotate keys.

**Operational note.** During an incident, call `freeze()` first for an immediate
account-level halt (without touching spend history), then optionally install
`emergency-freeze.json` if you also want the stored policy stripped to zero permissions
before rotating keys and restoring a vetted policy. See the
[emergency freeze sequence](operations/incident-playbook-admin-key-lost.md#emergency-freeze-sequence-when-the-admin-key-is-available)
and the [rollback and policy-recovery runbook](operations/rollback-and-recovery.md#1-pause)
for verification and recovery steps.

**What it does NOT protect against:**

- Loss of the admin key — an admin-frozen or paused account can only be recovered by
  the admin (`unfreeze()` / `resume()` / `set_policy()`); see the
  [incident playbook](operations/incident-playbook-admin-key-lost.md).
- Admin compromise — an attacker with the admin key can unfreeze and install a permissive
  policy.
- Transactions already finalized on-ledger before `freeze()` or `set_policy()` landed.

## Warnings that apply to every preset

- **Unaudited.** This contract is unaudited security tooling. Independent audit before
  mainnet is not optional.
- **Mainnet.** Presets ship with testnet fixture addresses and short DMS grace values
  for observability. Production deployments need real addresses and `dms_grace_secs` of
  **≥ several days** (SPEC §5).
- **Caps are ceilings, not alarms.** The contract rejects violations; it does not page
  anyone. Wire the `auth_checked` event stream into monitoring if you want alerts.
- **The admin key is a real trust root.** It can rewrite the policy, rotate the agent
  key, and freeze/unfreeze the account. Guard it like a key that can reconfigure the
  firewall — because that is what it is.

## CI keeps these files honest

`src/policy_preset_tests.rs` discovers every `*.json` file in
[`examples/policies/`](../examples/policies/), deserializes it into a `PolicyConfig`,
installs it via `set_policy` against the real contract in the Soroban test environment
(running the production `validate_config` path, SPEC §8), and reads the policy back to
assert a faithful round-trip. `tests/policy_schema.rs` separately validates every file
against [`policy.schema.json`](../policy.schema.json). If a preset stops parsing, stops
validating, or stops round-tripping, `cargo test` fails — preset rot cannot ship
silently, and adding a file without validation is impossible because discovery is
dynamic.

## See also

- [SPEC §8 — Config validation](../SPEC.md#8-config-validation-set_policy)
- [SPEC §5 — Dead-man switch](../SPEC.md#5-dead-man-switch--precise-definition)
- [set_policy function reference](functions/set-policy.md)
- [Enforcement scope](enforcement-scope.md) — what the policy can and cannot enforce
- [README — Public functions](../README.md#public-functions)
