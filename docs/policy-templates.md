# Policy templates / presets — named starter configs for common operator personas

Every new operator faces a blank `PolicyConfig` with 11 fields and must learn the
semantics from [SPEC §8](../SPEC.md#8-config-validation-set_policy). This page documents
four named presets — copy-paste JSON installable via `set_policy` — for the most common
operator personas, each with a one-paragraph rationale and an explicit list of what it
does **not** protect against.

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

Each preset is valid JSON in the exact shape the `stellar` CLI expects for
`set_policy --config`. Copy the JSON block, substitute your own addresses, and:

```bash
stellar contract invoke --id GUARD_CONTRACT_ID --network testnet \
  --source-account guard_admin --send=yes -- set_policy --config '<PASTE JSON>'
```

A fresh `set_policy` resets the rolling window and starts the dead-man-switch clock at
install time (full grace). Invalid configs are rejected with `InvalidConfig` and leave
the existing policy unchanged (fail-closed, SPEC §8).

## The presets

### 1. Day-trader agent — high per-tx, tight window

**Rationale.** A high-frequency trading agent needs room to move: large per-transaction
caps and a tight rolling window so that even a fully-compromised agent key cannot drain
more than `window_cap` units inside any `window_secs` span. The dead-man grace matches
the window (5 minutes) so a frozen or killed trading agent stops spending almost
immediately, and a DEX protocol rule lets the agent call only the specific swap/liquidity
functions it needs — everything else is default-deny.

```json
{
  "active_from": 0,
  "active_until": 0,
  "allow_any_recipient": false,
  "assets": ["CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7"],
  "dms_grace_secs": 300,
  "paused": false,
  "per_tx_cap": "50000",
  "protocols": [
    {
      "contract": "CCYIRHS5OIVHEBKM27BDOPS6N3XKJSBQW2JAAV2F47GJH4C7ESLYGKVM",
      "fns": ["swap", "add_liquidity"]
    }
  ],
  "recipients": ["GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX"],
  "window_cap": "250000",
  "window_secs": 300
}
```

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

**Rationale.** A payroll/vendor payments bot sends known amounts to known recipients on
a schedule. Modest caps bound the blast radius of any single buggy run, the recipient
allowlist is the whole security model (only the payroll, vendor, and treasury addresses
can ever receive funds), and a 1-day dead-man grace tolerates a weekend outage without
freezing the account.

```json
{
  "active_from": 0,
  "active_until": 0,
  "allow_any_recipient": false,
  "assets": ["CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7"],
  "dms_grace_secs": 86400,
  "paused": false,
  "per_tx_cap": "1000",
  "protocols": [],
  "recipients": [
    "GBQ6OQUM5FTH7M5AU4PXFGB5GZXDF742E6ORZUP6UUJ6IHA653Z6LPQL",
    "GCR2RCC7QOFAHRNGHTAMQ4VZFXSG2ICZGL6DGW7X2OMKOJHY2MAWJANI"
  ],
  "window_cap": "10000",
  "window_secs": 3600
}
```

**What it does NOT protect against:**

- Payments to an allowlisted recipient that is itself compromised — the allowlist
  authorizes the *address*, not the legitimacy of the payment.
- A live, heartbeating attacker — still bounded to 10,000 units/hour and the two
  fixed recipients.
- Non-SAC protocol calls — `protocols` is empty, so every non-transfer contract call
  is default-deny (which is the point for a payments bot).
- Admin compromise (policy rewrite / key rotation; funds still cannot move).

### 3. Watch-only + heartbeat — paused baseline

**Rationale.** The safest possible baseline: `paused: true` blocks **every**
authorization — transfers, protocol calls, and even `heartbeat` (SPEC §4 gate #4 runs
before the self-call allowance in gate #6). Deploy in this posture while you audit the
agent, then flip to a live preset with a fresh `set_policy`. Caps are disabled and the
allowlists are empty, so even an unpause without further edits cannot move funds. The
7-day dead-man grace gives you a week to notice a silent account before it freezes.

```json
{
  "active_from": 0,
  "active_until": 0,
  "allow_any_recipient": false,
  "assets": [],
  "dms_grace_secs": 604800,
  "paused": true,
  "per_tx_cap": "0",
  "protocols": [],
  "recipients": [],
  "window_cap": "0",
  "window_secs": 86400
}
```

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

**Rationale.** For an account that should barely move: 100 units per transaction, 500
units per hour, a single cold-wallet recipient, and a 1-hour dead-man grace so silence
freezes the account within the hour. This is the right posture for a long-horizon
savings account an agent can top up but never meaningfully spend from.

```json
{
  "active_from": 0,
  "active_until": 0,
  "allow_any_recipient": false,
  "assets": ["CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7"],
  "dms_grace_secs": 3600,
  "paused": false,
  "per_tx_cap": "100",
  "protocols": [],
  "recipients": ["GCDCESJSIFS2K2MI5OIUWJUJZVEM2WM2PBEAZMFRC5QU7HVJETCXYC3G"],
  "window_cap": "500",
  "window_secs": 3600
}
```

**What it does NOT protect against:**

- A live, heartbeating attacker — still bounded to 500 units/hour to the one
  recipient; the dead-man switch fires only on silence.
- Slow drainage — 500 units/hour is a *cap*, not a monitoring alert; pair the policy
  with off-chain event monitoring (`auth_checked` events) if you need anomaly
  detection, not just ceilings.
- Admin compromise (policy rewrite / key rotation; funds still cannot move).
- Non-SAC protocol calls — default-deny via the empty `protocols` list.

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

## CI keeps this doc honest

`src/policy_preset_tests.rs` extracts every fenced `json` block from this document,
deserializes it into a `PolicyConfig`, installs it via `set_policy` against the real
contract in the Soroban test environment (running the production `validate_config`
path, SPEC §8), and reads the policy back to assert a faithful round-trip. If a preset
ever stops deserializing, stops validating, or stops round-tripping, `cargo test`
fails — doc rot cannot ship silently.

## See also

- [SPEC §8 — Config validation](../SPEC.md#8-config-validation-set_policy)
- [SPEC §5 — Dead-man switch](../SPEC.md#5-dead-man-switch--precise-definition)
- [set_policy function reference](functions/set-policy.md)
- [Enforcement scope](enforcement-scope.md) — what the policy can and cannot enforce
- [README — Public functions](../README.md#public-functions)
