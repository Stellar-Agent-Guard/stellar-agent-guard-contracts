# Reason glossary — what each "blocked" reason means, per observer

Every authorization decision on the guard account ends in one of the stable
`Error` reasons below. The same symbol is what the `auth_checked` events and
`check()` results emit (SPEC §9/§7), so off-chain consumers map one
vocabulary. For each reason this table gives the seat-specific read:

- **Agent** — the automated software holding the registered key that heartbeats
  and transacts. The agent column is guidance for the *next action* after a
  denial.
- **Operator** — the admin on-call. The operator column is an actionable
  remediation ("re-apply the key", not "investigate").
- **Auditor** — trust/compliance. The auditor column is the fact the reason
  attests *at time T* and where the evidence lives.

> **No-evasion rule (restated).** The agent column must never suggest routing
> around policy. When a reason fires, the agent's job is to stop, align with
> policy, or escalate to the operator — never to disguise, split, re-route, or
> otherwise circumvent a denied action to make it pass. Enforcement is
> on-chain and unbypassable; circumvention attempts fail anyway and only add
> incident noise. SDK middleware that turns the agent column into
> user-facing messages must reproduce this constraint verbatim.

> **Vocabulary note.** Issue planning and SPEC §7 quote 17 codes; the current
> enum in `src/types.rs` has 19 — `CreateContractNotAllowed` (28) was added
> after that count and is not yet reflected in SPEC §7 (tracked separately,
> see issue #132). This table covers every current enum variant exactly once.
> Blocked reasons from *rejected* frames live in the client-side event log /
> diagnostics, not in persisted ledger events (SPEC §9, issue #37) — the
> auditor column assumes that evidence source.

| reason symbol | code | what was attempted | agent guidance | operator action | auditor note | SPEC ref |
|---|---|---|---|---|---|---|
| `unauthorized` | 1 | A transaction signed by a key that does not match the registered `AgentPubkey`, or an admin call not authenticated as the admin. | Stop: signing key or host payload does not match registration. Re-derive, verify nonce/expiry, escalate. Never try alternate keys to force a pass. | Re-register the intended key via `rotate_agent_key`, or re-provision credentials. If intermittent, inspect node time and reserved-nonce handling. | Records a key/signature mismatch at the account; investigate any recurrence. | §7 (`__check_auth` step 1) |
| `already_initialized` | 2 | `initialize` called a second time (admin path). | Not agent-facing; if tooling surfaces it, treat as an idempotency note, not an error. | None; the account is already initialized. | Documents a double-init attempt (usually benign automation). | §7 |
| `not_initialized` | 3 | A call before `initialize` ran. | Not agent-facing. | Run `initialize` with the admin and the registered agent key. | Marks the pre-activation window where all calls were default-denied. | §7 |
| `invalid_config` | 4 | `set_policy` given a config that fails §8 validation. | Not agent-facing (admin op refused). | Correct the config per §8 (e.g. `window_cap != 0` requires `window_secs != 0`; no self-address in `assets`/`protocols`; no duplicate addresses) and re-apply. | The proposed policy was refused; the on-chain policy is unchanged (fail-closed). | §8 |
| `invalid_amount` | 5 | SAC transfer parsed with amount ≤ 0. | Fix the caller: zero/negative amounts are a client bug, not a policy limit. | Check the agent's code path is not emitting non-positive amounts; high frequency = noisy client. | Attests the account never admits a non-positive transfer. | §6.2 |
| `admin_frozen` | 10 | Any spend or heartbeat while the admin kill switch is set. | Halt immediately; do not retry until the operator clears. Heartbeat is blocked too — escalate. | Establish why the freeze was set, then `unfreeze()` (also re-arms `LastHeartbeat`). | A hard stop; the later `unfrozen` event is the admin's recovery attestation. | §4 rule 1, §5 |
| `heartbeat_expired` | 11 | Any call after the dead-man grace elapsed (agent silent longer than `dms_grace_secs`). | Cannot self-recover; notify the operator immediately and stop operations. | Verify agent liveness, then `unfreeze()` to re-arm `LastHeartbeat`; consider raising `dms_grace_secs`. | Proves the dead-man switch fired for the recorded silence window; reconcile with policy. | §4 rule 2, §5 |
| `no_policy` | 12 | Any spend while no policy is installed (revoked or never set). | Cease — default-deny is by design; request a policy from the operator. | Install a policy with `set_policy`. | At revoke time default-deny held; the later `policy_set` event is the record. | §4 rule 3 |
| `paused` | 13 | Any call while `paused` (momentary admin halt). | Suspend activity and poll `status()` at a reasonable interval until `paused` clears; do not route around. | Resume via `set_policy` with `paused = false` after maintenance. | Operator kill-switch usage; pairs with the re-open event. | §4 rule 4 |
| `outside_active_window` | 14 | A spend outside `active_from`/`active_until`. | Wait for the activity window; schedule operations inside it. | Correct the window bounds via `set_policy` if the timetable changed. | Attests spend stays within the declared activity window at T. | §4 rule 5 |
| `asset_not_allowed` | 20 | SAC transfer on an asset not in `assets`. | Only operate on policy-listed assets; read `policy()` before choosing. | Add the asset to `assets` if it is intended (admin-attested change). | Asset allowlist compliance at T. | §6.2 |
| `recipient_not_allowed` | 21 | SAC transfer to a recipient not in `recipients` (and not covered by `allow_any_recipient`). | Only send to allowlisted recipients. | Add the recipient, or consciously enable `allow_any_recipient`. | Recipient allowlist compliance at T. | §6.2 |
| `per_tx_cap_exceeded` | 22 | A single transfer above `per_tx_cap`. | Halt and escalate; do not retry immediately. Never split one intended payment into multiple smaller ones to dodge the cap — that is evasion and unsupported. | Raise `per_tx_cap` if the business need genuinely grew, or restate the limit. | Per-tx bound held at T (event + tx reference). | §3, §6.2 |
| `window_cap_exceeded` | 23 | A transfer that would push the rolling-window total over `window_cap`. | Wait for window entries to expire (`window_secs`) before retrying; escalate. Do not re-route spend outside the accounting path to evade the window. | Raise `window_cap` if legitimately needed, or reset cadence expectations. | Rolling cap held over the [T − `window_secs`, T] span (invariant, §3.1). | §3.1, §6.2 |
| `protocol_not_allowed` | 24 | A call to a contract not in `protocols`. | Only call allowlisted protocol contracts. | Add the protocol to the allowlist if intended. | Protocol allowlist compliance at T. | §6.3 |
| `function_not_allowed` | 25 | A call to a function not in the protocol's `fns` list. | Only call allowlisted functions. | Extend the per-protocol `fns` list if intended. | Function-level allowlist compliance at T. | §6.3 |
| `unknown_contract` | 26 | A call to a contract that is neither this account, an allowlisted asset, nor an allowlisted protocol. | Unknown contracts are default-deny in v1; consult `policy()` and do not attempt workarounds. | Allowlist the contract if it should be callable under v1 intent. | Default-deny held at T. | §6.4 |
| `self_function_not_allowed` | 27 | A call to one of the account's own functions outside the agent-allowed path (only `heartbeat` — and the `check` pre-flight — are agent-facing). | The agent may only call its own `heartbeat`; management functions belong to the admin seat. | Use the admin path for management; align tooling, no contract change needed. | Records the self-call surface being contained to the heartbeat/check path. | §6.1, §7 |
| `create_contract_not_allowed` | 28 | Authorizing a host `CreateContract` context. | The account never authorizes contract creation in v1 — route creation to a dedicated operator-owned account. | Create contracts from a non-guarded account. | Proves the account never authorizes creation. | §6.4, §7 (enum) |

## Consumers

- **SDK middleware** (`stellar-agent-guard-sdk`): `explainReason`/message
  content maps the agent column (with the no-evasion rule applied verbatim);
  the operator column drives the composer's remediation hints.
- **Dashboard / telemetry:** surfaces the operator column; the auditor column
  feeds export and audit-pack tooling.