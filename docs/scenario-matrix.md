# Scenario matrix — every decision-table row × every call kind

This is the enforcement truth table for `stellar-agent-guard-contracts`, written as one
table instead of something you have to reconstruct by mentally combining SPEC §4 and
SPEC §6. Its second job is to answer **"are we tested?"** as a read rather than a guess:
every cell in [Table 1](#2-table-1--decision-matrix) is cross-referenced in
[Table 2](#3-table-2--coverage-map) to the test that pins it, and every cell with no
pinning test is named in the [gap list](#4-known-coverage-gaps).

Audience: **contributor**. Nothing here changes behavior — it is a documentation map of
what `src/engine.rs` already does and what the test suite already asserts.

- [1. How to read the matrix](#1-how-to-read-the-matrix)
- [2. Table 1 — decision matrix](#2-table-1--decision-matrix)
- [3. Table 2 — coverage map](#3-table-2--coverage-map)
- [4. Known coverage gaps](#4-known-coverage-gaps)
- [5. Test index](#5-test-index)
- [6. Findings for maintainers](#6-findings-for-maintainers)

---

## 1. How to read the matrix

### 1.1 The two axes

**Rows** are the seven rules of the SPEC §4 decision table, in the order `decide()` applies them.
Rules 1–5 are *transaction-level* gates; rule 6 admits self-calls; rule 7 classifies.

**Columns** are the six call kinds of SPEC §6, as materialised by the `ParsedCall` enum
(`src/types.rs`) and produced by `parse_call` (`src/engine.rs`):

| key | call kind | `ParsedCall` variant | SPEC ref |
|---|---|---|---|
| **K1** | self | `SelfCall { fname }` | §6.1 |
| **K2** | asset transfer (`transfer` / `transfer_from` on an allowlisted SAC) | `AssetTransfer { asset, to, amount }` | §6.2 |
| **K3** | asset other-fn (`mint`, `burn`, `set_admin`, … on an allowlisted SAC) | `AssetOther { asset, fname }` | §6.2 |
| **K4** | protocol (allowlisted non-asset contract) | `Protocol { contract, fname }` | §6.3 |
| **K5** | create-contract (host-function contract creation) | `CreateContract` | §2, §6.4 |
| **K6** | unknown (not self, not allowlisted asset, not allowlisted protocol) | `Unknown { contract, fname }` | §6.4 |

K5 is the one kind with no dedicated §6 subsection: the host hands contract creation to
`__check_auth` as `Context::CreateContractHostFn` / `CreateContractWithCtorHostFn`, and
`parse_call` maps both to `CreateContract`. It is listed here because it is a real
authorization context an account can be asked to approve, and it has its own reason
`CreateContractNotAllowed`.

### 1.2 Cell vocabulary

| cell | meaning |
|---|---|
| `` `reason_symbol` `` | this cell's first-match outcome is a block with that SPEC §7 / `Error::reason()` symbol |
| **pass** | this cell admits the call (assuming every earlier row passes) |
| `n/a` | **the rule's condition cannot match this kind** — see §1.3 |

`n/a` is *not* a gap. It is a structural fact: rule 6 only fires for K1, and rule 7 only
runs once rules 1–6 have passed. The one class of `n/a` that *is* a gap is an empty
`n/a`-free cell in [Table 2](#3-table-2--coverage-map), which is what the gap list enumerates.

### 1.3 Precedence notes (read before trusting any single cell)

1. **First match wins, and gates 1–5 precede classification.** Rules 1–5 are evaluated once
   per authorization, before any context is parsed. That is why their row in Table 1 is
   *identical across all six columns*: freeze / dead-man / no-policy / pause / active-window
   bind **every** call kind, SAC or protocol. This is the SPEC §6 "boundary stated exactly"
   paragraph, expressed as a table rather than a paragraph.
2. **Rules 1–5 are therefore `n/a` *as classification*, not `n/a` as outcome.** The gate does
   not merely fail to apply — it is *not reached* for the classification logic. A call
   blocked at rule 1 is never parsed, never matched against an allowlist, and never touches
   the rolling window.
3. **Rule 3 (`NoPolicy`) is evaluated before rule 1 (`AdminFrozen`) in code.** `decide()`
   destructures `policy: Option<&PolicyConfig>` first and returns `NoPolicy` before it reads
   `state.admin_frozen`. SPEC §4 numbers `AdminFrozen` as rule 1, so for the
   *no-policy + frozen* combination the spec implies `admin_frozen` and the code returns
   `no_policy`. See [finding F-1](#f-1-rule-order-no_policy-precedes-adminfrozen-in-code).
4. **Rule 6 admits `heartbeat` only, not `check`.** SPEC §4 rule 6 lists "(heartbeat, check)";
   `decide()` permits only `heartbeat`, everything else on the account's own address
   returns `SelfFunctionNotAllowed`. `check`/`check_detailed` are views that do not
   `require_auth`, so they never appear in `auth_contexts` in practice — the discrepancy
   is in the spec text, not observable in behavior. See [finding F-4](#f-4-rule-6-names-check-which-the-engine-does-not-admit).
5. **The window is pruned once, up front, and committed only if every context passes.**
   A `Blocked` decision leaves the ledger untouched (`src/window.rs`), so a denied call can
   never spend the window. This is what makes the K2 column's "no partial commit" claim
   testable, and it is pinned by `E-7`.

---

## 2. Table 1 — decision matrix

Rows = SPEC §4 decision-table rules. Columns = SPEC §6 call kinds. Cell = the expected
first-match outcome of that (rule, kind) pair. This is the "enforcement truth table" the
issue asks for: 7 × 6 = **42 cells, all filled**.

| SPEC §4 rule | K1 self | K2 asset transfer | K3 asset other-fn | K4 protocol | K5 create-contract | K6 unknown |
|---|---|---|---|---|---|---|
| **1.** `AdminFrozen` set | `admin_frozen` ᴬ | `admin_frozen` ᴬ | `admin_frozen` ᴬ | `admin_frozen` ᴬ | `admin_frozen` ᴬ | `admin_frozen` ᴬ |
| **2.** dead-man grace elapsed | `heartbeat_expired` ᴬ | `heartbeat_expired` ᴬ | `heartbeat_expired` ᴬ | `heartbeat_expired` ᴬ | `heartbeat_expired` ᴬ | `heartbeat_expired` ᴬ |
| **3.** no `Policy` stored | `no_policy` ᴬ | `no_policy` ᴬ | `no_policy` ᴬ | `no_policy` ᴬ | `no_policy` ᴬ | `no_policy` ᴬ |
| **4.** `paused` | `paused` ᴬ | `paused` ᴬ | `paused` ᴬ | `paused` ᴬ | `paused` ᴬ | `paused` ᴬ |
| **5.** outside active window | `outside_active_window` ᴬ | `outside_active_window` ᴬ | `outside_active_window` ᴬ | `outside_active_window` ᴬ | `outside_active_window` ᴬ | `outside_active_window` ᴬ |
| **6.** self-call admission | **pass** (`heartbeat`) / `self_function_not_allowed` (any other fname) | `n/a` | `n/a` | `n/a` | `n/a` | `n/a` |
| **7.** per-context classification | `self_function_not_allowed` | `invalid_amount` → `recipient_not_allowed` → `per_tx_cap_exceeded` → `window_cap_exceeded` → **pass** ᴮ | `function_not_allowed` | `function_not_allowed` / **pass** | `create_contract_not_allowed` | `unknown_contract` |

ᴬ = **kind-independent by construction.** The rule's condition is evaluated on account
state, not on the parsed call, so it is checked before any context is parsed and yields
the same reason for every kind. The value of these six identical rows is precisely that
they are *uniform*: no call kind escapes freeze, dead-man, no-policy, pause, or the active
window. Pinning evidence for that uniformity is in Table 2 — and it is where the gaps live.

ᴮ = K2's rule-7 chain is ordered *within* rule 7. The rules are checked in this order and
the first failure is returned: `amount <= 0` is rejected as malformed input before any
policy limit is consulted, recipient admissibility is checked before the per-tx cap, and
the rolling window is checked last because it is the only rule that mutates state. A
transfer that clears all four is admitted and its amount is added to the window ledger.

> **Reading rule 5's row, especially the K6 column.** Every cell says
> `outside_active_window`, including K6 (`unknown`). An unknown contract is *not* exempt
> from the active window just because it would be blocked at rule 7 anyway: rule 5 runs
> first, so a call made outside the window reports `outside_active_window`, and the reason
> an operator sees in the `auth_checked` event depends on which gate fired first. Uniformity
> here is the point — it is the same claim the SPEC §6 boundary paragraph makes, in a form
> that can be checked cell by cell.

---

## 3. Table 2 — coverage map

Same grid as Table 1. Each cell names the test that **pins** that outcome, or `— gap`
with a pointer into the [gap list](#4-known-coverage-gaps). Keys resolve in
[Test index](#5-test-index). `E` = pure engine unit test (`src/engine.rs`),
`I` = on-chain integration test through the host auth flow (`src/integration_tests.rs`),
`W` = window-ledger test (`src/window.rs`).

| SPEC §4 rule | K1 self | K2 asset transfer | K3 asset other-fn | K4 protocol | K5 create-contract | K6 unknown |
|---|---|---|---|---|---|---|
| **1.** `AdminFrozen` | — gap **G5** | `E-9` `I-13` | — gap **G3** | — gap **G3** | — gap **G3** | — gap **G3** |
| **2.** `HeartbeatExpired` | `E-10` `I-12` | `E-9` `I-12` | — gap **G4** | — gap **G4** | — gap **G4** | — gap **G4** |
| **3.** `NoPolicy` | — gap **G6** | `E-1` `I-7` `I-18` | — gap **G6** | — gap **G6** | — gap **G6** | — gap **G6** |
| **4.** `Paused` | — gap **G7** | `E-9` | — gap **G7** | — gap **G7** | — gap **G7** | — gap **G7** |
| **5.** `OutsideActiveWindow` | — gap **G1** | — gap **G1** | — gap **G1** | — gap **G1** | — gap **G1** | — gap **G1** |
| **6.** self-call admission | `E-10` `E-11` | `n/a` | `n/a` | `n/a` | `n/a` | `n/a` |
| **7.** classification | `E-10` `E-11` | `E-2` `E-3` `E-4` `E-5` `E-6` `E-7` `E-8` `I-8` `I-9` `I-10` `I-11` `I-4` | — gap **G8** | `E-8` | — gap **G9** | `E-5` `E-8` |

### 3.1 Coverage by call kind (rows = call kinds, columns = gates)

The same information rolled up per kind — this is the view that answers "which gates are
untested *for the thing I am touching*".

| kind | frozen | dead-man | no-policy | paused | active-window | self-fn | classification | pinned cells |
|---|---|---|---|---|---|---|---|---|
| **K1** self | — | `E-10` `I-12` | — | — | — | `E-10` `E-11` | `E-10` `E-11` | 4 / 7 |
| **K2** asset transfer | `E-9` `I-13` | `E-9` `I-12` | `E-1` `I-7` `I-18` | `E-9` | — | `n/a` | `E-2`…`E-8`, `I-4`, `I-8`…`I-11` | 6 / 7 |
| **K3** asset other-fn | — | — | — | — | — | `n/a` | — | **0 / 7** |
| **K4** protocol | — | — | — | — | — | `n/a` | `E-8` | 1 / 7 |
| **K5** create-contract | — | — | — | — | — | `n/a` | — | **0 / 7** |
| **K6** unknown | — | — | — | — | — | `n/a` | `E-5` `E-8` | 1 / 7 |

K2 is the well-covered kind, which is the correct shape for v1: SAC transfers are the
calls whose arguments are interpretable, so they are the ones with the most enforcement
attached. The thin rows are where the roadmap is.

### 3.2 Rule 7 sub-rules for K2, in engine check order

Because K2 is the only kind with a multi-step rule-7 chain, its individual rules are
broken out here so a contributor changing one knows exactly which test protects it.

| K2 sub-rule (SPEC §6.2) | reason | pinning test |
|---|---|---|
| `amount > 0` | `invalid_amount` | — gap **G10** |
| `allow_any_recipient` or `recipient ∈ recipients` | `recipient_not_allowed` | `E-4` `I-10` `I-11` |
| `amount <= per_tx_cap` (when `per_tx_cap != 0`) | `per_tx_cap_exceeded` | `E-3` `I-8` |
| `prune(window_secs)`, then `total + pending + amount <= window_cap` | `window_cap_exceeded` | `E-6` `E-7` `W-1` `W-2` `I-9` |
| blocked ⇒ ledger unchanged (no partial commit) | — | `E-7` `I-8` `I-19` |
| all four cleared | **pass** | `E-2` `I-4` |

---

## 4. Known coverage gaps

Every gap below is a cell in Table 2 with no pinning test. They are enumerated, not
hidden — the point of this document is that the roadmap is legible. Each is written as a
suggested test, sized for a contributor picking up a first issue.

### G1 — rule 5 `OutsideActiveWindow`: no test at all, for any kind

**Severity: highest.** `outside_active_window` is the only account-level gate with **zero**
decision tests. No test in `src/engine.rs` or `src/integration_tests.rs` ever sets a
non-zero `active_from` or `active_until` and calls `decide()`; the only places the symbol
appears are `error_and_block_reason_round_trip` (`I-19`, a symbol round-trip that never
constructs a decision) and the `benches/denial_path_gas.rs` cost measurement, which
**prints** its numbers and asserts nothing.

That means the `now < active_from` / `now > active_until` boundary condition — including
the off-by-one at each edge — is currently unpinned behavior on a gate that blocks real
spends.

> **Suggested test:** an engine unit test that walks a fixed `now` across a policy with
> `active_from = t0`, `active_until = t1`, asserting `pass` at `t0` and `t1` and
> `OutsideActiveWindow` at `t0 - 1` and `t1 + 1`; plus an on-chain test that a spend
> outside the window is blocked *without* touching the window ledger. `src/window.rs`
> already has `exact_boundary_semantics` (`W-4`) for the analogous window edge — mirror it.

### G2 — rule 4 `Paused` is pinned only for K2, and only at the unit layer

`E-9` asserts `paused` blocks an asset transfer through the pure engine. There is **no
integration test** for `paused` on any kind, so the on-chain path (host auth flow,
`auth_checked` event emission, ledger untouched) is unpinned for the admin kill switch.

> **Suggested test:** an integration test that sets `paused = true` via `set_policy` and
> asserts a transfer and a heartbeat are both blocked, then `paused = false` and both
> pass.

### G3 — rule 1 `AdminFrozen` × {K3, K4, K5, K6}

`I-13` proves freeze blocks a **K2** transfer. Nothing proves it binds the other kinds.
Given SPEC §6's "boundary stated exactly" claim — that freeze applies to *every* call the
account makes — this is the highest-value gap in the list: it is the cell most likely to
be silently broken by a future refactor of `parse_call` or of the pre-gate ordering.

> **Suggested test:** extend `E-9` to iterate the kinds (or add a single test that runs
> `decide()` with `admin_frozen = true` over a self, protocol, create-contract, and
> unknown context and asserts `AdminFrozen` for all four).

### G4 — rule 2 `HeartbeatExpired` × {K3, K4, K5, K6}

Same shape as G3, for the dead-man switch. `E-10` pins heartbeat (K1) and `E-9`/`I-12` pin
transfer (K2); the other four kinds are unpinned.

> **Suggested test:** same iteration as G3 with a stale `last_heartbeat`. Worth pairing
> with G3 in one "transaction-level gates bind every kind" test module.

### G5 — rule 1 `AdminFrozen` × K1 (self)

`I-13` blocks transfers under freeze but not heartbeats. The SPEC §5 / reason-glossary
claim that a frozen account's heartbeat is blocked too is currently unpinned.

> **Suggested test:** assert `heartbeat_expect_blocked()` while frozen, before the
> `unfreeze` half of `I-13`.

### G6 — rule 3 `NoPolicy` × {K1, K3, K4, K5, K6}

`no_policy` is pinned for K2 by `E-1`, `I-7`, and `I-18` — including the revoke path in
`I-18`, which is the more interesting half. The other five kinds are unpinned, including
**K1**: whether a heartbeat is blocked with no policy installed is a real semantic question
(a policy-less account arguably has no `dms_grace_secs` to enforce, so dead-man cannot
fire either) and nothing states the answer.

> **Suggested test:** one test over the six kinds asserting `NoPolicy` uniformly; add the
> K1 case to the table above once the answer is confirmed by a maintainer.

### G7 — rule 4 `Paused` × {K1, K3, K4, K5, K6}

See G2. Unpinned on-chain for every kind, and unit-pinned for none but K2.

### G8 — rule 7 × K3 (`AssetOther` → `function_not_allowed`)

`AssetOther` is constructed by `parse_call` for a non-`transfer`/`transfer_from` call on an
allowlisted asset, and `decide()` blocks it with `FunctionNotAllowed`. **No test
constructs that context.** The only `FunctionNotAllowed` assertions (`E-8`) exercise the
*protocol* function-allowlist path, which is a different arm of the same `match`.

This matters more than the missing assertion suggests: K3 is the arm that stops an agent
from calling `mint`/`burn`/`clawback` on a SAC the account is otherwise allowed to
transfer, which is a fund-safety-relevant boundary.

> **Suggested test:** an engine test calling `decide()` with `proto_ctx`-style context
> pointed at an **allowlisted asset** with `fname = "mint"`, asserting
> `FunctionNotAllowed`. Note the helper `transfer_ctx` in `E`'s module makes this a
> one-line addition; the assertion must target the asset address, not a protocol address.

### G9 — rule 7 × K5 (`CreateContract` → `create_contract_not_allowed`)

No test constructs a `Context::CreateContractHostFn` or `Context::CreateContractWithCtorHostFn`
(the `benches` and unit tests only ever build `Context::Contract`). The v1 "the account may
not create contracts" rule is therefore implemented but unproven.

> **Suggested test:** construct both host-fn context variants and assert
> `CreateContractNotAllowed` from `decide()`. This is the cheapest gap in the list to close.

### G10 — rule 7 × K2, sub-rule `invalid_amount`

`decide()` returns `InvalidAmount` for `amount <= 0`, and `src/types.rs` carries reason
code 5 and the glossary documents it — but no test ever passes a zero or negative amount.
`I-19` only round-trips the symbol.

> **Suggested test:** assert `InvalidAmount` for `amount = 0` and `amount = -1`, and assert
> the window ledger is untouched in both cases.

### Not gaps (documented so they are not re-reported as such)

- **`protocol_not_allowed` (code 24) has no test and cannot have one.** `parse_call` only
  emits `Protocol` when the contract is already in `cfg.protocols`, so the `!found` branch
  inside `decide()`'s protocol arm is unreachable defensive code. SPEC §6.3 and SPEC §4
  rule 7 both list `ProtocolNotAllowed` as an outcome, but on the current parse-then-decide
  structure it cannot fire. See [finding F-2](#f-2-asset_not_allowed-and-protocol_not_allowed-are-unreachable-in-decide).
- **`asset_not_allowed` (code 20) has no test and cannot have one either.** An unlisted SAC
  is parsed as `Unknown`, not `AssetTransfer`, so it is blocked with `unknown_contract`
  (pinned by `E-5`), never `asset_not_allowed`. SPEC §6.2 states the latter. See
  [finding F-2](#f-2-asset_not_allowed-and-protocol_not_allowed-are-unreachable-in-decide).
- **`benches/denial_path_gas.rs` is not coverage.** It exercises all seven gates including
  the untested `Paused` and `OutsideActiveWindow` paths, but `measure_decide` only prints
  `cpu_instruction_cost` — there is no `assert!` in the file. A gate appearing in the
  SPEC §4.1 cost table does **not** mean a test pins it.

---

## 5. Test index

`E` = `src/engine.rs` (pure `decide()`, no host). `I` = `src/integration_tests.rs` (real
Ed25519 signatures through the Soroban host auth flow). `W` = `src/window.rs` (ledger).

| key | test | file:line | layer |
|---|---|---|---|
| `E-1` | `no_policy_is_default_deny` | [`src/engine.rs:353`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/engine.rs#L353) | unit |
| `E-2` | `allowed_transfer_admits_to_window` | [`src/engine.rs:363`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/engine.rs#L363) | unit |
| `E-3` | `per_tx_cap_enforced` | [`src/engine.rs:376`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/engine.rs#L376) | unit |
| `E-4` | `recipient_allowlist_enforced_and_escaped` | [`src/engine.rs:389`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/engine.rs#L389) | unit |
| `E-5` | `unlisted_asset_is_unknown_contract` | [`src/engine.rs:405`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/engine.rs#L405) | unit |
| `E-6` | `window_cap_blocks_across_transactions_and_rolls_over` | [`src/engine.rs:416`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/engine.rs#L416) | unit |
| `E-7` | `window_checks_all_contexts_before_commit` | [`src/engine.rs:455`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/engine.rs#L455) | unit |
| `E-8` | `protocol_and_function_allowlists` | [`src/engine.rs:472`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/engine.rs#L472) | unit |
| `E-9` | `account_gates_order_beats_calls` | [`src/engine.rs:523`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/engine.rs#L523) | unit |
| `E-10` | `heartbeat_allowed_but_expired_blocked_even_for_heartbeat` | [`src/engine.rs:575`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/engine.rs#L575) | unit |
| `E-11` | `other_self_function_rejected` | [`src/engine.rs:601`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/engine.rs#L601) | unit |
| `I-4` | `allowed_transaction_succeeds` | [`src/integration_tests.rs:396`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/integration_tests.rs#L396) | on-chain |
| `I-7` | `no_policy_is_default_deny_on_chain` | [`src/integration_tests.rs:495`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/integration_tests.rs#L495) | on-chain |
| `I-8` | `per_tx_cap_violation_blocked_without_window_effect` | [`src/integration_tests.rs:504`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/integration_tests.rs#L504) | on-chain |
| `I-9` | `rolling_window_cap_blocks_and_recovers_after_expiry` | [`src/integration_tests.rs:521`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/integration_tests.rs#L521) | on-chain |
| `I-10` | `recipient_allowlist_blocked` | [`src/integration_tests.rs:538`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/integration_tests.rs#L538) | on-chain |
| `I-11` | `allow_any_recipient_escape_hatch_still_capped` | [`src/integration_tests.rs:549`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/integration_tests.rs#L549) | on-chain |
| `I-12` | `dead_man_switch_freeze_and_admin_reversal` | [`src/integration_tests.rs:562`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/integration_tests.rs#L562) | on-chain |
| `I-13` | `admin_freeze_blocks_immediately_and_unfreeze_restores` | [`src/integration_tests.rs:590`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/integration_tests.rs#L590) | on-chain |
| `I-18` | `revoke_policy_is_instant_default_deny` | [`src/integration_tests.rs:757`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/integration_tests.rs#L757) | on-chain |
| `I-19` | `error_and_block_reason_round_trip` | [`src/integration_tests.rs:771`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/integration_tests.rs#L771) | on-chain |
| `W-1` | `window_is_genuinely_rolling` | [`src/window.rs:158`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/window.rs#L158) | unit |
| `W-4` | `exact_boundary_semantics` | [`src/window.rs:170`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/src/window.rs#L170) | unit |

`E-*` numbering follows the order the tests appear in `src/engine.rs`; `I-*` numbering
follows `src/integration_tests.rs`. Gaps in the `I-*` sequence (no `I-1`…`I-3`, `I-5`…`I-6`,
`I-14`…`I-17`) are tests that exist but pin no matrix cell — they cover lifecycle, key
rotation, heartbeat gas, the event audit, and the agent-loop simulation.

### 5.1 Keeping this document honest

This map is a snapshot. When you add or rename a test that pins a matrix cell, update the
[Test index](#5-test-index) row and the corresponding [Table 2](#3-table-2--coverage-map)
cell in the same commit — an enforcement PR that adds coverage without closing its gap cell
leaves the roadmap lying. Conversely, if you close a gap, delete the `— gap G#` cell and
move the item out of the [gap list](#4-known-coverage-gaps) rather than leaving it stale.

---

## 6. Findings for maintainers

Writing the matrix surfaced four places where **SPEC text and `src/engine.rs` disagree**.
None are fixed here — this PR is documentation-only and each needs a maintainer decision
on which side is correct. They are listed in the order a reviewer should look at them.

<a id="f-1-rule-order-no_policy-precedes-adminfrozen-in-code"></a>
### F-1 — rule order: `NoPolicy` precedes `AdminFrozen` in code

SPEC §4 numbers `AdminFrozen` as rule 1 and `NoPolicy` as rule 3, and says "first match
wins". `decide()` returns `NoPolicy` first, because the `Option<&PolicyConfig>` is
destructured before `state.admin_frozen` is read. For the *no-policy + admin-frozen*
combination the code returns `no_policy` where a literal reading of §4 returns
`admin_frozen`. No test distinguishes them (`E-9`'s frozen case always has a policy).

Either §4's ordering note should state that rule 3 is evaluated first, or `decide()` should
check `admin_frozen` before the policy load. Security-wise the difference is small — both
are blocks — but the freeze/reversal boundary is exactly the kind of statement CONTRIBUTING
says must be word-for-word consistent with the code, so it should not be left ambiguous.

<a id="f-2-asset_not_allowed-and-protocol_not_allowed-are-unreachable-in-decide"></a>
### F-2 — `asset_not_allowed` and `protocol_not_allowed` are unreachable in `decide()`

`parse_call` maps an unlisted SAC to `ParsedCall::Unknown` and a protocol call to
`ParsedCall::Protocol` *only after* confirming membership in `cfg.protocols`. So
`decide()` blocks an unlisted asset with `unknown_contract` (confirmed by `E-5`), and its
`!found` guard for protocols is unreachable. Yet SPEC §6.2 states unlisted assets are
blocked with `AssetNotAllowed`, and §4 rule 7 plus the reason glossary list both
`asset_not_allowed` (20) and `protocol_not_allowed` (24) as live outcomes.

Consumers (the SDK, the dashboard) mapping reason 20 and 24 will never see them emitted.
This is the same class of drift already tracked for `CreateContractNotAllowed` in
`docs/reason-glossary.md` (issue #132) and the reason
`scripts/check-spec-coverage.sh` reports `CreateContractNotAllowed` as an orphan variant.

<a id="f-3-rule-7-omits-createcontractnotallowed-from-its-reason-list"></a>
### F-3 — SPEC §4 rule 7's reason list omits `CreateContractNotAllowed`

Rule 7 enumerates `AssetNotAllowed`, `RecipientNotAllowed`, `PerTxCapExceeded`,
`WindowCapExceeded`, `ProtocolNotAllowed`, `FunctionNotAllowed`, `UnknownContract`. The
engine also returns `CreateContractNotAllowed` (and `SelfFunctionNotAllowed`, which §4.1's
cost table does list as gate 6). The matrix includes both; §4 rule 7's inline list does not.
This is the same omission issue #132 tracks for the SPEC §7 enum, one section earlier.

<a id="f-4-rule-6-names-check-which-the-engine-does-not-admit"></a>
### F-4 — rule 6 names `check`, which the engine does not admit

SPEC §4 rule 6 reads "(`heartbeat`, `check`)". `decide()` permits only `heartbeat`; any
other self-function returns `SelfFunctionNotAllowed` (pinned by `E-11`, which uses
`set_policy` as its example). This is almost certainly harmless — `check` and
`check_detailed` are views that never `require_auth`, so they never appear in
`auth_contexts` — but the spec text overstates the allowed set. Worth a one-word fix so
the allowed set is exactly the enforced set.

---

## 7. Related documents

- [SPEC §4 — policy semantics, decision table](../SPEC.md#4-policy-semantics--decision-table)
- [SPEC §6 — per-context classification and rule application](../SPEC.md#6-per-context-classification-and-rule-application)
- [SPEC §6.5 — scenario matrix (cross-reference)](../SPEC.md#65-scenario-matrix--decision-rows--call-kinds)
- [Enforcement scope](enforcement-scope.md) — the prose form of the same boundary this matrix tabulates
- [Reason glossary](reason-glossary.md) — what each reason symbol means per observer
- [CONTRIBUTING coding standards](../CONTRIBUTING.md#coding-standards) — the doc/test consistency rule this matrix serves
