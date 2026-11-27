Closes #350
Closes #351
Closes #352
Closes #354

## What this PR does

Four issues about the contract's **public contract surface**: one makes an already-true window
property explicit, one turns a silent inert policy into a loud one, one adds the read-only
`set_policy` preflight the SDK/dashboard path needs, and one consolidates the whole ABI into a
single table a reviewer can scan. They are shipped together because the last one documents the
other three: every row of the new SPEC §7.0 table is accurate only after #351 and #352 land.

| Issue | Type | Where |
|---|---|---|
| #350 | docs | `SPEC.md` §3.1, `README.md` §Storage |
| #351 | validation semantics | `src/lib.rs`, `SPEC.md` §8/§9, `docs/functions/set-policy.md`, tests |
| #352 | new read entry point | `src/lib.rs`, `SPEC.md` §7/§8.1, `README.md`, ABI snapshot, tests |
| #354 | docs | `SPEC.md` §7.0 (new), `docs/README.md`, `docs/functions/set-policy.md` |

---

## #350 — the 8192-entry backstop implies a maximum exact `window_secs`

**Problem.** `MAX_WINDOW_ENTRIES = 8192` and the merge-forward backstop engage only past that
many distinct spend seconds in one window. The property was described only in the abstract
(`SPEC.md` §3.1 "in the pathological region of ≥8192 distinct spend seconds … conservative"),
so an operator choosing `window_secs = 604800` had no way to know when exactness ends.

**Change.** A new bullet in `SPEC.md` §3.1 states the arithmetic, and the README's storage
section repeats it in the same words:

- the ledger holds **at most one entry per second** (`SpendEntry.ts` is a whole unix second and
  same-second spends coalesce), so a window can never hold more distinct entries than
  `window_secs`;
- therefore accounting is **exact for every spend density while `window_secs <= 8192`**;
- past that, a spender sustaining 1 Hz fills all 8192 slots after **8192 s = 2 h 16 min 32 s**,
  and every further admission merges the two oldest entries forward;
- a `window_secs = 604800` (7-day) policy is exact for a sparse spender and conservative for a
  sustained ≥1 Hz one — **stricter, never looser** (the merge over-counts, so it can deny spend
  the raw ledger would have admitted, never the reverse);
- the bound applies **independently** to the global window, each tracked per-recipient window,
  and the protocol-call ledger (`admit_to_ledger` / `admit_to_protocol_call_ledger` in
  `src/window.rs`).

No code change: the merge is already fail-safe, which is why the issue is documentation. While
editing the bullet I also repaired the dangling sentence fragment it ended with ("This is"),
which had swallowed the end of the previous sentence.

---

## #351 — empty `recipients` with `allow_any_recipient == false`

**Decision: accepted, with a dedicated warning event — not a rejection.** The issue allowed
either. Rejection was the alternative and was declined for one concrete reason: the shipped
[watch-only baseline](docs/policy-templates.md) is *deliberately* this exact shape (`paused:
true`, no assets, no destinations) as the posture to audit an agent from before going live. A
hard rejection would make a legitimate, safer-than-default configuration uninstallable and would
force an edit to a documented preset. The empty-`assets` case is the symmetric inert shape and
is already documented as accepted, so warning (rather than rejecting one and accepting the
other) keeps the two symmetric.

**Change.**

- New event `EventPolicyNoRecipient` → topic `event_policy_no_recipient` (single topic), data
  `by: Address`, `revision: u64`, so the warning joins on the §9 policy-revision key.
- `set_policy` emits it once per install — immediately after `policy_set` — when
  `config.recipients.is_empty() && !config.allow_any_recipient`. It fires on every such install
  (including an edit), because it describes the installed policy, not the call.
- It is **not** emitted when `allow_any_recipient == true` (recipients are genuinely not
  required) or for empty `assets` (a different, separately documented inert shape).
- `SPEC.md` §8: the parenthetical row is rewritten as a first-class row (**Accepted + warned**)
  naming the event, code location, and covering tests; a rationale bullet records why warning
  was chosen over rejection. `SPEC.md` §9 gains the event row.
  `docs/functions/set-policy.md` documents the same behaviour and points at the calm path.
- Nothing changes about enforcement: such a policy still denies every SAC transfer with
  `RecipientNotAllowed`. The new surface is one additive event; no error code, no
  `PolicyRuleId` ordinal, and no `PolicyConfig` field changed.

**Tests.**

- `empty_recipients_without_escape_hatch_is_accepted_but_inert_for_transfers`
  (`src/integration_tests.rs`): the dry run says `Valid`, the policy installs, `check` returns
  `Blocked(recipient_not_allowed)`, and a real host-routed transfer is blocked identically.
- `inert_recipient_policy_emits_one_warning_event` (`src/event_audit_tests.rs`): exactly one
  warning with 1 topic, a 2-field data map (`by`, `revision`) and the revision the install
  produced; no warning for the escape-hatch config; no warning for the symmetric empty-`assets`
  config (with a non-empty recipient list).

---

## #352 — `dry_run_set_policy()`

**Problem.** `set_policy` is all-or-nothing and fail-closed: an invalid config returns the single
`InvalidConfig` code and leaves state untouched. Safe, but iterating on a config becomes a
write-audit exercise for an operator, the SDK, or the dashboard.

**Change.** A new permissionless read:

```rust
pub fn dry_run_set_policy(env: Env, config: PolicyConfig) -> ValidationOutcome
```

- **No forked validation.** `validate_policy` (issue #35) already existed and does exactly this.
  Both entry points now call one new private `validation_outcome`, which walks
  `first_failing_rule` — the same function `set_policy`'s `validate_config` gate is built on. One
  rule set, three callers; there is nothing to drift.
- **Why an alias rather than a rename:** `validate_policy` is the name already in the published
  ABI and may be called by existing consumers. `dry_run_set_policy` is added as the
  operator-facing name ("validate this before I sign `set_policy`"), returning the identical
  `ValidationOutcome` (`Valid` / `Invalid(rule)` naming the **first** §8 rule).
- **Read-only and permissionless:** no auth, no events, no state writes (only the §9.5 TTL
  refresh any read may perform); installed policy and `PolicyRevision` are untouched.
- `SPEC.md` §7 signature block and §8.1 document the entry point and the trade-off the issue
  asked for: validation is pure, so it discloses nothing, but a permissionless entry point's
  cost is public. `README.md` gains a `validate_policy` / `dry_run_set_policy` section.

**Tests.**

- `dry_run_set_policy_is_permissionless_and_writes_nothing`: runs on the **enforcing-auth**
  harness (no blanket `mock_all_auths`), so a stray `require_auth` would fail it; asserts
  `Valid`, an empty event log, `policy() == None`, `policy_revision == 0`, then proves the real
  admin-authorized `set_policy` accepts the same candidate.
- `assert_rejects_with` — the helper every §8 rule test already uses — now asserts
  `dry_run_set_policy(cfg) == validate_policy(cfg) == Invalid(expected_rule)` **and** that
  `set_policy` still rejects. Because that helper backs every rule test, a divergence on any
  rule fails the suite, which is the "cannot drift" guarantee the issue asked for.

**ABI note.** `tests/snapshots/abi_snapshot.txt` is regenerated (`UPDATE_SNAPSHOTS=1 cargo test
--test abi_snapshot`); the diff is a single added line for the new function. This is additive and
not breaking.

---

## #354 — one canonical public-ABI table

**Change.** New `SPEC.md` §7.0, placed at the top of the public-surface section: one row per
entry point with **auth required · storage keys read · storage keys written · events emitted ·
failure on rejection · README section · GitBook page**. Columns are terse by design — the prose
signature block below, the README sections and the GitBook function pages stay the long form,
and the table cross-references them instead of restating them.

Notes on the table's conventions, both stated in the section:

- `A` / `P` mark instance vs persistent storage; `DataKey` names match `src/types.rs` and §3.
- "Written" lists **state** writes only. Permissionless reads may refresh a persistent entry's
  TTL under §9.5; that rent-bearing effect is not a policy change, and folding it into the column
  would make every read row look like a writer.

**Rows verified against `src/lib.rs` (all 27).** Following the issue's request to name them:
`initialize`, `set_policy`, `reset_window`, `increase_window_cap`, `revoke_policy`,
`rotate_agent_key`, `propose_admin_rotation`, `confirm_admin_rotation`, `cancel_admin_rotation`,
`pause`, `resume`, `heartbeat`, `freeze`, `unfreeze`, `refresh_deadman`, `policy`,
`policy_version`, `policy_hash`, `validate_policy`, `dry_run_set_policy`, `dms_health`, `status`,
`status_at`, `check`, `check_detailed`, `check_batch`, `__check_auth`.

Rows whose details are easy to get wrong, and what the source says: `set_policy` writes `Window`
and `LastHeartbeat` **only on a first install** (issue #289); `increase_window_cap` reads
`Window` but writes only `Policy` + `PolicyRevision`; `pause`/`resume` advance `PolicyRevision`
**only when the flag actually flips** (issue #290); `heartbeat`'s reads/writes include what
`__check_auth` performs on its behalf (`AgentPubkey`, `Window`), and its `LastHeartbeat` write is
skipped when it already equals `now`; `status`/`status_at` read `PolicyRevision` but never write;
`check`/`check_detailed`/`check_batch` write nothing (they prune an in-memory ledger copy);
`validate_policy`/`dry_run_set_policy` touch no storage key at all.

**Coverage gaps, handled explicitly rather than invented.** Four entry points have no GitBook
page today (`increase_window_cap`, `check_batch`, `policy_version`, and the
`validate_policy`/`dry_run_set_policy` pair). Those cells say so and point at the owning SPEC
section instead of inventing a page or a dead link. `README.md` gained the
`validate_policy` / `dry_run_set_policy` section, so those rows do have a README target. Also
added: the §7.0 row in the SPEC ↔ GitBook cross-reference map (`docs/README.md`), and a
See-also link from `docs/functions/set-policy.md` to the table.

---

## Compatibility / risk

- **Additive only.** One new read entry point and one new event. Error codes `1..=33` are
  unchanged, `PolicyRuleId` ordinals are unchanged (no new rule variant), `PolicyConfig`'s wire
  format is untouched (`policy.schema.json` unchanged), and no `DataKey` was added or renamed
  (the `agent-tx` storage-key fixture is unchanged).
- The new event's topic is `event_policy_no_recipient` (25 chars). Worth stating because
  Soroban `Symbol`s are capped at 32 characters: a longer first draft
  (`event_policy_permits_no_recipient`, 33 chars) panicked the `#[contractevent]` macro, so the
  name is deliberately short and the payload carries the detail.
- Telemetry consumers that ignore unknown event names are unaffected; those that enumerate
  events will see one new name, documented in SPEC §9.

## Verification

Run locally on the pinned toolchain (`rust-toolchain.toml`, 1.99.0):

| Command | Result |
|---|---|
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --all-features -- -D warnings` | pass, no warnings, no new `#[allow]` |
| `cargo test` | **253 passed, 0 failed** (219 lib + 34 integration/doc targets) |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` | pass |
| `cargo build --release --target wasm32v1-none` | pass |
| `scripts/check-wasm-panic-strings.sh` | pass (all matches already allowlisted) |
| `scripts/verify-readme.sh` | pass — README's test-count claim updated 250 → 253 |
| `scripts/verify-docs-reachability.sh` | pass, 63 checks |
| `scripts/check-spec-coverage.sh` | **fails on 3 variants** — pre-existing, see below |

**Known limitation, not introduced here:** `scripts/check-spec-coverage.sh` reports
`Unauthorized`, `AlreadyInitialized` and `DecisionInvariantViolation` as missing from §4/§6. The
identical three failures reproduce on unmodified `main` (`git show HEAD:SPEC.md`,
`git show HEAD:src/types.rs`), the script is not wired into `.github/workflows/ci.yml`, and this
PR does not change the `Error` enum or those sections. Fixing it would be an unrelated §4/§6
edit, so it is left alone and reported instead of silently "fixed" by padding prose.

## Out of scope (deliberately)

- Sibling repositories (`stellar-agent-guard-sdk`, `stellar-agent-guard-dashboard`): consuming
  the new event and `dry_run_set_policy` is tracked there.
- Writing new GitBook pages for the entry points that lack one; the table marks those rows
  honestly instead.
- Changing the empty-`recipients` combination from warning to rejection — recorded as the
  alternative in SPEC §8 with the reason it was not taken.
