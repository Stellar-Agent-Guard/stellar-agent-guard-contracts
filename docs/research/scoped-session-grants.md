# Scoped Session Grants — Decision Record

**Issue:** #308
**Status:** Decision recorded — **build in v2, not v1** (no contract change in this PR)
**Type:** Architecture decision record (ADR) for a research spike
**Spec anchor:** [SPEC Appendix A — Scoped session grants](../../SPEC.md#appendix-a--scoped-session-grants-research-spike-issue-308)
**Cross-links:** [SPEC §3 — Storage model](../../SPEC.md#3-storage-model) ·
[SPEC §4 — Policy semantics](../../SPEC.md#4-policy-semantics--decision-table) ·
[SPEC §6.2 — Asset (SAC) calls](../../SPEC.md#62-asset-sac-calls--fully-enforced) ·
[SPEC §10 — Threat model](../../SPEC.md#10-threat-model-what-this-does-and-does-not-do)

---

## 1. Decision

**Do not build scoped session grants in v1. Build them in v2 as
contract-stored, nonce-identified grants** (representation A), with the cap
semantics and revocation rules stated in §6 and §7. Do **not** build the
off-chain signed-grant representation (B): it requires breaking the account's
`Signature` ABI, it introduces a second admin trust root, and it cannot offer
per-grant revocation without the same on-chain state that representation A
already uses.

The v2 trigger is evidence that `increase_window_cap` is insufficient — in
particular, operators asking for **time-boxed budgets scoped to an asset and a
recipient set**, rather than a global cap increase. Until that evidence exists,
the existing in-place budget controls already cover the motivating pain (see
§2).

This PR changes documentation only. No storage key, decision row, error
variant, event, or `__check_auth` behavior is added.

---

## 2. Current state — what is already true on `main`

The issue's background says that "every policy change resets the window." That
was true before issue #289 and is **not true at this revision**; the decision
record must start from the shipped semantics:

| Control | Shipped behavior | Gap that a grant would fill |
|---|---|---|
| `set_policy` | Preserves the rolling window and the DMS clock across edits; only a *first* install seeds a fresh window (`src/lib.rs`, issue #289). | None for the "reset" pain. A policy edit is still account-global. |
| `reset_window` | The one explicit way to zero the ledger (admin-only). | Not relevant to routine budgets. |
| `increase_window_cap` | Raises `window_cap` **in place**, keeps every non-expired spend entry counted, bumps `PolicyRevision` (issue #349). | Caps are global and have no expiry or recipient scope. Lowering the cap later is refused below the live rolling total, so the increase is effectively open-ended. |
| `pause` / `resume` | Flip one flag in place; window and DMS clock untouched. | Account-global; not a budget. |
| Per-recipient caps | `recipient_window_caps` narrow one recipient's rolling budget. | Still requires a policy rewrite and applies indefinitely. |

So the remaining, honest gap is: **a short-lived, amount-capped, scope-limited
budget that an admin can hand to the agent without rewriting the whole policy,
and that cannot outlive the policy revision it was minted under.** That is the
only thing this ADR proposes to build.

Two hard constraints shape everything below:

1. **`__check_auth` receives no grant side-channel.** Its signature is fixed by
   `CustomAccountInterface`: `(env, signature_payload: Hash<32>, signatures:
   Self::Signature, auth_contexts: Vec<Context>)`. `Self::Signature` is
   currently `BytesN<64>`. Any off-chain grant must therefore travel inside a
   changed `Signature` type, or be reflected in storage before the spend is
   authorized.
2. **There is no background process.** Soroban does not run timers. Expiry,
   revocation, and DMS lapse are all *lazy predicates* evaluated when an
   authorization happens — the same model as §5 and §9.5.

---

## 3. What a grant is — and is not

A grant is an **admin-issued budget envelope**, not a new signer and not a
bearer token:

- The agent's Ed25519 signature over the transaction payload remains mandatory.
  A leaked grant is useless without the agent key; a leaked agent key can burn
  every outstanding grant, exactly as it can spend under policy today.
- A grant can only affect **monetary limits on an already-admissible SAC
  `transfer` / `transfer_from`**. It cannot authorize `UnknownContract`,
  `CreateContract`, `AssetOther`, a non-`heartbeat` self-call, a protocol call,
  or a recipient/asset the policy would otherwise reject.
- A grant cannot bypass `AdminFrozen`, DMS expiry, `NoPolicy`, `paused`, the
  active window, the asset allowlist, the recipient allowlist/denylist, or
  function classification. Those gates **intersect** — the grant can only be
  consulted after they pass (§6).
- A grant is bound to the **contract address**, the **admin authority that
  minted it**, the **agent key** at mint time, the **policy revision**, the
  **asset**, the **recipient scope**, the **caps**, and the **expiry**. The
  policy-revision binding is what makes every policy-mutating admin call an
  implicit global revocation. That binding is what prevents redirection and
  cross-deployment replay.

---

## 4. Representation A — contract-stored grant with nonce (recommended)

### 4.1 Shape

```rust
// v2 candidate — illustrative, not present in the v1 ABI.
#[contracttype]
pub struct SessionGrant {
    pub nonce: u64,                 // contract-assigned, monotonic; mint/replay id
    pub asset: Address,             // must be a member of PolicyConfig.assets
    pub recipients: Vec<Address>,   // empty = any recipient the policy allows
    pub per_tx_cap: i128,           // > 0; grant's own per-call cap
    pub total_cap: i128,            // > 0; grant's remaining budget ceiling
    pub consumed: i128,             // >= 0; settled only with a fully allowed batch
    pub starts_at: u64,             // optional; 0 = immediately
    pub expires_at: u64,            // required; now < expires_at
    pub policy_revision: u64,       // grant is inert once the policy revision moves
    pub agent_key: BytesN<32>,      // grant is inert after rotate_agent_key
}
```

Storage: one live grant per account (`DataKey::Grant`), plus
`DataKey::LastGrantNonce`. Keeping the live set at one entry bounds the
contract's persistent footprint and keeps the engine's input deterministic.
A future v2.1 may extend to one live grant per asset, but that is not needed
for the motivating use case and multiplies the storage/audit surface.

### 4.2 Minting (`mint_grant`) and validation

Admin-only, via the normal `admin.require_auth()` path (not inside
`__check_auth`), so a contract admin address works exactly like it does for
`set_policy`:

- `asset ∈ PolicyConfig.assets`; otherwise `AssetNotAllowed`.
- `recipients` must be a subset of the policy's recipient set unless
  `allow_any_recipient` is true; a denylisted recipient is rejected. A grant
  can only narrow the recipient scope, never widen it.
- `0 < per_tx_cap <= total_cap`, `now < expires_at`, and
  `expires_at <= now + MAX_GRANT_LIFETIME` (a bounded, short lifetime).
- `policy_revision` and `agent_key` are stamped from current storage; the admin
  cannot choose stale values.
- Same nonce is never reused: `LastGrantNonce` is incremented and the nonce is
  returned in the `grant_minted` event. This makes mint replay and
  "overwrite a live grant to reset `consumed`" impossible.
- Minting while a live, unexpired grant exists is rejected; the admin must
  `revoke_grant` first. This prevents silently discarding unconsumed budget.
- A monotonic `expires_at` bound and the one-live-grant rule are what keep
  storage rent bounded without a reaper.

### 4.3 Consumption

The engine consults the loaded grant only after the policy path fails a
monetary cap (§6). On the grant path it checks:

```text
match scope(asset, to)
  && now >= starts_at && now < expires_at
  && grant.policy_revision == current_revision
  && grant.agent_key == AgentPubkey
then amount <= per_tx_cap
  && grant.consumed + staged_grant_amount + amount <= total_cap
```

`consumed` is staged alongside the rolling-window admissions and is written
only if **every** context in the authorization is allowed. A failed
multi-context batch therefore consumes neither the policy window nor the
grant. Grant-funded spend is **not** added to `WindowState` (see §6 for why).

### 4.4 Replay analysis

| Replay vector | Why it fails / is harmless |
|---|---|
| Replaying the mint transaction | Stellar transaction replay protection (sequence number + signature payload binding, §10.1). The contract-assigned nonce also makes a duplicated mint a second grant, not a reset. |
| Re-presenting the same grant for many spends | This is **intended**: the grant is a budget, not a one-shot ticket. `consumed` monotonically decreases the remaining budget. |
| Double-spending the last unit of a grant | Soroban executes a ledger's transactions serially; `consumed` is read and staged inside the same `__check_auth`. Two contexts in one batch share the staged amount, so they cannot both consume the same headroom. |
| Replaying a grant on another contract/deployment | The grant lives in this contract's storage and is bound to this contract address and admin. It does not exist elsewhere. |
| Replaying after a policy edit or key rotation | `policy_revision` and `agent_key` bindings make the grant inert (fail-closed to policy). |
| Redirecting the grant to another asset/recipient | Scope checks match the parsed context; mint-time validation already restricted scope to the policy's allowlists. |
| A third party using a leaked grant | It is not a bearer token: every spend still needs the agent key's signature. |

A note on cross-network forks: if the same contract ID were deployed on two
networks, storage would still be independent, so an on-chain grant cannot be
replayed from one to the other. The off-chain representation does need an
explicit network/domain separator (§5).

### 4.5 Expiry analysis

- Expiry is a lazy comparison in `__check_auth` against
  `env.ledger().timestamp()`. An expired grant is simply ignored, so the call
  falls back to the policy result. There is no timer and no state transition
  that must happen at the expiry instant.
- Time comparisons must use the same saturating/checked discipline as the DMS
  and active-window gates; `expires_at` is validated at mint, so no wrap is
  possible from admin input.
- The expired entry may remain in storage until the next admin call. A read
  must not extend TTL beyond `expires_at`. `mint_grant` and `revoke_grant`
  prune/overwrite the expired slot; bounding `MAX_GRANT_LIFETIME` bounds the
  rent an operator can be made to pay.
- An expired grant cannot be "revived" by policy edits. A new mint is required.

### 4.6 Revocation analysis

- `revoke_grant(nonce)` is admin-only and removes or tombstones the live grant.
  The next authorization sees no grant and falls back to the policy. Revocation
  is **not retroactive**: it cannot undo a spend that already settled.
- There is no background process, and none is needed: the check is lazy, like
  the DMS. The worst case is that a revocation and a spend race in the same
  ledger; ledger ordering decides. The admin's `revoke_grant` transaction and
  the agent's spend are both ordinary transactions — no front-running
  advantage exists because the grant is not a secret and cannot be redirected.
- **Global revocation is free:** a grant is bound to `policy_revision` and
  `agent_key`, so any `set_policy`, `increase_window_cap`, `pause`/`resume`
  that flips the flag, `revoke_policy`, or `rotate_agent_key` invalidates every
  outstanding grant without touching grant storage. This is the strongest
  revocation story available without a scheduler, and it matches the project's
  framing that a policy edit is the operator's kill switch.
- Per-grant revocation is a convenience, not the last line of defense:
  `freeze`, `pause`, `revoke_policy`, and key rotation already stop all grant
  consumption because the account-level gates run before per-context rules.

---

## 5. Representation B — signed off-chain grant verified in `__check_auth` (rejected for v2)

### 5.1 Shape

The admin signs a canonical grant digest off-chain; the agent presents
`(grant, admin_signature)` with each spend; `__check_auth` verifies the admin
signature and applies the grant. No stored grant record at mint time.

The deliverability problem is decisive:

- **There is no argument to carry the grant.** `__check_auth` receives only
  the payload hash, `Self::Signature`, and the auth contexts. Shipping this
  representation requires changing the account's associated `Signature` type
  from `BytesN<64>` to, for example,
  `SessionGrantEnvelope { agent_sig: BytesN<64>, grant: Bytes, admin_sig: BytesN<64> }`.
  That is an ABI break for every client, SDK, signer, and auth-entry builder —
  and it changes the type the host hands to the account on every transaction,
  not just grant-funded ones.
- **A "present the grant first" self-call does not work.** `__check_auth` runs
  before any call in the transaction executes, so a `present_grant` call in the
  same batch cannot populate storage in time for the spend's authorization. A
  prior transaction works, but that is just representation A with an extra
  step.
- **A second admin trust root is required.** The stored `Admin` is an
  `Address`, which may be a contract. Verifying an Ed25519 signature inside
  `__check_auth` needs a stored admin public key (or a new signer abstraction).
  On-chain minting can reuse `require_auth()` and works for both account and
  contract admins; the off-chain form cannot without adding a new key that the
  security model must now protect.
- **It still needs on-chain state.** Without a consumed counter keyed by grant
  id, the same signed grant can be replayed until expiry. Adding that counter
  makes it "off-chain mint, on-chain settle": storage grows with every grant
  ever used, and rent/cleanup concerns return. The claimed storage saving
  largely disappears.

### 5.2 Expiry, replay, revocation

| Property | Analysis |
|---|---|
| Expiry | Lazy check against ledger time; sound. The grant digest must include `expires_at` so it cannot be edited. |
| Replay | Needs a `Consumed(grant_id)` record on first use, otherwise double-spend until expiry. The grant id is a hash over all fields; consumption is per grant, so an unbounded set of ids can accrue. A global sequence can bound it, but then only one grant can be live at a time — the same constraint as A, paid for with extra complexity. |
| Redirection / cross-deployment | The signed digest must include a domain separator: network id, contract address, admin address, asset, recipients, policy revision, agent key. Omitting any of these creates a replay or redirection vector. |
| Revocation | No per-grant revocation without on-chain state. The only bounded story is a global epoch/revision: admin bumps `GrantEpoch` (or the policy revision), invalidating every grant issued before it. If a per-grant revocation list is added, it is admin-only but unbounded and only usable if the admin knows the grant id. |
| Freeze/pause/policy revoke | Still work, because account gates run before grant evaluation — but they do not provide a way to revoke *one* grant. |

**Verdict:** reject for v2. It is not more decentralized (the admin still
mints), not cheaper once replay protection exists, strictly weaker on
revocation, and it requires an ABI break. Keep it as a possible optimization
only if a future ABI revision is already happening for another reason and the
grant consumption ledger can reuse that revision's storage layout.

---

## 6. Interaction with `per_tx_cap` and `window_cap`

The answer is not a single verb:

- **Eligibility gates — intersect.** The grant is consulted only after
  `AdminFrozen`, DMS, `NoPolicy`, `paused`, active window, asset allowlist,
  recipient allow/deny lists, pause flags, and classification have all passed.
  A grant never admits a call the policy would block for a non-monetary
  reason.
- **Monetary caps — substitute on policy overflow ("replace", narrowly).**
  A matching grant replaces the *monetary* gate for that one call when, and
  only when, the policy's own monetary gate would reject it.

Concretely, inside the existing `ParsedCall::AssetTransfer` branch:

1. Evaluate the policy path exactly as today (per-tx cap, global window,
   per-recipient override). If it allows, admit and charge the policy window;
   **do not touch the grant**, so routine spending does not burn the exception
   budget.
2. If the policy path fails specifically on `PerTxCapExceeded` or
   `WindowCapExceeded`, evaluate the matching grant. Non-monetary checks have
   already passed.
3. If the grant covers the call (`amount <= per_tx_cap` and
   `consumed + staged + amount <= total_cap`), admit and stage grant
   consumption — **do not add the amount to `WindowState`**.
4. If the grant does not cover it, return the original policy error
   (`PerTxCapExceeded` / `WindowCapExceeded`). No new error variant is needed,
   and the denial vocabulary stays stable.

Why not **raise** (add grant headroom to the policy window)? It would make
grant-funded spend consume the operator's rolling budget, so the grant would
silently borrow from future policy budget; after expiry the account could be
over its window cap with no grant left and no obvious explanation. The joint
algebra (`window_cap + remaining`) is also harder to state, test, and audit
than a separate ledger.

Why not **intersect** the caps too? A grant that can only tighten policy caps
cannot express the motivating use case at all (it would only let the admin
restrict the agent, which `set_policy` already does). Intersection is right for
eligibility, not for the budget the grant exists to provide.

**Per-asset and per-recipient overrides.** On the grant path, the grant's own
`per_tx_cap` and `total_cap` are the only monetary limits; the policy's global
window and recipient override are replaced for that call. That is the point of
a scoped capability. All non-monetary restrictions still apply, and the grant
is minted only for a policy-allowlisted asset and recipient scope.

**Batch atomicity.** Grant consumption is staged with the same all-or-nothing
rule as §6.0: if any context in the authorization block, nothing is committed.
This prevents a rejected batch from burning grant budget — the same invariant
that protects the rolling window.

**Diagnostics.** `status()` / `grant_status()` should expose the live grant's
`nonce`, `remaining`, `expires_at`, and whether it is currently inert
(expired / wrong revision / wrong key). The dashboard and SDK can then explain
why a grant is not helping, without adding denial reasons to `__check_auth`.

---

## 7. Revocation story, stated explicitly

This is the hard part without a background process, so state it without
hedging:

1. **There is no scheduler.** Expiry and revocation are predicates read on the
   next authorization. Nothing happens at the expiry timestamp; an expired
   grant is inert from the first moment `now >= expires_at`, and a revoked
   grant is inert from the first authorization that reads the new state.
2. **Revocation is never retroactive.** A spend that settled before the
   revocation transaction is final. Revocation prevents future consumption; it
   cannot claw funds back. The same is true of `freeze` and `pause`.
3. **Per-grant revocation (A) is immediate-on-next-read.** `revoke_grant(nonce)`
   removes the live grant. If the admin and agent race, ledger ordering decides;
   there is no way to front-run the revocation for profit because the grant is
   scoped and requires the agent key.
4. **Global revocation is already available and is the primary story.**
   - `AdminFrozen` blocks every authorization before any grant is read.
   - `paused` and `revoke_policy` block every authorization at rows 4 and 3.
   - `policy_revision` binding means any policy-mutating admin call
     (`set_policy`, `increase_window_cap`, a `pause`/`resume` that flips the
     flag, `revoke_policy`) makes every outstanding grant inert.
   - `rotate_agent_key` changes `AgentPubkey`, and the grant's `agent_key`
     binding makes every outstanding grant inert. That is the intended response
     to a suspected agent-key compromise.
   - Expiry bounds the blast radius even if the admin does nothing.
5. **Representation B cannot revoke one grant.** Its only bounded mechanisms
   are the same global revision/epoch and the account-level gates. Per-grant
   revocation would require an on-chain revocation list or a consumption
   record keyed by grant id — state that representation A already has. This is
   a reason B is rejected, not a detail to paper over.

The honest residual risk: **a compromised agent key can consume every
outstanding grant before the operator notices.** Grants do not change that —
the same key can already spend within policy — but they enlarge the loss by the
grant amount. Mitigate by construction: short `MAX_GRANT_LIFETIME` (hours, not
weeks), small `total_cap`, one live grant, and binding to the agent key so
rotation kills the remainder.

---

## 8. Threat model comparison

| Threat | A (stored) | B (signed off-chain) |
|---|---|---|
| Grant leaked to third party | Useless without agent key | Useless without agent key |
| Agent key leaked | Can burn grant; expiry/caps bound it | Same |
| Admin key leaked | Attacker can mint grants, but can already rewrite policy; no new authority | Same, plus can sign arbitrary grants offline without touching the chain, so detection is harder |
| Grant redirected to another asset/recipient | Scope checked per context; mint validates subset | Scope must be inside the signed digest; any omission is a vulnerability |
| Replay across deployments/networks | Grant is contract-local storage | Needs explicit domain separator; easy to get wrong |
| Double-spend | `consumed` staged atomically with window | Needs a consumption record, or replay until expiry |
| Revocation of one grant | `revoke_grant(nonce)`, lazy but immediate on next auth | Not possible without extra on-chain state |
| Revocation of all grants | Policy revision / agent-key binding / freeze / pause | Same global mechanisms only |
| Storage/rent blow-up | One bounded live grant | Unbounded grant-id consumption records |
| ABI break | None to `__check_auth`; new admin functions and a storage key only | Changes `Self::Signature`, breaking every client and signer |
| Denial of service against the admin | Admin-only mint/revoke, bounded size | Admin-only verify, but an attacker can spam invalid grants (cheap rejection; still CPU) |

---

## 9. Engine decision shape (v2, illustrative)

This is the shape a future implementation should take in `src/engine.rs`; it is
**not** compiled or shipped by this spike. The important properties are: the
new input is explicit (`Option<&SessionGrant>`), the verdict type is unchanged
(`Decision::Allowed | Blocked(Error)`), and every new branch is inside the
existing `AssetTransfer` arm after the allowlist gates.

```rust
// Illustrative only — do not paste into v1.
pub struct GrantState<'a> {
    pub grant: Option<&'a SessionGrant>,
    pub revision: u64,
    pub agent_key: &'a BytesN<32>,
}

fn grant_matches(
    grant: &SessionGrant,
    state: &GrantState,
    asset: &Address,
    to: &Address,
    now: u64,
) -> bool {
    grant.asset == *asset
        && (grant.recipients.is_empty() || contains_addr(&grant.recipients, to))
        && grant.policy_revision == state.revision
        && grant.agent_key == *state.agent_key
        && now >= grant.starts_at
        && now < grant.expires_at
}

fn grant_covers(grant: &SessionGrant, staged: i128, amount: i128) -> bool {
    amount <= grant.per_tx_cap
        && grant
            .consumed
            .checked_add(staged)
            .and_then(|v| v.checked_add(amount))
            .is_some_and(|v| v <= grant.total_cap)
}

// Inside ParsedCall::AssetTransfer, after amount/denylist/allowlist checks:
let policy_result = /* existing per-tx + window + per-recipient evaluation */;
match policy_result {
    Decision::Allowed => { /* charge policy window as today */ }
    Decision::Blocked(Error::PerTxCapExceeded | Error::WindowCapExceeded) => {
        match state.grant {
            Some(grant)
                if grant_matches(grant, state, &asset, &to, now)
                    && grant_covers(grant, staged_grant, amount) =>
            {
                staged_grant += amount; // committed only if all contexts pass
                Decision::Allowed
            }
            _ => policy_result, // original denial reason preserved
        }
    }
    other => other, // allowlist/denylist/classification failures are not grantable
}
```

`lib.rs` would load the grant alongside the policy snapshot and persist
`consumed` only when the whole batch is admitted. `AccountState` gains the
grant inputs (or a separate `GrantState` parameter), and no existing decision
row changes for callers that have no grant.

---

## 10. Rejected alternatives

| Alternative | Verdict | Reason |
|---|---|---|
| Grant as a second signer / bearer capability | Reject | Violates the single-key v1 model, and a bearer token would let anyone spend; the agent key must remain the authorizer. |
| Grant that can widen allowlists or bypass pause/DMS/freeze | Reject | Those are the operator's kill switches; widening them turns a budget into a policy bypass. |
| Raise (`window_cap + grant`) semantics | Reject | Grant spend consumes the operator's window, silently borrowing future budget; poor auditability and surprising post-expiry blocks. |
| Intersect-only grants | Reject | Cannot serve the use case (only tightens, which `set_policy` already does). |
| Off-chain signed grants (B) for v2 | Reject | ABI break, new admin trust root, unbounded consumption state, no per-grant revocation. Keep for a future ABI revision at most. |
| A separate grant contract | Reject | Moves the authoritative check outside `__check_auth`; a compromised agent could bypass it. The grant must be enforced by the account contract itself. |

---

## 11. Open questions before implementation

1. **Lifetime and dose ceilings.** `MAX_GRANT_LIFETIME` (hours?) and whether
   `total_cap` needs an absolute ceiling independent of policy caps. The admin
   is trusted, but a ceiling limits the damage from a mistaken mint.
2. **One grant or one per asset.** This ADR recommends one live grant total;
   verify against real operator workflows before committing storage layout.
3. **Events.** `grant_minted`, `grant_revoked`, and a consumption signal
   (`grant_consumed` with nonce/remaining) will need the full §9 vocabulary and
   testnet-proof treatment, including `PolicyRevision` join keys.
4. **Read surface.** `status()` is already large; adding grant data may warrant
   a separate `grant_status()` to avoid changing an established wire shape.
5. **Error vocabulary.** This design deliberately adds no denial reason. If
   `grant_status()` needs an "inert" reason, model it as data, not as a new
   `Error` variant, unless maintainers decide agents need a distinct denial
   signal.
6. **Migration.** New `DataKey` entries and admin entry points are additive,
   but they still require the §3 storage-layout review, ABI snapshot
   regeneration, and a `POLICY_FORMAT_VERSION` decision.
7. **SDK/dashboard.** Out of scope for this repository, but the grant shape and
   read surface must be agreed with `stellar-agent-guard-sdk` and
   `stellar-agent-guard-dashboard` before the v2 layout freezes.

---

## 12. Acceptance criteria mapping

| Issue criterion | Where answered |
|---|---|
| Enumerate at least two grant representations (stored + signed off-chain) and analyse replay, expiry, revocation for each | §4 (A), §5 (B); see replay tables in §4.4 and §5.2 |
| State how a grant interacts with `per_tx_cap` / `window_cap` — raise, replace, or intersect | §6: intersect for eligibility; substitute-on-overflow for monetary caps |
| State the revocation story explicitly without a background process | §7 |
| Decision record (SPEC appendix or ADR) stating whether to build and the v2 shape | This ADR + [SPEC Appendix A](../../SPEC.md#appendix-a--scoped-session-grants-research-spike-issue-308) |
| Lints clean; lint, type-check, tests pass | No code changed; the documentation-only gate is `cargo fmt --check`, `cargo clippy`, `cargo test`, and `scripts/verify-docs-reachability.sh` |
| PR references the issue with `Closes #` | PR body uses `Closes #308` |
| No contract code | This PR adds Markdown only |
