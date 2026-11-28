# CAP-71 Delegated Signers: Research Spike and Decision Record (v2 Gate)

**Issue:** #80 (gate for #2 multi-key work)  
**Status:** Decision record — **defer with trigger conditions**; delegation is **rejected as the basis for #2's threshold model**  
**Decision owner:** maintainers (this record is the proposal of record)  
**Verified against:** `soroban-sdk 27.0.6`, `soroban-env-host 27.0.1`, `stellar-xdr 27.0.0`,
[CAP-0071-01](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071-01.md)
(*Authentication delegation for custom accounts*, Status: Final, Protocol version: 27)  
**Linked from:** [SPEC §1.1](../../SPEC.md#11-sdk-and-host-surface-this-is-built-on-soroban-sdk-27)  
**Related:** [Multi-Sig Threshold Models](multi-sig-threshold-models.md) (issue #153/#2), SPEC §1, §10.1

---

## 1. The question this record answers

SPEC §1.1 defers CAP-71 to v2. Before #2 (multi-key / threshold authorization) starts, three
things had to be established:

1. What delegation actually *enables* for this design — session keys? spending
   sub-authorities with their own scopes? something else?
2. Whether the host still routes delegated operations through the custom account's
   `__check_auth`, i.e. whether the policy engine remains the enforcement vector.
3. Whether #2's multi-sig model should be **built on top of** delegation or **beside** it.

Short answers, with the evidence in §2–§5:

1. It enables *adding an external approver* to an authorization the guarded account has
   already decided to approve. It enables a scoped sub-authority only if the delegate is
   itself a contract that enforces that scope — the parent cannot constrain a delegate.
2. **Yes.** The account's `__check_auth` is still the entry point and still runs, first and
   unconditionally. Delegation is an *outbound call made from inside it*, not an inbound
   route that bypasses it.
3. **Beside it.** Delegation cannot express M-of-N (§5.4), so #2 must not be built on it.
   Delegation stays deferred as an optional additive signer path (§6).

---

## 2. What CAP-71 actually is (protocol facts, not marketing)

CAP-0071-01 is **Final** for **protocol 27**. It adds a built-in way for a custom
(contract) account to hand its authentication decision to another address, without asking
the host for a second, separate authorization entry.

**Two host functions** (`soroban-env-host 27.0.1`, `src/host.rs`):

| Host function | SDK 27.0.6 wrapper | Callable from |
|---|---|---|
| `delegate_account_auth(address)` | `env.custom_account().delegate_auth(&addr)` — `custom_account.rs:317` | only inside `__check_auth` |
| `get_delegated_signers_for_current_auth_check()` | `env.custom_account().get_delegated_signers()` — `custom_account.rs:274` | only inside `__check_auth` |

Both are guarded by `ensure_check_auth_frame`; calling them anywhere else fails.

**One new credential kind.** `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` bundles the
account's normal `SorobanAddressCredentials` with a tree of

```text
struct SorobanDelegateSignature {
    SCAddress address;
    SCVal signature;                          // for a G delegate: the classic signature vec
    SorobanDelegateSignature nestedDelegates<>; // recursive
};
```

so one auth entry carries the account credential *and* every delegate signature. Protocol 27
also adds `SOROBAN_CREDENTIALS_ADDRESS_V2` and a new envelope type
(`ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS`) that **binds the signed payload to the
top-level account address**, so a delegate's signature cannot be replayed against a different
guarded account. This matters directly for us: a session key cannot reuse its signature on
another agent's account.

**Host-enforced rules on the tree** (`soroban-env-host 27.0.1`, `src/auth.rs`,
`DelegatedAccountAuthSignerTreeNode::from_xdr`, ~L2093–2145):

- each `nested_delegates` array must be **strictly ascending by address** — unsorted or
  duplicate addresses are `ScErrorType::Auth / InvalidInput` errors, not silent no-ops;
- nesting is allowed but bounded (`with_limited_depth`);
- each delegate node is **single-use**: `delegate_account_auth` marks it
  `is_exhausted`, and a second call for the same address in the same frame fails with
  "no delegated signers were provided" / matching error;
- the delegate list is **user input**: `get_delegated_signers()` returns it "not sanitized in
  any way" and the contract must decide which delegates it accepts.

**Delegation is not supported in recording auth mode**, so simulation never emits delegate
credentials on its own; the client assembles them
(see the Stellar JS SDK protocol-27 migration guide, `buildWithDelegatesEntry`).

---

## 3. How delegation interacts with our `__check_auth`

This is the acceptance-criterion question: *does the host still route delegated ops through
the custom account?*

**Yes — and the ordering is the important part.** The sequence for a transaction the guarded
account must authorize is:

```text
host: require_auth(guarded_account, invocation)
  └─ host builds auth_contexts (flattened invocation tree, SPEC §2.1)
     └─ guarded_account.__check_auth(payload, signature, auth_contexts)   ← ALWAYS runs
          ├─ signature verification (v1: ed25519 on registered agent key)
          ├─ policy pipeline (SPEC §4.0: freeze, pause, DMS, allowlists, caps, window)
          └─ optional: env.custom_account().delegate_auth(&delegate)
               ├─ G delegate → classic account auth (thresholds/weights) over the same payload
               └─ C delegate → delegate.__check_auth(payload, signature, SAME auth_contexts)
```

Consequences that decide the design:

1. **The policy engine cannot be bypassed by attaching delegates.** `__check_auth` runs
   regardless of what the credential carries; a wallet that supplies delegates still gets
   every gate in SPEC §4.0 applied to every context. Delegation is strictly *additive*.
2. **`delegate_auth` forwards the parent's `signature_payload` and the parent's
   `context`** (`AuthenticationFrame { signature_payload, context }`, `auth.rs:524–533`).
   A contract delegate therefore sees the *full* context set the parent saw — it can evaluate
   its own narrower policy, but it cannot ask for a subset, and it cannot re-scope the parent.
3. **All-or-nothing failure.** `delegate_auth` returns `Result` but the SDK wrapper is
   `unwrap_infallible()`; there is no `try_delegate_auth`, and Soroban has no catch. A
   delegate that does not authorize aborts the whole transaction. This is why delegation is
   **AND semantics only** — you cannot probe candidates and count successes (see §5.4).
4. **One authorization, not two.** The delegate is not recorded as a separate authorization
   entry, so `auth_contexts` in *our* `__check_auth` is unchanged by delegation. Telemetry,
   `auth_checked` events, and the decision table keep exactly the shape SPEC §2.1 pins.
5. **Revocation is the parent's job.** The protocol has no revocation registry; "which
   delegates are allowed" lives in contract storage, exactly like the agent key. That puts
   delegate control in the same admin surface (SPEC §7) and the same threat model (§10).
6. **Delegate identity is part of the signature surface.** Because the delegate must sign a
   payload bound to the guarded account address, delegation does not weaken SPEC §10.1
   signature binding.

What delegation does **not** do: it does not give a delegate its own spending cap inside our
contract, it does not let a delegate authorize a call our policy would block, and it does not
create an auditable "sub-key" object on-chain. Those must be built (Option B) or avoided.

---

## 4. SDK 27.0.6 surface actually available

Everything below exists in the pinned version; nothing here is API-shaped guesswork.

| Item | Exact shape | Notes |
|---|---|---|
| `Env::custom_account()` | `pub fn custom_account(&self) -> CustomAccount` (`env.rs:354`) | accessor; methods panic outside `__check_auth` |
| `CustomAccount::get_delegated_signers` | `pub fn get_delegated_signers(&self) -> Vec<Address>` (`custom_account.rs:274`) | empty `Vec` when the credential carries no delegates; **unsanitized** |
| `CustomAccount::delegate_auth` | `pub fn delegate_auth(&self, address: &Address)` (`custom_account.rs:317`) | panics if the address is not a non-exhausted delegate that authorized the invocation |
| `CustomAccountInterface` | unchanged `type Signature`, `__check_auth(env, Hash<32>, Signature, Vec<Context>)` | our `Signature = BytesN<64>` still valid; a delegating account typically uses `()` |
| XDR | `SorobanDelegateSignature`, `SorobanAddressCredentialsWithDelegates`, `ScSorobanCredentialsType::SorobanCredentialsAddressWithDelegates` | `stellar-xdr 27.0.0` |
| Host side | `delegate_account_auth` (`host.rs:3645`), `get_delegated_signers_for_current_auth_check` (`host.rs:3657`) | enforcing mode only |
| Not available | per-delegate scope/limit struct, threshold-of-delegates helper, `try_delegate_auth`, delegate enumeration/revocation host call, delegate support in recording mode | none of these exist in 27.0.6 |

Also relevant: a **G-address delegate is authenticated with classic Stellar account
thresholds and weights** (`builtin_contracts/account_contract.rs:177–230`: sorted public
keys, duplicate-key rejection, summed weights vs. threshold). So "one delegate address" can
already mean "an M-of-N classic multisig account" — but that M-of-N is enforced by the
*delegate's* account, outside our policy engine, and invisible to our audit surface.

---

## 5. Design options for scoped sub-keys

### Option A — Registered delegate allowlist, one delegate per authorization ("session key")

`__check_auth` verifies the agent key **or** accepts a single registered delegate address from
`get_delegated_signers()`, then `delegate_auth`s it. The delegate signs the same payload; the
full policy pipeline still runs on the same contexts.

- **Scope:** whatever the parent policy already enforces — nothing extra. A "session key" here
  is just an additional approver, not a narrower one.
- **Revocation:** `remove_delegate` admin/agent entrypoint writing the same kind of storage key
  as the agent key.
- **Cost:** ~0 extra storage reads for the happy path, one extra authentication call.
- **Risk:** every accepted delegate is a full alternative signer for *all* contexts. If the
  intent was "this key may only spend 10 XLM/day", this option does not deliver it. Naming it a
  scoped sub-key would be a lie.

### Option B — Delegate to a sub-account contract that enforces its own scope

The guarded account registers *contract* delegates (a "sub-authority" contract deployed per
session/scope). Because `delegate_auth` forwards the parent's full context set to the
delegate's `__check_auth`, that contract can run its own, narrower policy — e.g. per-asset cap,
recipient allowlist, expiry ledger — and reject anything outside it. The parent still runs its
own pipeline, so enforcement is the **intersection** of both policies.

- **Scope:** genuinely expressible (own storage, own config, own limits).
- **Revocation:** retire the delegate address (or let the sub-contract expire by ledger).
- **Cost:** a second contract invocation per authorization (CPU/rent), plus a second audit
  surface; the sub-contract's storage must be TTL-maintained (SPEC §9.5 concerns apply to it).
- **Risk:** the sub-contract sees the same contexts and must parse SAC args again; its
  correctness is now part of the security story. A bug there is a *loosening* only to the
  extent the parent already allows — but it is still a new contract to audit and to prove on
  testnet.

### Option C — Keep keys inside the account (v2 multi-sig, no delegation)

N registered keys, each signing the same `signature_payload`, verified in `__check_auth` with
our own threshold/role logic (the model in
[multi-sig-threshold-models.md](multi-sig-threshold-models.md)). No delegate credentials, no
second contract, no protocol dependency.

- **Scope:** roles and thresholds are ours to define (agent keys vs. recovery keys); scoped
  sub-keys can be modelled as role + per-role policy.
- **Revocation:** storage write in our contract; already the model for agent-key rotation.
- **Cost:** signature bytes grow with N (64 B each, plus per-signature verify cost); no extra
  invocation.
- **Risk:** none new; it is the v1 mechanism generalised.

### 5.4 Why delegation cannot express M-of-N (the decisive finding)

`delegate_auth` **aborts on failure** and there is no `try` variant. So inside `__check_auth`
you cannot "attempt" a delegate and continue: the first unauthenticated delegate kills the
transaction. The only workable shapes are:

- call `delegate_auth` for every attached delegate → **all must authorize (AND)**;
- pick one delegate and delegate to it → 1-of-N by *client* choice, not by on-chain threshold.

Counting valid signatures and comparing to a threshold requires verifying them yourself —
i.e. Option C. Delegation can therefore *add* an approver, but it cannot *count* approvers.
Any claim that #2's M-of-N could sit on CAP-71 is wrong, and that is exactly the trap this
spike existed to close.

### Comparison

| | A: delegate allowlist | B: sub-account contract | C: in-account keys |
|---|---|---|---|
| Real scoping (cap/recipient/expiry) | ✗ (parent policy only) | ✓ (delegate's own policy) | ✓ (role + policy) |
| M-of-N threshold | ✗ | ✗ (per delegate) | ✓ |
| Parent policy still enforced | ✓ | ✓ (intersection) | ✓ |
| New contract to audit | ✗ | ✓ | ✗ |
| Extra invocation per auth | ✗ | ✓ | ✗ |
| Protocol dependency | CAP-71 (27) | CAP-71 (27) | none |
| Works with simulation as-is | ✗ (client must assemble delegates) | ✗ | ✓ (existing flow) |
| Revocation path | storage + admin fn | storage + admin fn | storage + admin fn |
| Fits current `Signature = BytesN<64>` | needs `()`/enum | needs `()`/enum | extends type |

---

## 6. Decision

### 6.1 On "build #2's multi-sig on top of delegation": **REJECT** (with rationale)

1. Delegation is AND-only; M-of-N needs counting, which the host does not offer (§5.4).
2. Per-delegate scope is not a protocol concept; the parent cannot bound a delegate, so
   "threshold built on delegates" would either be 1-of-N by client choice or N-of-N.
3. It would make the account's `Signature` type a delegate-credential carrier, forcing every
   integrator and the SDK to assemble `ADDRESS_WITH_DELEGATES` entries for a feature that
   needs none.
4. It adds a second contract (Option B) and a second audit surface to reach a goal Option C
   reaches inside the contract we already ship.

### 6.2 On adopting CAP-71 in v2 at all: **DEFER with trigger conditions**

Adopt only when **all** of the following hold (the AutoGPT-revisit pattern used elsewhere in
this repo's backlog):

- **T1 — a concrete integrator requirement for an external approver** that is not satisfiable
  by adding a key to the account: e.g. a custodian/HSM-held key that must co-sign, or a
  per-session delegate contract with its own limits.
- **T2 — the delegating path is proven on testnet**, including nested delegation, sorted/
  duplicate-address rejection, exhaustion reuse, and a scoped delegate contract rejecting an
  out-of-scope call (proof fixture in `tests/fixtures/`).
- **T3 — the sub-contract, if Option B is chosen, has its own tests, TTL story and audit note**
  (SPEC §9.5, §10).

Until T1–T3 are met, `Signature = BytesN<64>` stays as-is and no delegate credential is
accepted. If any delegate is ever accepted, it will be a registered, admin-governed address,
never an arbitrary one taken from `get_delegated_signers()`.

### 6.3 Effect on #2 (the v2 gate)

**Unblocked.** #2 proceeds with **Option C**: N keys and role/threshold logic inside
`__check_auth`, per
[multi-sig-threshold-models.md](multi-sig-threshold-models.md). #2 must not wait on CAP-71,
and must not design its `Signature` type around delegate credentials.

---

## 7. What this record changes, and what it does not

- **SPEC §1.1** now links here, so the "available but out of v1 scope" note has a decision
  behind it rather than an omission.
- **No contract code changes.** `Signature`, `__check_auth`, storage layout and error
  vocabulary are untouched; this record explicitly rejects accepting delegate credentials in
  v1.
- **No new SPEC behaviour.** If the decision ever flips to adopt, that is a new SPEC section
  with its own tests — not an edit to this file.

## 8. Open questions (for whoever picks up T1–T3)

1. Does a scoped sub-account (Option B) need its own `policy_hash`/`PolicyRevision` join key so
   indexers can attribute an authorization to a sub-authority?
2. If delegates are ever accepted alongside the agent key, does a delegate approval satisfy
   the DMS heartbeat, or only a spend? (Current answer: only the registered agent key
   heartbeats, SPEC §5.)
3. Transaction-size and simulation UX for `ADDRESS_WITH_DELEGATES` in the SDK/dashboard repos —
   cross-repo, out of scope here.

## 9. References

- CAP-0071-01, *Authentication delegation for custom accounts* (Final, protocol 27):
  <https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071-01.md>
- `soroban-sdk 27.0.6`: `src/custom_account.rs` (accessor docs and modular-account example),
  `src/env.rs:354`.
- `soroban-env-host 27.0.1`: `src/auth.rs` (`AuthenticationFrame` L524, `delegate_account_auth`
  L1026, `get_delegated_signers_for_current_auth_check` L1099, signer-tree parsing ~L2093),
  `src/builtin_contracts/account_contract.rs:177` (classic G-address authentication).
- `stellar-xdr 27.0.0`: `SorobanDelegateSignature`, `SorobanCredentialsType`.
- Stellar JS SDK, *Protocol 27 — Soroban authorization migration*
  (`buildWithDelegatesEntry`, `authorizeEntry(..., forAddress)`).
- This repo: SPEC §1.1, §2.1, §4.0, §7, §10.1; `docs/research/multi-sig-threshold-models.md`.
