# Non-SAC Enforcement: Defining "Fine-Grained for Protocol Calls" Honestly

**Issue:** #152 (refinement of #1)  
**Status:** Design exploration — maintainer decision required  
**Constraint:** SPEC §2 — trustworthy amounts not in auth context generally

---

## The Core Problem

Issue #1 promises v2 "per-call amount/recipient enforcement for non-SAC protocol calls" but SPEC §2 states: **"No other Soroban contract exposes a fixed, knowable argument schema, and per-call value moved is frequently a return value or an internal effect that is not readable at authorization time."**

We must decompose #1 into honest sub-strategies.

---

## Sub-Strategy Analysis

### (a) Protocol-Specific Parsers (Known ABI Adapters)
**Concept**: Allowlist specific protocols (DEX, lending) with known function signatures; parse args at known positions (e.g., `swap(amount_in, amount_out_min, path, to, deadline)` → extract `amount_in`).

**Feasibility per SPEC §2**: 
- ✅ Works for **known, stable ABIs** (Soroswap, Phoenix, Comet, etc.)
- ❌ Fails for **any unknown/upgraded contract** — args are opaque `Vec<Val>`
- ❌ **Maintenance burden**: Every protocol upgrade breaks parser
- ❌ **Trust assumption**: Parser correctness = enforcement correctness

**Verdict**: Opt-in per `ProtocolRule`. Admin adds `parser: Option<ProtocolParser>` where `ProtocolParser` is an enum of known protocols. Not a general solution.

### (b) Count-Based Throttling (Rate Limiting)
**Concept**: Limit **number of calls** to a protocol per window (not amount). E.g., "max 10 DEX swaps per hour."

**Feasibility**:
- ✅ **Fully enforceable** — call count is visible in `auth_contexts` (every context = one call)
- ✅ **No ABI knowledge needed** — works for any protocol
- ✅ **Composable** — combine with existing window logic
- ❌ **Not amount enforcement** — but addresses "runaway loop" threat

**Verdict**: **Strongest deliverable core**. Implements as `protocol_limits: Vec<ProtocolLimitRule>` where `ProtocolLimitRule { contract, max_calls_per_window, window_secs }`.

### (c) Declared-Max-Per-Call Policy (Operator Assertion)
**Concept**: Admin declares "this protocol call moves at most X tokens"; enforcement trusts the declaration.

**Feasibility**:
- ❌ **Meaningless without parsing** — contract cannot verify the declared max matches actual args
- ❌ **No on-chain verification** — operator could lie, or protocol could change behavior
- ❌ **False sense of security** — looks like enforcement, isn't

**Verdict**: **Document why this is not enforcement**. If included, label explicitly as "advisory only — not enforced by contract."

### (d) Return-Value Commitments (Host Limitations)
**Concept**: Use host features to commit to return values / effects at auth time.

**Feasibility per SPEC §2 / host research**:
- Soroban auth context **does not expose return values** — they don't exist yet at `__check_auth` time
- Host does not provide "effects preview" at authorization
- CAP-?? (future) might add this, but not in current SDK (v27)

**Verdict**: **Research only — not buildable today**. Track as "host capability gap."

---

## Recommended Direction

**Primary deliverable**: **(b) Count-based throttling (protocol rate limits)**

- Extends existing window machinery to protocol calls
- Honest: "We limit call frequency, not call value"
- Addresses runaway-loop threat (infinite swap loop → blocked at call count)
- Composable with future amount parsing if host adds it

**Secondary (opt-in)**: **(a) Protocol-specific parsers** for major DEXes
- Behind feature flag / opt-in `ProtocolRule.parser`
- Clearly documented as "best-effort, breaks on protocol upgrade"

**Explicitly not building**: (c) Declared-max (not enforcement), (d) Return-value (host gap)

---

## Refined Issue #1 Body (Proposed)

> **Issue #1 (refined): Non-SAC protocol call enforcement — rate limiting first, parsing opt-in**
>
> **Accepted strategy**: 
> 1. **Protocol rate limiting** (core): `max_calls_per_window` per protocol, enforced via existing rolling window machinery. No ABI parsing. Addresses runaway loops.
> 2. **Opt-in protocol parsers** (secondary): For known DEXes (Soroswap, Phoenix), admin can enable `parser: Soroswap` to extract `amount_in` from `swap` args. Documented as best-effort.
> 3. **Declared-max**: Not implemented — documented as "not enforceable."
> 4. **Return-value commitments**: Tracked as host capability gap.
>
> **Sub-issues to file**:
> - `feat(core): protocol rate limiting (count-based)` — core deliverable
> - `feat(core): opt-in protocol parsers for known DEXes` — secondary
> - `research: host return-value commitments for auth-time amount verification` — long-term
>
> **Supersedes**: Original #1 "fine-grained amount/recipient" promise — replaced with honest scope.

---

## Feasibility Citations (per SPEC §2 / host / SDK 27)

- `auth_contexts` provides: `contract: Address`, `fn_name: Symbol`, `args: Vec<Val>` (raw, opaque)
- `Val` is an opaque union — no introspection without knowing the contract's ABI
- No host API for "simulate call and get return value at auth time"
- OpenZeppelin `spending_limit` plugin confirms: only meters transfer contexts, rejects non-transfer

---

## Decision Checklist (Maintainer)

- [ ] Accept protocol rate limiting as core v2 deliverable
- [ ] Accept opt-in parsers as secondary (with breakage warning)
- [ ] Reject declared-max as "enforcement"
- [ ] File sub-issues as above
- [ ] Update SPEC §2 v2 annex with this decomposition

---

## Links

- SPEC §2 (enforcement scope framing)
- Issue #1 body (to be edited by maintainer)
- This design note: `docs/research/non-sac-enforcement.md`