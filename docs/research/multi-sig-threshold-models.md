# Multi-Sig Threshold Models Against Soroban Auth Realities

**Issue:** #153 (refinement of #2)  
**Status:** Design exploration — maintainer sign-off required per branch protection  
**Cross-link:** SDK `AgentSigner` interface awaits this decision

---

## Current State (v1)

- `CustomAccountInterface::Signature = BytesN<64>` (single Ed25519 key)
- `__check_auth` verifies: `ed25519_verify(agent_pubkey, signature_payload, signature)`
- Admin is separate (`Address`, can be classic or contract), governs policy/keys only

---

## The Core Question: M-of-N Over What?

### Model 1: M-of-N Signatures Over Same Payload (Straightforward)
- N registered keys (all Ed25519, or mixed Ed25519 + contract signers via CAP-71)
- Each signs the *same* `signature_payload` (the transaction auth digest)
- Contract verifies each signature against its registered pubkey
- Count valid signatures ≥ threshold M
- **Pros**: Simple, maps directly to current `__check_auth` flow
- **Cons**: All signers must be online/coordinated for every transaction

### Model 2: Key Roles (Agent Keys vs Admin-Recovery Keys)
- **Agent keys** (threshold M₁): Used for routine `__check_auth` — heartbeat, spend
- **Admin-recovery keys** (threshold M₂): Used only for `rotate_agent_key`, `unfreeze`, policy changes
- **Pros**: Separation of concerns; recovery keys stay cold
- **Cons**: Two threshold configurations; complex auth routing

### Model 3: DMS / Heartbeat Semantics Under Multi-Key
- **Who heartbeats?**
  - Option A: Any agent key can heartbeat (sufficient for liveness)
  - Option B: Threshold of agent keys must heartbeat (stronger liveness)
  - Option C: Dedicated "heartbeat key" (simplest, but single point of failure)
- **DMS freeze**: If threshold of agent keys fails to heartbeat → freeze
- **Revival**: Admin-recovery threshold signs `unfreeze`

---

## Migration Story for Deployed Single-Key Accounts

**Critical constraint**: Soroban contract code is **immutable**. A deployed v1 account cannot become v2 multi-sig.

### Options:
1. **Redeploy v2 contract, migrate funds**: New contract address → user must migrate balances. Honest about immutability.
2. **Proxy/wrapper pattern**: v1 account delegates to v2 via CAP-71 — but CAP-71 is out of v1 scope.
3. **Social migration**: Document that v1 accounts are single-key forever; v2 is for new deployments only.

**Recommendation**: Option 1 (redeploy) with clear documentation. No in-place upgrade path exists.

---

## Refined Issue #2 Body (Proposed)

> **Issue #2 (refined): Multi-signature / threshold policy enforcement**
>
> **Goal**: Allow accounts to require M-of-N signatures for authorization, with key-role separation.
>
> **Recommended model**: Model 1 + Model 2 combined
> - `Signature = Vec<BytesN<64>>` (list of Ed25519 signatures)
> - Config: `agent_keys: Vec<BytesN<32>>`, `agent_threshold: u32`
> - Config: `recovery_keys: Vec<BytesN<32>>`, `recovery_threshold: u32` (optional, for admin functions)
> - `__check_auth`: Verify ≥ `agent_threshold` signatures from `agent_keys` over `signature_payload`
> - Admin functions (`set_policy`, `rotate_agent_key`, `unfreeze`): Require ≥ `recovery_threshold` from `recovery_keys` (or fall back to single `Admin` address if not configured)
> - Heartbeat: Any single `agent_key` can heartbeat (Option A) — keeps it simple
> - DMS: If no agent key heartbeats within grace → freeze
>
> **Test plan sketch**:
> - 2-of-3 agent keys: any 2 can authorize spend; 1 cannot
> - 1-of-2 recovery keys: either can rotate keys/unfreeze
> - Heartbeat from key A keeps account alive; key B missing is fine
> - Migration: New contract deployment required; document in README
>
> **SDK cross-link**: `stellar-agent-guard-sdk` `AgentSigner` interface must support multi-key signing flow (coordinator collects signatures, submits tx with all sigs).

---

## Decision Checklist (Maintainer Sign-off)

- [ ] Accept Model 1+2 combined as v2 direction
- [ ] Accept redeploy-only migration (no in-place upgrade)
- [ ] Accept "any agent key can heartbeat" for DMS
- [ ] File sub-issues: (a) contract changes, (b) SDK `AgentSigner` multi-key, (c) dashboard multi-key UI
- [ ] Link SDK issue from this note and vice versa

---

## Links

- SPEC §1.1 (v2 annex placeholder)
- SDK multi-sig prep issue (cross-link pending)
- This design note: `docs/research/multi-sig-threshold-models.md`