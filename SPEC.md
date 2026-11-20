# Stellar Agent Guard — Technical Specification

## §1. Architecture & Core Design

Stellar Agent Guard is a Soroban smart contract framework providing fine-grained, policy-enforced delegation for autonomous agents on the Stellar network.

### §1.1 CAP-71 Delegation Note
The architecture leverages Soroban custom account abstractions to enforce policy limits on every invoked transaction, avoiding reliance on off-chain relayers or trusted proxies.

---

## §3. Storage Model & Fleet Operations

### §3.1 Storage Layout
Contract data is segregated between instance storage (low cost, bounded) and persistent storage (unbounded lifetime with TTL management).

### §3.2 Appendix: Shared Rolling Budget Fleet Architecture
*Design exploration for issue #307: a pooled rolling budget shared across multiple guard accounts.*

#### Motivation
Operator fleets running multiple agent accounts currently require separate, independent window caps per contract. A pooled rolling budget allows multiple guard accounts to draw from a single shared ceiling (e.g. daily aggregate limit across a fleet of 10 payout agents).

#### Design Options

##### Option A: Centralized Ledger-State Pool Contract
- **Mechanism**: A dedicated shared budget contract manages the global pool state, tracking the rolling window entries and current consumption. Each guard account queries and reserves quota from the shared contract prior to executing a transfer.
- **Storage Cost**: Low per-guard contract; single persistent storage entry in the budget contract.
- **TTL Behaviour**: Requires explicit TTL extensions on the central budget contract entry; if the budget entry expires, guarding accounts block safely.
- **Failure Modes**: Single point of failure. If the central budget contract experiences high contention or TTL expiry, all dependent guard accounts halt transactions.

##### Option B: Decentralized Quota-Delegation Receipts
- **Mechanism**: An off-chain or periodic coordinator records signed allocation receipts, or guard accounts verify a shared Merkle commitment of pool consumption stored in a shared contract.
- **Storage Cost**: Minimal on-chain state, relies on cryptographic proofs or signed state updates.
- **TTL Behaviour**: Epoch-based TTL; receipts carry expiry timestamps.
- **Failure Modes**: Relies on liveness of the distribution channel; stale proofs block spending.

#### Interaction with Window Bound (`MAX_WINDOW_ENTRIES = 8192`)
Pooled budgets either aggregate consumption counters directly (avoiding per-tx window entry bloat) or delegate window entry tracking to the central pool contract, ensuring individual accounts do not exceed storage limits.

#### Revocation of a Single Account from a Pool
An account can be revoked from a pool by updating its local policy reference from the shared budget contract address to a local or null policy, terminating its ability to draw from the pool without impacting sibling accounts.

---

## §5. Dead-Man Switch & Precise Definition
Installing or replacing a policy via `set_policy` re-arms the dead-man clock (`LastHeartbeat = now`) as a side effect, and the admin's action counts as a liveness attestation.

---

## §7. Public Surface & Exact Signatures
Agent public keys must be valid non-zero Ed25519 keys (all-zero keys are rejected).

---

## §8. Validation Rules
`initialize` and `rotate_agent_key` validate that the agent public key is not all zeros (`[0u8; 32]`), returning `InvalidConfig` if invalid.

---

## §11. Exit Criteria Checklist

| Gate / Check | Command | Evidence Link / Fixture | Verified By | Status |
|---|---|---|---|---|
| Code Formatting | `cargo fmt --check` | CI Workflow Run | Contributor / CI | [ ] |
| Clippy Lints | `cargo clippy --all-targets --all-features` | CI Workflow Run | Contributor / CI | [ ] |
| Unit & Integration Tests | `cargo test` | CI Workflow Run | Contributor / CI | [ ] |
| Fixture Parity | Checked via test suites | `tests/fixtures/` | Contributor | [ ] |
| README & Spec Synchronized | Manual review | `SPEC.md`, `README.md` | Maintainer | [ ] |
