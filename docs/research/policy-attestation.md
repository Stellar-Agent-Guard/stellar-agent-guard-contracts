# Verifiable Off-Chain Policy Attestation

**Issue:** #151  
**Status:** Design exploration — no code until decision recorded  
**Linked:** SPEC §1.1 (CAP-71 note), hash-read issue (prerequisite)

---

## Problem Statement

An agent bootstrapping trust needs to know which policy it runs under without trusting its own RPC feed. The proposal: admin signs `policy_hash()` output off-chain; agent verifies signature before starting its loop ("I am running under policy P as attested by admin A").

---

## Threat Model Analysis

### What the threat actually is
- **Compromised RPC lying about policy**: An attacker controlling the agent's RPC endpoint could return a different `policy()` response than what's on-chain.
- **Agent self-verification**: The agent wants cryptographic proof that the policy it reads matches what the admin installed.

### Why on-chain verification is stronger
The agent can **directly read the chain** via `policy()` — this is a trustless read from the Soroban host. The contract's storage is the source of truth. An off-chain signature adds nothing over a direct chain read unless:
1. The agent cannot read the chain (air-gapped, no RPC access)
2. The agent wants to verify *before* any chain interaction (bootstrap trust)
3. The agent wants to detect RPC censorship (RPC returns stale data)

### Does off-chain attestation add value over direct chain read?

| Scenario | Direct `policy()` read | Off-chain attestation |
|----------|------------------------|----------------------|
| Normal operation | ✅ Trustless, current | ❌ Extra complexity |
| RPC returns stale data | ❌ Agent sees old policy | ✅ Signature binds to hash at signing time |
| RPC returns fabricated data | ❌ Agent sees fake policy | ✅ Signature verification fails |
| Air-gapped agent | ❌ Cannot read chain | ✅ Can verify pre-loaded attestation |
| Admin key compromised | ❌ Policy changed on-chain | ❌ Attacker can sign new hash |

**Key insight**: If the agent has *any* RPC access, it can just call `policy()` directly — that's the ground truth. The attestation only helps if the agent **cannot** read the chain at bootstrap time, or wants to detect a *stale* (not fabricated) RPC response.

---

## Design Schemes

### Scheme A: Env var / file with signature + policy hash
```
ADMIN_ATTESTATION="policy_hash=<sha256>;signature=<ed25519_sig>;admin_pubkey=<pubkey>;signed_at=<unix_ts>"
```
- Agent loads at startup, verifies `ed25519_verify(admin_pubkey, policy_hash, signature)`
- Then calls `policy()` on-chain and verifies `sha256(policy_json) == policy_hash`

### Scheme B: Separate attestation file
```
/etc/stellar-agent-guard/attestation.json
{
  "policy_hash": "sha256:...",
  "signature": "ed25519:...",
  "admin_pubkey": "ed25519:...",
  "signed_at": 1234567890,
  "expires_at": 1234567890  // optional
}
```

### Scheme C: Embedded in policy metadata (on-chain)
- Admin calls `set_policy_with_attestation(config, signature)` — but this requires on-chain verification, which defeats the "off-chain" purpose.

---

## Replay Considerations

- **Hash binds content**: `policy_hash = sha256(canonical_json(policy))` — any policy change changes the hash
- **Signature binds admin key**: Only the admin's Ed25519 key can produce valid signatures
- **Expiry (optional)**: `expires_at` limits validity window; without it, old attestations remain valid until policy changes
- **Replay attack**: An old attestation for a *previous* policy is harmless — the hash won't match current `policy()`. An attestation for the *current* policy can be replayed indefinitely unless expiry is used.

---

## Recommendation: Deferral with Trigger

**Off-chain attestation does not add meaningful security over direct `policy()` chain read for the typical agent deployment model (agent has RPC access).**

The only legitimate use cases:
1. **Air-gapped agents** that cannot read chain at bootstrap
2. **Stale-data detection** (RPC returns cached response) — but this is better solved by the agent checking `policy_revision` (on-chain counter, see `DataKey::PolicyRevision`) and detecting staleness

**Decision**: Document deferral. Build when first external integrator requests it with a concrete air-gapped or stale-data threat model.

**Trigger condition**: First external integrator asks for this feature with a deployment architecture that cannot read `policy()` at startup.

---

## Links

- SPEC §1.1 (CAP-71 delegation note — related but distinct)
- Hash-read issue (prerequisite: `policy_hash()` read function)
- This design note recorded in `docs/research/policy-attestation.md`