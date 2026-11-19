# ADR-0003: Use one registered Ed25519 key in v1, not multi-sig

- Status: Accepted
- Date: 2026-11-19
- Supersedes: none
- Superseded by: none

## Context

`CustomAccountInterface` requires the account to choose a `Signature` type and
verify it inside `__check_auth`. The account needs an agent identity that the
runtime can use unattended, 24/7, with no interactive approval per transaction.
The admin must be able to recover from key loss or compromise without gaining
fund-moving authority.

The authentication path is also the place where a mistake is most expensive: it
executes before policy evaluation, and a malformed check becomes a host trap
rather than a stable denial reason.

## Decision

`type Signature = BytesN<64>`: exactly one registered Ed25519 public key,
stored at `initialize` and replaceable only by the admin through
`rotate_agent_key`. `__check_auth` verifies the signature over the host's
32-byte payload with `env.crypto().ed25519_verify` **before** reading policy
state. Key rotation records the outgoing and incoming key fingerprints in
`agent_rotated` telemetry.

Normative text: [SPEC §1.1](../../SPEC.md#11-sdk-and-host-surface-this-is-built-on-soroban-sdk-27)
and [SPEC §7](../../SPEC.md#7-public-surface--exact-signatures-and-auth-placement).

## Rejected alternatives

### Native multi-sig / threshold signatures in v1

Require k-of-n agent keys to authorize a transaction.

Rejected for v1 because it expands the stored surface (signer set, threshold,
per-signer replay state) and the decision surface (which signatures count, how
partial signatures are represented and ordered, how a signer is added or
removed) before there is a demonstrated operator need. It also makes the
unattended runtime harder: every transaction needs k online signers or a
signing service that reintroduces the centralization the design avoids.
Threshold models are researched in
[`docs/research/multi-sig-threshold-models.md`](../research/multi-sig-threshold-models.md)
as a v2 candidate.

### CAP-71 delegated signers

Use `get_delegated_signers()` / `delegate_auth` to delegate authorization to
another account.

Rejected for v1 scope: it moves the authority question to another account's
authorization policy without simplifying the guard's own decision table, and
the delegation surface is still evolving. The SDK capability is recorded in
SPEC §1.1 as available but out of scope.

### Passkey / secp256r1 (WebAuthn) signers

Let a human approve with a platform passkey.

Rejected as the **agent** signer because the agent is an unattended runtime, not
a human at a browser; a passkey would make routine operation depend on an
interactive ceremony. It may be a useful additional admin or recovery factor
later, which is a separate decision.

### Session keys or per-protocol sub-keys

Issue ephemeral keys scoped to a protocol or time range.

Rejected because the policy engine, not the key, is the scoping mechanism here.
Adding key-level scopes would duplicate policy in two places and complicate
rotation and auditing. One registered key plus an on-chain policy is easier to
reason about and to prove.

## Consequences

- Key compromise means full agent authority until the admin rotates the key or
  freezes the account; the dead-man switch and admin freeze are the containment
  controls, and rotation is the recovery path (`docs/key-rotation.md`).
- The admin never needs the agent key and cannot sign as the agent, preserving
  the non-custodial split.
- Signature verification is one fixed-size check with a stable host error
  (`InvokeError::Abort`), not a threshold policy that can fail in several ways.
- SDK/dashboard surfaces assume a single signature; adding threshold support is
  an ABI and telemetry change, not a configuration toggle.

## Revisit when

- Operators need shared control of one agent account (for example two services
  that must both approve high-value transactions).
- The threshold-model research concludes that a k-of-n design can be added
  without weakening the non-custodial or fail-closed properties.
- A recovery model is required that a single key plus admin rotation cannot
  provide (for example loss of both agent and admin keys).
