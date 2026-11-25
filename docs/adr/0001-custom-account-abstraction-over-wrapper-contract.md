# ADR-0001: Use Soroban Custom Account Abstraction instead of a wrapper contract

- Status: Accepted
- Date: 2026-11-19
- Supersedes: none
- Superseded by: none

## Context

The product needs an agent runtime to move funds continuously under a policy
that a human admin can inspect and change, while the admin must never gain
fund-moving authority. The enforcement point has to be unavoidable: if the
agent can transact without passing through the policy, the policy is advice,
not a guard.

Soroban exposes `CustomAccountInterface`. A contract that implements it and is
used as the account address is invoked by the host through `__check_auth` for
every authorization that address must grant. The host supplies the contract,
function, and raw arguments of each call being authorized. The full host
surface is recorded in [SPEC §1.1](../../SPEC.md#11-sdk-and-host-surface-this-is-built-on-soroban-sdk-27).

## Decision

The guard **is** the agent's account: a Soroban contract implementing
`CustomAccountInterface`, with the registered agent Ed25519 key as its only
signer. Funds are held at the contract address by SAC tokens; the admin holds
no fund-moving authority. `__check_auth` is the single enforcement vector, and
a contract account has no classic Stellar key of its own, so every action is a
Soroban invocation and passes through it.

Normative text: [SPEC §1](../../SPEC.md#1-mechanism-and-non-custodial-guarantee).

## Rejected alternatives

### A wrapper contract in front of a normal account

The agent (or a classic Stellar account) holds the funds and calls a wrapper
that checks policy before forwarding each call.

Rejected because the agent can bypass the wrapper by calling the target
protocol directly, and the target sees the wrapper — not the agent — as the
caller, which breaks protocols that key balances or permissions on the
invoking address. Making the wrapper mandatory would require the target
protocols to cooperate, which is not a property we control.

### An off-chain policy service that signs or approves transactions

An external service decides whether a transaction is admissible and only then
releases a signature.

Rejected because enforcement would depend on the service being online and
honest, and because a compromised or unavailable service becomes either a
custodian or an outage. It also reintroduces the third-party vault the product
explicitly does not have. The on-chain signature and policy check are
verifiable by anyone after the fact.

### One proxy contract per protocol

Deploy a dedicated adapter per target protocol, each embedding the spend rules
for that protocol.

Rejected because it multiplies the trusted surface, fragments the policy and
the spend window across contracts, and repeats the same integration work for
every protocol. It also makes "what is my remaining budget?" a join across
contracts instead of a read of one account.

### A classic Stellar account with a separate policy companion

Keep the agent on a classic account and enforce policy in a second contract
that the agent is expected to call.

Rejected for the same bypass reason as the wrapper: classic operations and
direct Soroban calls do not route through a companion contract. Custom Account
Abstraction is the only mechanism on the platform where the policy is inside
the account's own authorization path.

## Consequences

- Non-custodial by construction: the admin can change policy and freeze state,
  but cannot move funds.
- Every call the account authorizes is inspectable before it executes, which is
  what makes the decision table in [SPEC §4](../../SPEC.md#4-policy-semantics--decision-table)
  possible at all.
- The account's address is a contract address (`C...`), not a `G...` key, so
  tooling must sign Soroban authorization entries rather than classic
  transactions. The `tools/agent-tx` helper exists for that path.
- The contract inherits the SDK's `Context` surface, including contract-creation
  contexts it does not want; those are default-denied rather than ignored
  ([ADR-0004](0004-deny-by-default-classification.md)).

## Revisit when

- Soroban or Stellar adds a native account-policy primitive that is enforced by
  the host below the contract layer, making a custom account unnecessary or
  strictly weaker.
- CAP-71 delegated signers mature enough that a different authority split
  (delegated agent without a bespoke contract) becomes enforceable with the same
  guarantees.
- A supported protocol requires the caller's address to be a classic `G...`
  account, which would make the contract-address model unusable for that
  integration.
