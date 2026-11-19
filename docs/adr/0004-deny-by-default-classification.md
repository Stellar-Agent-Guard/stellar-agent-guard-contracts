# ADR-0004: Classify auth contexts deny-by-default

- Status: Accepted
- Date: 2026-11-19
- Supersedes: none
- Superseded by: none

## Context

`__check_auth` receives every context the account must authorize. A context
carries a contract address, a function name, and raw `Val` arguments. Only the
Stellar Asset Contract has a fixed, knowable argument schema; for an arbitrary
protocol the guard cannot interpret what a call will do or how much value it
will move.

The account is a security boundary, so the failure mode of an unknown call must
be "reject", not "allow and hope the policy covers it". At the same time, an
operator must be able to opt a protocol in explicitly.

## Decision

Classify each context into one of a closed set — self-call, asset transfer,
asset-other-function, allowlisted protocol, contract creation, or unknown — and
admit only the paths that are explicitly configured:

- Self-calls: only `heartbeat` is admitted.
- SAC `transfer` / `transfer_from` on an allowlisted asset: recipient,
  per-transaction, and rolling-window checks apply.
- Other functions on an allowlisted SAC: blocked.
- Allowlisted protocol contract (and optional function allowlist): admitted
  (with call-count rate limiting where configured).
- Contract creation: blocked unconditionally.
- Anything else: blocked with `UnknownContract`.

The rule is affirmative: a call is admitted because it matched an explicit
policy entry, never because it failed to match a denylist. Normative text:
[SPEC §2](../../SPEC.md#2-enforcement-scope--sac-token-calls-vs-every-other-soroban-call-required-framing)
and [SPEC §6](../../SPEC.md#6-per-context-classification-and-rule-application).

## Rejected alternatives

### Allow-by-default with a denylist

Admit everything except contracts, recipients, or functions an operator has
blocked.

Rejected because the guard cannot enumerate the universe of dangerous calls in
advance. A newly deployed protocol, a renamed function, or a router the
operator has not seen would be admitted by default, and the denylist would
silently lag reality. Deny-by-default inverts the failure mode: a missing
policy entry is a false rejection (visible, recoverable) rather than a false
approval (fund loss).

### Heuristic parsing of arbitrary protocol arguments

Guess recipient/amount positions from argument types or common conventions.

Rejected because it is unsound: the same `(Address, i128)` shape can mean
different things in different protocols, and a wrong guess either blocks valid
calls or, worse, meters the wrong value and admits an overspend. The boundary
is stated honestly in [ADR-0002](0002-rolling-window-over-fixed-bucket.md)'s
rolling-window rationale and SPEC §2 rather than papered over with heuristics.

### A "trusted protocol" registry maintained by the project

Ship a list of known-good protocols and allow them implicitly.

Rejected because it makes the project a curator of protocol safety and turns
every registry update into a security decision with no on-chain evidence. It
also does not scale across the ecosystem, and it hides the operator's own
allowlist decision. The operator's policy is the registry.

### Allow unknown calls but rely on simulation/pre-flight warnings

Let the transaction execute and surface a warning from `check()`.

Rejected because pre-flight is advisory and cannot stop a transaction that is
submitted directly. Enforcement must be on the authorization path, and an
unknown call is exactly the case where the guard has no basis to approve.

## Consequences

- A new protocol integration requires an explicit `protocols` entry; forgetting
  it fails closed with a stable reason (`unknown_contract`).
- Contract creation by the agent is impossible, so the agent cannot deploy a
  new contract that later bypasses the allowlist.
- Every call kind has a named decision row and a stable error code, which is
  what makes the decision table and scenario matrix testable.
- The guard is stricter than some operators initially expect for DEX/lending
  calls; that is the documented boundary, not a bug. Fine-grained non-SAC
  enforcement is a v2 track
  ([`docs/research/non-sac-enforcement.md`](../research/non-sac-enforcement.md)).

## Revisit when

- Opt-in protocol parsers land, so specific protocols can be classified with
  readable arguments while unknown protocols stay denied.
- A declared-max or return-value-commitment scheme gives a trustworthy amount
  signal for non-SAC calls without heuristics.
- The ecosystem standardizes a machine-readable call-interface registry that the
  operator can explicitly trust and the contract can verify, rather than one the
  project curates.
