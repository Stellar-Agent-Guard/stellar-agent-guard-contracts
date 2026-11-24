# Architecture Decision Records

This directory records the mechanism decisions that took real reasoning and
that a new contributor would otherwise re-litigate. It exists because a
well-meant revert in a contract that gates fund movement is a real risk: the
SPEC explains **what** the mechanism is, but not **what was rejected** or
**what would have to change** for the answer to change.

## Format

These ADRs use plain Markdown with the four sections the issue asks for —
**Context**, **Decision**, **Rejected alternatives**, and **Revisit when** —
plus a Status and Date header. That is a Nygard-style record with an explicit
"revisit" trigger; it is deliberately not MADR's full template. If the
maintainer prefers another convention, convert the set in one commit rather than
letting formats drift.

Status values: `Proposed`, `Accepted`, `Superseded by ADR-NNNN`, `Deprecated`.
Never rewrite an accepted ADR to change its decision — add a new ADR and mark the
old one superseded. The decision history is the point.

## Index

| ADR | Decision | Status |
|---|---|---|
| [ADR-0001](0001-custom-account-abstraction-over-wrapper-contract.md) | Soroban Custom Account Abstraction, not a wrapper contract | Accepted |
| [ADR-0002](0002-rolling-window-over-fixed-bucket.md) | A genuinely rolling spend window, not a fixed bucket | Accepted |
| [ADR-0003](0003-ed25519-single-key-over-multisig-v1.md) | One registered Ed25519 key in v1, not multi-sig | Accepted |
| [ADR-0004](0004-deny-by-default-classification.md) | Deny-by-default classification of auth contexts | Accepted |

## Template

Copy this block into `NNNN-short-decision-title.md` (next free number), fill
every section, and add the row to the index above. Keep the rejected
alternatives concrete: "we did not want the complexity" is not a record, but
the specific failure mode of the alternative is.

```markdown
# ADR-NNNN: <decision in one line>

- Status: Proposed
- Date: YYYY-MM-DD
- Supersedes: none
- Superseded by: none

## Context

What forced a decision? State the constraints (host surface, threat model,
operational needs) and the facts that were true when the decision was made.

## Decision

What was chosen, stated as an implementable rule. Link the SPEC section that
carries the normative version.

## Rejected alternatives

For each alternative: what it was, why it lost, and what evidence or failure
mode decided it. Include the "obvious" option a new contributor is likely to
propose.

## Consequences

What the decision makes easy, what it makes expensive, and which invariants or
tests now depend on it.

## Revisit when

The observable conditions that would reopen the decision. If there are none,
say so rather than leaving the section empty.
```
