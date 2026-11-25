# ADR-0002: Use a genuinely rolling spend window, not a fixed bucket

- Status: Accepted
- Date: 2026-11-19
- Supersedes: none
- Superseded by: none

## Context

A per-transaction cap alone does not stop a runaway agent: an agent can send
many admissible transactions in a short period. The guard therefore needs a
second limit over time — "at most X within any window of Y seconds" — evaluated
on-chain at authorization time.

The window has to be computed from ledger time (`env.ledger().timestamp()`,
one-second granularity), because the submitter's wall clock is untrusted and
the contract cannot schedule background work. State is persistent and paid for
by rent, so the accounting structure must be bounded and lazily maintained.

## Decision

Keep a genuinely rolling window: each admitted spend carries its ledger
timestamp, and a spend is counted if it falls within `window_secs` of the
candidate transaction. Expired entries are pruned lazily on access, dense
same-second spends coalesce into one entry, and a bounded backstop
(`MAX_WINDOW_ENTRIES = 8192`) merges the two oldest entries forward when a write
would exceed the bound. Merging forward can only over-count, so the
`window_cap` remains a hard ceiling.

The same ledger shape also meters protocol-call count
(`protocol_calls_per_window`) where the protocol allowlist admits a call but no
amount is readable.

Normative text: [SPEC §3.1](../../SPEC.md#31-the-window-is-genuinely-rolling--not-a-fixed-bucket).

## Rejected alternatives

### A fixed bucket that resets at midnight (or every N seconds)

Count spend since the start of the current calendar day (or current aligned
N-second bucket) and reset at the boundary.

Rejected because it does not provide the guarantee operators think it does:
spend at 23:59 and spend at 00:01 are two minutes apart but land in different
buckets and are never counted together. The burst-at-the-boundary case is
exactly the case a spend guard exists to catch. Two spends inside any
`window_secs` span must be counted together for the cap to mean anything.

### A token bucket or leaky bucket with a continuous refill

Maintain a balance that refills at a rate and is debited per spend.

Rejected because the refill rate is a second parameter that operators must
tune, the resulting guarantee is not "no more than X in any Y-second span"
(a token bucket permits a burst up to the bucket size after idling), and the
continuous refill state is more expensive to explain, audit, and pin with a
test than a timestamped entry list. The product promise is the simpler,
stronger span guarantee.

### Recomputing the window off-chain from transaction history

Let the SDK or dashboard reconstruct spend from Horizon/RPC and warn before
signing.

Rejected as an enforcement mechanism because it cannot reject a transaction;
it is advisory pre-flight only. The contract already exposes `check()` for an
advisory read ([SPEC §7.2](../../SPEC.md#72-preflight--simulate-a-transfer-doc-alias-for-check));
that is a convenience on top of the on-chain gate, not a replacement.

### An unbounded entry list

Keep every spend forever and scan the live prefix on each authorization.

Rejected because persistent storage and rent are finite and the scan cost grows
without bound, which converts a spend guard into a denial-of-service surface.

## Consequences

- The cap is a true ceiling over any `window_secs` span, including boundary
  bursts.
- Cost is proportional to expired entries pruned plus live entries, not to the
  account's lifetime, because pruning is lazy and prefix-based.
- At extreme density (≥8192 distinct spend seconds inside one window) the
  forward merge makes enforcement conservative — it can reject spend the exact
  policy would have admitted, but can never admit spend policy would reject.
- The guarantee is observable in tests such as
  `window::tests::ledger_second_changes_window_membership_at_boundary` and the
  measured prune-cost test named in SPEC §3.1.

## Revisit when

- The host exposes a native rate-limiting primitive with a span guarantee, so
  the contract no longer has to carry the ledger.
- Agents routinely produce more than 8192 distinct spend seconds within one
  window, making the conservative merge bias operationally significant rather
  than pathological.
- Storage/rent changes make an alternative accounting structure (for example a
  verified sparse structure) cheaper at the same guarantee.
