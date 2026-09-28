# Heartbeat Sources Beyond the Agent Key — Security Analysis

**Issue:** #154 (refinement of #3)
**Status:** Design analysis — recommendation proposed, maintainer sign-off required
**Cross-link:** [Multi-Sig Threshold Models](multi-sig-threshold-models.md) (#153, refinement of #2) — candidate (a) depends on that decision
**Spec anchor:** [SPEC §5 — Dead-man switch, precise definition](../../SPEC.md) (`guards against *silence*; it does not guard against a live attacker`)

---

## The question

Issue #3 asks for "additional heartbeat sources" so that operator-side tooling failures
don't cause spurious dead-man-switch (DMS) freezes. Before adding any source, the note
fixes the acceptance test it must pass:

> **Is the proposed source's attestation evidence that the *agent* is alive and under the
> operator's control?**

SPEC §5 states the DMS guards *silence*, not hostile liveness. That framing makes
`heartbeat()` more than a keep-alive: it is a **key-control proof** by the only party whose
continued operation the DMS is trying to measure. A heartbeat source is safe when a
heartbeat from it carries the same information as the agent's own heartbeat; it is harmful
when it can suppress the freeze while saying nothing about the agent.

Each candidate below is judged on that test, plus a second-order question: **does it add a
new, long-lived authority?**

## Current state (v1)

- `heartbeat()` self-calls `require_auth(env.current_contract_address())`, so it routes
  through `__check_auth` and is verified against the single registered `AgentPubkey`.
- `__check_auth` already distinguishes a heartbeat self-call from every other call:
  `ParsedCall::SelfCall { fname }` is matched at `src/engine.rs:194` and only `heartbeat`
  is permitted as a self-call.
- The registered signer is `type Signature = BytesN<64>` — **exactly one key**. Registering a
  distinct heartbeat key therefore requires multi-key support, which is v2 (#2, refined in
  [Multi-Sig Threshold Models](multi-sig-threshold-models.md)).
- Because rule #2 is evaluated on every authorization, a heartbeat arriving **after** grace
  has lapsed is rejected (`HeartbeatExpired`). Silence cannot self-revive; only the admin's
  `unfreeze()` can, and `unfreeze()` itself sets `LastHeartbeat = now`.

The important consequence for this analysis: **the freeze is not primarily an access
control; it is the alarm.** It is the only externally observable signal that the agent
stopped. Anything that can hold the account open is, by construction, holding the alarm off.

---

## Candidate (a) — Companion "watchdog" key with heartbeat-only power

**Sketch.** Register a second key that `__check_auth` accepts *only* when the auth batch is
entirely heartbeat self-calls — i.e. the batch-level condition, not per-context, since a
batch that pairs a heartbeat with a transfer must be authorized by the agent key.

**Feasibility — yes at the classifier, no at the signer.** The engine can already tell a
heartbeat self-call apart (`ParsedCall::SelfCall`, `src/engine.rs:88/194`), so the scoping
rule is expressible without new host primitives. But v1 holds one `AgentPubkey`, so the key
cannot be registered until #2's multi-key decision lands. This candidate does not add
information about the agent; it adds a **second attestor with a strictly weaker but real
authority: the power to indefinitely postpone the DMS freeze.**

**The trade-off, stated honestly.** The watchdog key is strictly weaker than the agent key
(which can heartbeat *and* spend), so it never grants authority the agent key lacks. The
benefit is posture: the monitoring process no longer needs the spending key on disk. The
cost is a new long-lived secret whose entire power is *alarm suppression* — a leaked or
coerced watchdog key means the operator's "my agent is dead" signal never fires, while no
spend authority leaks. That is a genuinely different risk profile, not a free win.

**Assessment.** Technically sound and the only candidate that matches #3's stated
motivation (relaying from separate tooling). It should not ship in v1 (one key by design,
SPEC §1.1) and should be carried as a **v2 sub-item of #2**, with an explicit requirement
that the scoped key is revocable and that SPEC §5 states its suppression power.

## Candidate (b) — Permissionless, anyone-can-heartbeat

**Sketch.** Drop the auth requirement: let any address extend `LastHeartbeat`.

**Assessment — reject.** The attestation becomes information-free. A stranger paying a fee
tells us the stranger is willing to pay a fee; it says nothing about the agent. Three
concrete harms:

1. **It falsifies the alarm.** The DMS's output is consumed by the operator as "my agent is
   dead," and by the admin runbook as the cue to run the recovery ceremony. A busybody —
   or a griefer, or a competitor — reviving the account removes the cue while the agent
   remains dead.
2. **It weakens the compromised-key backstop.** Per SPEC §5, the DMS does not stop a live
   attacker who keeps heartbeating, but the freeze *does* stop a stolen agent key the moment
   the attacker goes quiet. Permissionless heartbeats remove that floor: an attacker's
   accomplice (or the attacker's own relay) can hold the account open across the grace
   window with no agent key and no spend authority at all.
3. **It inverts the reversal path.** Today, revival requires the admin's signature. Under
   (b) the account can be revived by a stranger, and the "silence cannot self-revive"
   invariant celebrated in SPEC §5 no longer holds in spirit — plenty of parties can
   self-revive it on the agent's behalf.

## Candidate (c) — Admin heartbeat

**Sketch.** Let the admin key call `heartbeat()` (or run it on a schedule).

**Assessment — reject.** This collapses the DMS into *admin* liveness, which is a proxy for
the wrong quantity: the admin's cron being alive is not evidence that the agent is alive, so
the alarm would never fire for the failure mode the DMS exists to catch. It also inverts the
roles the SPEC assigns: the admin is the cold recovery path, deliberately kept out of
steady-state operation. Note the primitive already exists and is correctly shaped —
`unfreeze()` is the admin's liveness attestation — but it is a **considered, one-off
recovery act**, not a background keep-alive. Periodic admin heartbeats would make the
freeze unreachable in practice.

---

## Summary

| | Who can heartbeat | Contract change | Addresses #3's motivation? | Carries agent-liveness information? | Extra authority created | Verdict |
|---|---|---|---|---|---|---|
| **(a)** Watchdog key, heartbeat-only scope | Scoped second key | Yes (needs #2 multi-key) | ✅ Yes | Partially — trusted co-signer, not the agent | Yes — indefinite alarm suppression | **Defer to v2 under #2**, with revocation + SPEC §5 disclosure |
| **(b)** Permissionless | Anyone | Yes (remove auth) | ✅ Yes (delivery is trivially resilient) | ❌ No | Yes — to every account on the network | **Reject** |
| **(c)** Admin periodic heartbeat | Admin | No (already `unfreeze`-shaped) | ❌ No (admin liveness ≠ agent liveness) | ❌ No | Yes — makes the freeze unreachable | **Reject** (SPEC §5 purpose) |

## Recommendation

1. **v1: no contract change.** The off-chain relayer issue #3 was reaching for is already
   available *without* a new on-chain authority: run a second process that holds the agent
   key (KMS/HSM-backed, or an isolated monitor host) and calls `heartbeat()` on a cadence
   `≤ grace / 3`. This is the delivery redundancy that prevents spurious freezes from a
   single broken agent process, and it is exactly what `tools/agent-tx heartbeat` and
   [`examples/agent-loop.md`](../../examples/agent-loop.md) already document. Issue #3's
   remaining on-chain ask is therefore **closed by design**: only the agent key's signature
   is the liveness signal, because it is the only attestation that proves the key which
   holds spend authority is still alive and under operator control.
2. **v2: candidate (a) is a sub-item of #2**, not of #3. If a heartbeat-only scoped key is
   wanted for key-isolation reasons, it must be specified inside the multi-signature model
   ([Multi-Sig Threshold Models](multi-sig-threshold-models.md)) — same `Vec` signature and
   threshold config, plus (i) `__check_auth` accepts the scoped key only when *every*
   context in the batch is a `heartbeat` self-call, (ii) the key is revocable via
   `rotate_agent_key`, and (iii) SPEC §5 states that the scoped key can suppress the freeze.
3. **Candidates (b) and (c) are closed as rejected** with the semantic harms above; no
   follow-up issue is needed for either.

## Refined issue #3 (proposed body)

> **Dead-man switch: off-chain heartbeat delivery redundancy (no on-chain change)**
>
> **Decision (from #154):** the DMS's signal is the agent key's own attestation — it is the
> only one that proves the spending key is alive. Additional on-chain heartbeat sources are
> rejected for v1: permissionless heartbeats are information-free and defeat the alarm
> (#154 candidate b); admin keep-alives measure the wrong party (#154 candidate c); a
> heartbeat-only scoped key is a v2 sub-item of #2 because it requires multi-key support
> (#154 candidate a).
>
> **Deliverable:** documentation + tooling guidance for running a redundant heartbeat
> process with the agent key (second host / KMS-backed signer), covering cadence
> (`interval ≤ grace / 3`), pre-flight, alerting on missed heartbeats, and the stop
> conditions when grace has lapsed. Contract unchanged; SPEC §5 unchanged.
>
> **Acceptance criteria:**
> - [ ] `docs/concepts/dead-man-switch.md` / `examples/agent-loop.md` document the redundant
>       heartbeat process and the KMS/HSM signing option.
> - [ ] A missed-heartbeat alerting recommendation (what to alert on before the freeze, and
>       what the freeze itself means for operators).
> - [ ] Explicit statement that only `unfreeze()` revives an expired account, and that the
>       agent key must be able to sign from the standby process.
> - [ ] Gates green.
>
> **Dependency:** none for the documentation. The scoped-key variant remains blocked on the
> #2 multi-key decision ([#153](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/153)).

## Decision checklist (maintainer sign-off)

- [ ] Accept "off-chain relayer with the agent key" as the resolution of #3 (close #3 as
      DMS-by-design: only the agent's own silence is the signal)
- [ ] Accept rejection of candidate (b) — permissionless heartbeats
- [ ] Accept rejection of candidate (c) — admin periodic heartbeat
- [ ] Accept candidate (a) as a v2 sub-item of #2 (scoped key requires multi-key), with
      revocation and a SPEC §5 disclosure of its alarm-suppression power
- [ ] Confirm no follow-up issue is required for (b)/(c)

## Links

- [SPEC §5 — Dead-man switch](../../SPEC.md) · [SPEC §10 — Threat model](../../SPEC.md)
- [Dead-Man Switch](../concepts/dead-man-switch.md) · [heartbeat](../functions/heartbeat.md)
- [Agent runtime loop](../../examples/agent-loop.md)
- [Multi-Sig Threshold Models](multi-sig-threshold-models.md) (#153 → #2)
- Issue #3 (refined by this note) · Issue #154 (this refinement)
