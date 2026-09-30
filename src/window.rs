//! Rolling-window ledger (SPEC §3.1). Operates over `soroban_sdk::Vec` so it
//! is no_std/wasm-clean. Pure logic — no storage access — unit-testable with
//! a bare `Env`.
//!
//! Guarantee: a hard ceiling over any `window_secs` span. Expired entries are
//! popped lazily on access; same-second spends coalesce; at the entry bound
//! the two oldest entries merge *forward* (newer ts), which can only
//! over-count — never under-count — so the ceiling is never exceeded.
//!
//! The ledger now holds a global rolling window plus per-recipient rolling
//! windows for recipients that carry a cap override in the active policy.
//!
//! Persistent `WindowState` TTL management belongs to the storage boundary in
//! `lib.rs` (`persist_get`/`save_ledger`); this module transforms only the
//! in-memory snapshot after storage has loaded it.

use crate::types::{
    ProtocolCallEntry, RecipientWindowState, SpendEntry, WindowState, MAX_WINDOW_ENTRIES,
};
use soroban_sdk::{contracttype, Address, Env};

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientLedger {
    pub recipient: Address,
    pub total: i128,
    pub entries: soroban_sdk::Vec<SpendEntry>,
}

impl RecipientLedger {
    #[allow(clippy::must_use_candidate)]
    fn empty(env: &Env, recipient: Address) -> Self {
        Self {
            recipient,
            total: 0,
            entries: soroban_sdk::Vec::new(env),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    pub total: i128,
    pub entries: soroban_sdk::Vec<SpendEntry>,
    /// Per-recipient rolling windows, populated only for recipients that have a
    /// configured per-recipient cap override. Storage is bounded by the same
    /// cardinality limit applied to the recipient allowlist (SPEC §8).
    pub recipients: soroban_sdk::Vec<RecipientLedger>,
    /// Protocol call count entries (for rate limiting).
    pub protocol_call_entries: soroban_sdk::Vec<ProtocolCallEntry>,
    /// Cached rolling total of protocol calls (sum of non-expired entries).
    pub protocol_call_total: u32,
}

impl Ledger {
    #[allow(clippy::must_use_candidate)]
    pub fn empty(env: &Env) -> Self {
        Self {
            total: 0,
            entries: soroban_sdk::Vec::new(env),
            recipients: soroban_sdk::Vec::new(env),
            protocol_call_entries: soroban_sdk::Vec::new(env),
            protocol_call_total: 0,
        }
    }

    /// Build from persisted state, recomputing every total so a corrupted
    /// cached total can never admit spend.
    #[allow(clippy::must_use_candidate)]
    pub fn from_state(env: &Env, state: WindowState) -> Self {
        let global = ledger_from_entries(env, state.entries);
        let mut recipients: soroban_sdk::Vec<RecipientLedger> = soroban_sdk::Vec::new(env);
        for i in 0..state.recipients.len() {
            if let Some(rws) = state.recipients.get(i) {
                let inner = ledger_from_entries(env, rws.entries);
                recipients.push_back(RecipientLedger {
                    recipient: rws.recipient,
                    total: inner.total,
                    entries: inner.entries,
                });
            }
        }
        let proto_call_info = protocol_call_entries_from_state(env, state.protocol_call_entries);
        Self {
            total: global.total,
            entries: global.entries,
            recipients,
            protocol_call_entries: proto_call_info.entries,
            protocol_call_total: proto_call_info.total,
        }
    }

    /// Serialize back to persistent state. Every `total` is recomputed on
    /// load, so what we write here can be trusted but need not be canonical.
    #[allow(clippy::must_use_candidate)]
    pub fn to_state(&self, env: &Env) -> WindowState {
        let mut recipient_states: soroban_sdk::Vec<RecipientWindowState> =
            soroban_sdk::Vec::new(env);
        for i in 0..self.recipients.len() {
            if let Some(r) = self.recipients.get(i) {
                recipient_states.push_back(RecipientWindowState {
                    recipient: r.recipient.clone(),
                    total: r.total,
                    entries: r.entries.clone(),
                });
            }
        }
        WindowState {
            total: self.total,
            entries: self.entries.clone(),
            recipients: recipient_states,
            protocol_call_entries: self.protocol_call_entries.clone(),
        }
    }

    #[allow(clippy::must_use_candidate, clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        self.entries.len()
    }

    /// Drop fully-expired entries from every tracked window and update totals.
    ///
    /// Expiry is tested as `entry.ts + window_secs <= now` (addition form)
    /// rather than `entry.ts <= now - window_secs` (subtraction form): the
    /// two are algebraically identical but the addition form never underflows
    /// at low timestamps, so an entry recorded at ledger ts 0 cannot be
    /// wrongly treated as expired just because `now - window_secs` would clip
    /// to 0 under saturating subtraction.
    pub fn prune(&mut self, now: u64, window_secs: u64) {
        prune_entries(&mut self.total, &mut self.entries, now, window_secs);
        for i in 0..self.recipients.len() {
            if let Some(mut r) = self.recipients.get(i) {
                prune_entries(&mut r.total, &mut r.entries, now, window_secs);
                self.recipients.set(i, r);
            }
        }
        prune_protocol_call_entries(
            &mut self.protocol_call_total,
            &mut self.protocol_call_entries,
            now,
            window_secs,
        );
    }

    /// Record a spend against the global window at `now`.
    pub fn admit(&mut self, now: u64, amount: i128) {
        admit_to_ledger(&mut self.total, &mut self.entries, now, amount);
    }

    /// Current rolling total for a recipient, or zero if no per-recipient
    /// ledger is being tracked.
    #[allow(clippy::must_use_candidate)]
    pub fn recipient_total(&self, recipient: &Address) -> i128 {
        for i in 0..self.recipients.len() {
            if let Some(r) = self.recipients.get(i) {
                if &r.recipient == recipient {
                    return r.total;
                }
            }
        }
        0
    }

    /// Record a spend for `recipient` against that recipient's per-recipient
    /// window. If this is the first spend for the recipient, a fresh ledger is
    /// created. Callers must ensure the recipient is meant to be tracked (i.e.,
    /// has a configured per-recipient cap), otherwise this wastes storage.
    pub fn admit_for_recipient(&mut self, env: &Env, now: u64, recipient: Address, amount: i128) {
        for i in 0..self.recipients.len() {
            if let Some(r) = self.recipients.get(i) {
                if r.recipient == recipient {
                    let mut updated = r;
                    admit_to_ledger(&mut updated.total, &mut updated.entries, now, amount);
                    self.recipients.set(i, updated);
                    return;
                }
            }
        }
        let mut created = RecipientLedger::empty(env, recipient);
        admit_to_ledger(&mut created.total, &mut created.entries, now, amount);
        self.recipients.push_back(created);
    }

    /// Record a protocol call at `now`.
    pub fn admit_protocol_call(&mut self, now: u64) {
        admit_to_protocol_call_ledger(
            &mut self.protocol_call_total,
            &mut self.protocol_call_entries,
            now,
        );
    }
}

// ── Single rolling ledger helpers ────────────────────────────────────────────

fn ledger_from_entries(env: &Env, mut entries: soroban_sdk::Vec<SpendEntry>) -> SingleLedger {
    let mut acc: i128 = 0;
    let mut clean: soroban_sdk::Vec<SpendEntry> = soroban_sdk::Vec::new(env);
    while let Some(e) = entries.pop_front() {
        if e.amount > 0 {
            acc = acc.saturating_add(e.amount);
            clean.push_back(e);
        }
    }
    SingleLedger {
        total: acc,
        entries: clean,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SingleLedger {
    total: i128,
    entries: soroban_sdk::Vec<SpendEntry>,
}

fn prune_entries(
    total: &mut i128,
    entries: &mut soroban_sdk::Vec<SpendEntry>,
    now: u64,
    window_secs: u64,
) {
    if window_secs == 0 {
        return;
    }
    while let Some(front) = entries.first() {
        if front.ts.saturating_add(window_secs) <= now {
            *total = total.saturating_sub(front.amount);
            entries.pop_front();
        } else {
            break;
        }
    }
}

fn admit_to_ledger(
    total: &mut i128,
    entries: &mut soroban_sdk::Vec<SpendEntry>,
    now: u64,
    amount: i128,
) {
    debug_assert!(amount > 0);
    let n = entries.len();
    if n > 0 {
        if let Some(last) = entries.get(n - 1) {
            if last.ts == now {
                entries.set(
                    n - 1,
                    SpendEntry {
                        ts: now,
                        amount: last.amount.saturating_add(amount),
                    },
                );
                *total = total.saturating_add(amount);
                return;
            }
        }
    }
    entries.push_back(SpendEntry { ts: now, amount });
    *total = total.saturating_add(amount);
    if entries.len() as usize > MAX_WINDOW_ENTRIES {
        // Conservative merge: the merged entry keeps the NEWER of the two
        // timestamps, so the older amount expires later than it truly
        // should — over-counting only.
        let older = entries.first().unwrap_or(SpendEntry { ts: 0, amount: 0 });
        entries.pop_front();
        let newer = entries.first().unwrap_or(SpendEntry { ts: 0, amount: 0 });
        entries.pop_front();
        entries.push_front(SpendEntry {
            ts: newer.ts,
            amount: older.amount.saturating_add(newer.amount),
        });
    }
}

fn prune_protocol_call_entries(
    total: &mut u32,
    entries: &mut soroban_sdk::Vec<ProtocolCallEntry>,
    now: u64,
    window_secs: u64,
) {
    if window_secs == 0 {
        return;
    }
    while let Some(front) = entries.first() {
        if front.ts.saturating_add(window_secs) <= now {
            *total = total.saturating_sub(front.count);
            entries.pop_front();
        } else {
            break;
        }
    }
}

fn protocol_call_entries_from_state(
    env: &Env,
    mut entries: soroban_sdk::Vec<ProtocolCallEntry>,
) -> ProtocolCallLedger {
    let mut acc: u32 = 0;
    let mut clean: soroban_sdk::Vec<ProtocolCallEntry> = soroban_sdk::Vec::new(env);
    while let Some(e) = entries.pop_front() {
        if e.count > 0 {
            acc = acc.saturating_add(e.count);
            clean.push_back(e);
        }
    }
    ProtocolCallLedger {
        total: acc,
        entries: clean,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProtocolCallLedger {
    total: u32,
    entries: soroban_sdk::Vec<ProtocolCallEntry>,
}

fn admit_to_protocol_call_ledger(
    total: &mut u32,
    entries: &mut soroban_sdk::Vec<ProtocolCallEntry>,
    now: u64,
) {
    let n = entries.len();
    if n > 0 {
        if let Some(last) = entries.get(n - 1) {
            if last.ts == now {
                entries.set(
                    n - 1,
                    ProtocolCallEntry {
                        ts: now,
                        count: last.count.saturating_add(1),
                    },
                );
                *total = total.saturating_add(1);
                return;
            }
        }
    }
    entries.push_back(ProtocolCallEntry { ts: now, count: 1 });
    *total = total.saturating_add(1);
    if entries.len() as usize > MAX_WINDOW_ENTRIES {
        // Conservative merge: keep the newer timestamp
        let older = entries
            .first()
            .unwrap_or(ProtocolCallEntry { ts: 0, count: 0 });
        entries.pop_front();
        let newer = entries
            .first()
            .unwrap_or(ProtocolCallEntry { ts: 0, count: 0 });
        entries.pop_front();
        entries.push_front(ProtocolCallEntry {
            ts: newer.ts,
            count: older.count.saturating_add(newer.count),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{vec, Address, Env};

    fn led(env: &Env, entries: &[(u64, i128)]) -> SingleLedger {
        let mut v: soroban_sdk::Vec<SpendEntry> = soroban_sdk::Vec::new(env);
        for (ts, amount) in entries {
            v.push_back(SpendEntry {
                ts: *ts,
                amount: *amount,
            });
        }
        ledger_from_entries(env, v)
    }

    fn addr(env: &Env, n: u8) -> Address {
        use soroban_sdk::xdr::{ContractId, Hash, ScAddress};
        use soroban_sdk::TryFromVal;
        let sc = ScAddress::Contract(ContractId(Hash([n; 32])));
        Address::try_from_val(env, &sc).unwrap()
    }

    #[test]
    fn prune_drops_only_expired() {
        let env = Env::default();
        let mut l = led(&env, &[(0, 10), (100, 5), (200, 7)]);
        prune_entries(&mut l.total, &mut l.entries, 300, 200); // cutoff 100; ts==cutoff expired
        assert_eq!(l.total, 7);
        assert_eq!(l.entries.len(), 1);
        assert_eq!(l.entries.first().unwrap().ts, 200);
    }

    #[test]
    fn admit_coalesces_three_same_second_spends() {
        let env = Env::default();
        let mut ledger = Ledger::empty(&env);
        ledger.admit(100, 3);
        ledger.admit(100, 4);
        ledger.admit(100, 5);
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.entries.get(0).unwrap().ts, 100);
        assert_eq!(ledger.entries.get(0).unwrap().amount, 12);

        ledger.admit(101, 6);
        assert_eq!(ledger.entries.len(), 2);
        assert_eq!(ledger.entries.get(0).unwrap().ts, 100);
        assert_eq!(ledger.entries.get(0).unwrap().amount, 12);
        assert_eq!(ledger.entries.get(1).unwrap().ts, 101);
        assert_eq!(ledger.entries.get(1).unwrap().amount, 6);
    }

    #[test]
    fn prune_then_admit_coalesces_with_trailing_same_second_entry() {
        let env = Env::default();
        let mut ledger = Ledger::empty(&env);
        ledger.admit(0, 3);
        ledger.admit(100, 7);
        assert_eq!(ledger.entries.len(), 2);

        // At the exact expiry boundary, the oldest entry is pruned before
        // the new spend is admitted at the trailing entry's second.
        ledger.prune(100, 100);
        ledger.admit(100, 11);

        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.entries.get(0).unwrap().ts, 100);
        assert_eq!(ledger.entries.get(0).unwrap().amount, 18);
        assert_eq!(ledger.total, 18);
    }

    #[test]
    fn window_is_genuinely_rolling() {
        let env = Env::default();
        let mut total = 0i128;
        let mut entries: soroban_sdk::Vec<SpendEntry> = soroban_sdk::Vec::new(&env);
        admit_to_ledger(&mut total, &mut entries, 86_399, 50);
        admit_to_ledger(&mut total, &mut entries, 86_401, 50);
        prune_entries(&mut total, &mut entries, 86_461, 120);
        assert_eq!(total, 100);
        prune_entries(&mut total, &mut entries, 86_500, 100); // cutoff 86_400 -> ts=86_399 expired
        assert_eq!(total, 50);
    }

    #[test]
    fn exact_boundary_semantics() {
        let env = Env::default();
        let mut total = 0i128;
        let mut entries: soroban_sdk::Vec<SpendEntry> = soroban_sdk::Vec::new(&env);
        admit_to_ledger(&mut total, &mut entries, 200, 40);
        prune_entries(&mut total, &mut entries, 300, 100); // entry ts + 100 == 300 -> exactly expired
        assert_eq!(total, 0);
    }

    #[test]
    fn prune_keeps_recent_entries_at_low_timestamps() {
        // Regression: `now.saturating_sub(window_secs)` clips to 0 at low
        // timestamps and wrongly expired entries recorded at ledger ts 0 that
        // were still well inside the window.
        let env = Env::default();
        let mut total = 0i128;
        let mut entries: soroban_sdk::Vec<SpendEntry> = soroban_sdk::Vec::new(&env);
        admit_to_ledger(&mut total, &mut entries, 0, 30);
        prune_entries(&mut total, &mut entries, 50, 100); // 50s later; entry is only 50s old -> must survive
        assert_eq!(total, 30);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn backstop_merge_is_conservative_and_bounded() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let mut total = 0i128;
        let mut entries: soroban_sdk::Vec<SpendEntry> = soroban_sdk::Vec::new(&env);
        for i in 0..(MAX_WINDOW_ENTRIES + 10) {
            admit_to_ledger(&mut total, &mut entries, i as u64, 1);
        }
        assert!((entries.len() as usize) <= MAX_WINDOW_ENTRIES);
        assert_eq!(total, (MAX_WINDOW_ENTRIES + 10) as i128);
    }

    #[test]
    fn from_entries_recomputes_total() {
        let env = Env::default();
        let v = vec![
            &env,
            SpendEntry { ts: 0, amount: 10 },
            SpendEntry { ts: 1, amount: 5 },
        ];
        assert_eq!(ledger_from_entries(&env, v).total, 15);
    }

    #[test]
    fn ledger_round_trips_through_state() {
        let env = Env::default();
        let mut ledger = Ledger::empty(&env);
        ledger.admit(100, 10);
        ledger.admit_for_recipient(&env, 100, addr(&env, 1), 5);
        ledger.admit_for_recipient(&env, 101, addr(&env, 1), 3);
        ledger.admit_for_recipient(&env, 100, addr(&env, 2), 7);

        let state = ledger.to_state(&env);
        let restored = Ledger::from_state(&env, state);

        assert_eq!(restored.total, 10);
        assert_eq!(restored.recipient_total(&addr(&env, 1)), 8);
        assert_eq!(restored.recipient_total(&addr(&env, 2)), 7);
        assert_eq!(restored.recipients.len(), 2);
    }

    #[test]
    fn recipient_ledger_prunes_with_global() {
        let env = Env::default();
        let mut ledger = Ledger::empty(&env);
        let r = addr(&env, 1);
        ledger.admit_for_recipient(&env, 0, r.clone(), 10);
        ledger.admit_for_recipient(&env, 50, r.clone(), 5);
        ledger.prune(150, 100); // ts 0 exactly expired, ts 50 exactly expired
        assert_eq!(ledger.recipient_total(&r), 0);

        ledger.admit_for_recipient(&env, 100, r.clone(), 5);
        ledger.prune(199, 100); // ts 100 now inside the window
        assert_eq!(ledger.recipient_total(&r), 5);
    }

    #[test]
    fn recipient_admit_coalesces_same_second() {
        let env = Env::default();
        let mut ledger = Ledger::empty(&env);
        let r = addr(&env, 1);
        ledger.admit_for_recipient(&env, 100, r.clone(), 3);
        ledger.admit_for_recipient(&env, 100, r.clone(), 4);
        ledger.admit_for_recipient(&env, 101, r.clone(), 5);
        assert_eq!(ledger.recipient_total(&r), 12);
        assert_eq!(ledger.recipients.len(), 1);
    }

    #[test]
    fn protocol_call_counter_admits_and_coalesces() {
        let env = Env::default();
        let mut ledger = Ledger::empty(&env);
        ledger.admit_protocol_call(100);
        assert_eq!(ledger.protocol_call_total, 1);
        ledger.admit_protocol_call(100);
        assert_eq!(ledger.protocol_call_total, 2);
        assert_eq!(ledger.protocol_call_entries.len(), 1);
        ledger.admit_protocol_call(101);
        assert_eq!(ledger.protocol_call_total, 3);
        assert_eq!(ledger.protocol_call_entries.len(), 2);
    }

    #[test]
    fn protocol_call_counter_prunes_expired() {
        let env = Env::default();
        let mut ledger = Ledger::empty(&env);
        ledger.admit_protocol_call(0);
        ledger.admit_protocol_call(100);
        ledger.admit_protocol_call(200);
        assert_eq!(ledger.protocol_call_total, 3);

        ledger.prune(300, 200); // ts 0 exactly expired, ts 100 exactly expired
        assert_eq!(ledger.protocol_call_total, 1);
        assert_eq!(ledger.protocol_call_entries.len(), 1);
        assert_eq!(ledger.protocol_call_entries.first().unwrap().ts, 200);
    }

    #[test]
    fn protocol_call_counter_round_trips_through_state() {
        let env = Env::default();
        let mut ledger = Ledger::empty(&env);
        ledger.admit_protocol_call(100);
        ledger.admit_protocol_call(100);
        ledger.admit_protocol_call(101);

        let state = ledger.to_state(&env);
        let restored = Ledger::from_state(&env, state);

        assert_eq!(restored.protocol_call_total, 3);
        assert_eq!(restored.protocol_call_entries.len(), 2);
    }
}
