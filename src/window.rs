//! Rolling-window ledger (SPEC §3.1). Operates over `soroban_sdk::Vec` so it
//! is no_std/wasm-clean. Pure logic — no storage access — unit-testable with
//! a bare `Env`.
//!
//! Guarantee: a hard ceiling over any `window_secs` span. Expired entries are
//! popped lazily on access; same-second spends coalesce; at the entry bound
//! the two oldest entries merge *forward* (newer ts), which can only
//! over-count — never under-count — so the ceiling is never exceeded.

use crate::types::{SpendEntry, MAX_WINDOW_ENTRIES};
use soroban_sdk::Env;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ledger {
    pub total: i128,
    pub entries: soroban_sdk::Vec<SpendEntry>,
}

impl Ledger {
    #[allow(clippy::must_use_candidate)]
    pub fn empty(env: &Env) -> Self {
        Self {
            total: 0,
            entries: soroban_sdk::Vec::new(env),
        }
    }

    /// Build from persisted entries (consumed), recomputing the total so a
    /// corrupted cached total can never admit spend.
    #[allow(clippy::must_use_candidate)]
    pub fn from_entries(env: &Env, mut entries: soroban_sdk::Vec<SpendEntry>) -> Self {
        let mut acc: i128 = 0;
        let mut clean: soroban_sdk::Vec<SpendEntry> = soroban_sdk::Vec::new(env);
        while let Some(e) = entries.pop_front() {
            if e.amount > 0 {
                acc = acc.saturating_add(e.amount);
                clean.push_back(e);
            }
        }
        Self {
            total: acc,
            entries: clean,
        }
    }

    #[allow(clippy::must_use_candidate, clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        self.entries.len()
    }

    /// Drop fully-expired entries (front of the list) and update the total.
    ///
    /// Expiry is tested as `entry.ts + window_secs <= now` (addition form)
    /// rather than `entry.ts <= now - window_secs` (subtraction form): the
    /// two are algebraically identical but the addition form never underflows
    /// at low timestamps, so an entry recorded at ledger ts 0 cannot be
    /// wrongly treated as expired just because `now - window_secs` would clip
    /// to 0 under saturating subtraction.
    pub fn prune(&mut self, now: u64, window_secs: u64) {
        if window_secs == 0 {
            return;
        }
        while let Some(front) = self.entries.first() {
            if front.ts.saturating_add(window_secs) <= now {
                self.total = self.total.saturating_sub(front.amount);
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }

    /// Record a spend at `now`: coalesce into the trailing entry when it
    /// shares the second, otherwise append; apply the bounded conservative
    /// merge backstop when over the entry bound.
    pub fn admit(&mut self, now: u64, amount: i128) {
        debug_assert!(amount > 0);
        let n = self.entries.len();
        if n > 0 {
            if let Some(last) = self.entries.get(n - 1) {
                if last.ts == now {
                    self.entries.set(
                        n - 1,
                        SpendEntry {
                            ts: now,
                            amount: last.amount.saturating_add(amount),
                        },
                    );
                    self.total = self.total.saturating_add(amount);
                    return;
                }
            }
        }
        self.entries.push_back(SpendEntry { ts: now, amount });
        self.total = self.total.saturating_add(amount);
        if self.entries.len() as usize > MAX_WINDOW_ENTRIES {
            // Conservative merge: the merged entry keeps the NEWER of the two
            // timestamps, so the older amount expires later than it truly
            // should — over-counting only.
            let older = self
                .entries
                .first()
                .unwrap_or(SpendEntry { ts: 0, amount: 0 });
            self.entries.pop_front();
            let newer = self
                .entries
                .first()
                .unwrap_or(SpendEntry { ts: 0, amount: 0 });
            self.entries.pop_front();
            self.entries.push_front(SpendEntry {
                ts: newer.ts,
                amount: older.amount.saturating_add(newer.amount),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{vec, Env};

    fn led(env: &Env, entries: &[(u64, i128)]) -> Ledger {
        let mut v: soroban_sdk::Vec<SpendEntry> = soroban_sdk::Vec::new(env);
        for (ts, amount) in entries {
            v.push_back(SpendEntry {
                ts: *ts,
                amount: *amount,
            });
        }
        Ledger::from_entries(env, v)
    }

    #[test]
    fn prune_drops_only_expired() {
        let env = Env::default();
        let mut l = led(&env, &[(0, 10), (100, 5), (200, 7)]);
        l.prune(300, 200); // cutoff 100; ts==cutoff expired
        assert_eq!(l.total, 7);
        assert_eq!(l.len(), 1);
        assert_eq!(l.entries.get(0).unwrap().ts, 200);
    }

    #[test]
    fn admit_coalesces_same_second() {
        let env = Env::default();
        let mut l = Ledger::empty(&env);
        l.admit(100, 3);
        l.admit(100, 4);
        assert_eq!(l.len(), 1);
        assert_eq!(l.entries.get(0).unwrap().amount, 7);
        l.admit(101, 5);
        assert_eq!(l.len(), 2);
        assert_eq!(l.total, 12);
    }

    #[test]
    fn window_is_genuinely_rolling() {
        let env = Env::default();
        let mut l = Ledger::empty(&env);
        l.admit(86_399, 50);
        l.admit(86_401, 50);
        l.prune(86_461, 120);
        assert_eq!(l.total, 100);
        l.prune(86_500, 100); // cutoff 86_400 -> ts=86_399 expired
        assert_eq!(l.total, 50);
    }

    #[test]
    fn exact_boundary_semantics() {
        let env = Env::default();
        let mut l = Ledger::empty(&env);
        l.admit(200, 40);
        l.prune(300, 100); // entry ts + 100 == 300 -> exactly expired
        assert_eq!(l.total, 0);
    }

    #[test]
    fn prune_keeps_recent_entries_at_low_timestamps() {
        // Regression: `now.saturating_sub(window_secs)` clips to 0 at low
        // timestamps and wrongly expired entries recorded at ledger ts 0 that
        // were still well inside the window.
        let env = Env::default();
        let mut l = Ledger::empty(&env);
        l.admit(0, 30);
        l.prune(50, 100); // 50s later; entry is only 50s old -> must survive
        assert_eq!(l.total, 30);
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn backstop_merge_is_conservative_and_bounded() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let mut l = Ledger::empty(&env);
        for i in 0..(MAX_WINDOW_ENTRIES + 10) {
            l.admit(i as u64, 1);
        }
        assert!((l.len() as usize) <= MAX_WINDOW_ENTRIES);
        assert_eq!(l.total, (MAX_WINDOW_ENTRIES + 10) as i128);
    }

    #[test]
    fn from_entries_recomputes_total() {
        let env = Env::default();
        let v = vec![
            &env,
            SpendEntry { ts: 0, amount: 10 },
            SpendEntry { ts: 1, amount: 5 },
        ];
        assert_eq!(Ledger::from_entries(&env, v).total, 15);
    }
}
