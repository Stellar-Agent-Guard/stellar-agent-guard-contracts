//! Decision engine (SPEC §4/§6). Pure policy evaluation over the auth
//! `Context`s the host hands to `__check_auth` — no storage access — so the
//! whole decision table is unit-testable.

use crate::types::{Error, ParsedCall, PolicyConfig};
use crate::window::Ledger;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::{Address, Env, Symbol, TryFromVal, Vec};

pub struct AccountState {
    pub admin_frozen: bool,
    pub last_heartbeat: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Context admitted.
    Allowed,
    /// Failing reason.
    Blocked(Error),
}

/// Return advisory cap metrics from an already-loaded ledger for a specific
/// recipient. If the recipient has a per-recipient window override, the
/// effective cap and remaining headroom use that recipient's ledger;
/// otherwise the global ledger and cap are used.
pub fn cap_metrics(
    policy: &PolicyConfig,
    ledger: &Ledger,
    recipient: &Address,
) -> (Option<i128>, Option<i128>, Option<i128>) {
    let window_cap = effective_window_cap(policy, recipient);
    let per_tx_cap = (policy.per_tx_cap > 0).then_some(policy.per_tx_cap);
    let tracked_total = if has_recipient_window_cap(policy, recipient) {
        ledger.recipient_total(recipient)
    } else {
        ledger.total
    };
    let remaining = window_cap.map(|cap| cap.saturating_sub(tracked_total).max(0));
    (remaining, per_tx_cap, window_cap)
}

/// Evaluate dead-man switch health given current timestamp, last heartbeat, and policy config.
pub fn dms_health(
    now: u64,
    last_heartbeat: u64,
    policy: &PolicyConfig,
) -> crate::types::DmsHealthStatus {
    if policy.dms_grace_secs == 0 {
        return crate::types::DmsHealthStatus::Ok;
    }
    if last_heartbeat == 0 {
        return crate::types::DmsHealthStatus::Expired;
    }
    let elapsed = now.saturating_sub(last_heartbeat);
    if elapsed > policy.dms_grace_secs {
        return crate::types::DmsHealthStatus::Expired;
    }
    let warn_threshold = policy
        .dms_grace_secs
        .saturating_mul(crate::types::DMS_WARN_THRESHOLD_PERCENT)
        / 100;
    if elapsed >= warn_threshold {
        crate::types::DmsHealthStatus::Warn
    } else {
        crate::types::DmsHealthStatus::Ok
    }
}

// ── Small contains helpers (soroban Vec has no `contains`) ───────────────

#[allow(clippy::must_use_candidate)]
pub fn contains_addr(list: &Vec<Address>, a: &Address) -> bool {
    for i in 0..list.len() {
        if let Some(x) = list.get(i) {
            if &x == a {
                return true;
            }
        }
    }
    false
}

fn contains_sym(list: &Vec<Symbol>, s: &Symbol) -> bool {
    for i in 0..list.len() {
        if let Some(x) = list.get(i) {
            if &x == s {
                return true;
            }
        }
    }
    false
}

#[allow(clippy::must_use_candidate)]
fn recipient_override_cap(cfg: &PolicyConfig, recipient: &Address) -> Option<i128> {
    for i in 0..cfg.recipient_window_caps.len() {
        if let Some(rc) = cfg.recipient_window_caps.get(i) {
            if &rc.recipient == recipient && rc.cap > 0 {
                return Some(rc.cap);
            }
        }
    }
    None
}

#[allow(clippy::must_use_candidate)]
fn has_recipient_window_cap(cfg: &PolicyConfig, recipient: &Address) -> bool {
    recipient_override_cap(cfg, recipient).is_some()
}

#[allow(clippy::must_use_candidate)]
fn effective_window_cap(cfg: &PolicyConfig, recipient: &Address) -> Option<i128> {
    recipient_override_cap(cfg, recipient)
        .or_else(|| (cfg.window_cap > 0).then_some(cfg.window_cap))
}

// ── Context parsing (SPEC §6) ────────────────────────────────────────────

#[cfg(feature = "testutils")]
#[allow(clippy::must_use_candidate)]
pub fn parse_call(env: &Env, self_addr: &Address, ctx: &Context, cfg: &PolicyConfig) -> ParsedCall {
    parse_call_inner(env, self_addr, ctx, cfg)
}

#[cfg(not(feature = "testutils"))]
#[allow(clippy::must_use_candidate)]
fn parse_call(env: &Env, self_addr: &Address, ctx: &Context, cfg: &PolicyConfig) -> ParsedCall {
    parse_call_inner(env, self_addr, ctx, cfg)
}

#[allow(clippy::must_use_candidate)]
fn parse_call_inner(
    env: &Env,
    self_addr: &Address,
    ctx: &Context,
    cfg: &PolicyConfig,
) -> ParsedCall {
    match ctx {
        Context::Contract(ContractContext {
            contract,
            fn_name,
            args,
        }) => {
            if contract == self_addr {
                return ParsedCall::SelfCall {
                    fname: fn_name.clone(),
                };
            }
            let is_asset = contains_addr(&cfg.assets, contract);
            let is_protocol = cfg.protocols.iter().any(|r| r.contract == *contract);
            let fn_transfer = Symbol::new(env, "transfer");
            let fn_transfer_from = Symbol::new(env, "transfer_from");

            if is_asset && (fn_name == &fn_transfer || fn_name == &fn_transfer_from) {
                let (to_idx, amt_idx) = if fn_name == &fn_transfer {
                    (1u32, 2u32)
                } else {
                    (2u32, 3u32)
                };
                // Exact arity required: transfer = 3 args, transfer_from = 4 args.
                // Extra trailing args or short arg lists are rejected -- we do not
                // partially parse a call whose effective meaning we do not fully
                // understand (SPEC section 6.2). Falling through to Unknown = default deny.
                let expected_arity: u32 = if fn_name == &fn_transfer { 3 } else { 4 };
                if args.len() != expected_arity {
                    return ParsedCall::Unknown {
                        contract: contract.clone(),
                        fname: fn_name.clone(),
                    };
                }
                let to_val = args.get(to_idx);
                let amt_val = args.get(amt_idx);
                if let (Some(to_val), Some(amt_val)) = (to_val, amt_val) {
                    let to = Address::try_from_val(env, &to_val);
                    let amount = i128::try_from_val(env, &amt_val);
                    if let (Ok(to), Ok(amount)) = (to, amount) {
                        return ParsedCall::AssetTransfer {
                            asset: contract.clone(),
                            to,
                            amount,
                        };
                    }
                }
                // Malformed SAC args: default deny.
                return ParsedCall::Unknown {
                    contract: contract.clone(),
                    fname: fn_name.clone(),
                };
            }
            if is_asset {
                return ParsedCall::AssetOther {
                    asset: contract.clone(),
                    fname: fn_name.clone(),
                };
            }
            if is_protocol {
                return ParsedCall::Protocol {
                    contract: contract.clone(),
                    fname: fn_name.clone(),
                };
            }
            ParsedCall::Unknown {
                contract: contract.clone(),
                fname: fn_name.clone(),
            }
        }
        Context::CreateContractHostFn(_) | Context::CreateContractWithCtorHostFn(_) => {
            ParsedCall::CreateContract
        }
    }
}

// ── Decision ─────────────────────────────────────────────────────────────

#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)] // by-value host Vec avoids slice/coercion limits
pub fn decide(
    env: &Env,
    self_addr: &Address,
    policy: Option<&PolicyConfig>,
    state: &AccountState,
    ledger: &mut Ledger,
    now: u64,
    contexts: soroban_sdk::Vec<Context>,
) -> alloc::vec::Vec<Decision> {
    let mut verdicts = alloc::vec::Vec::new();

    let Some(cfg) = policy else {
        for _ in 0..contexts.len() {
            verdicts.push(Decision::Blocked(Error::NoPolicy));
        }
        return verdicts;
    };

    let account_error = if state.admin_frozen {
        Some(Error::AdminFrozen)
    } else if cfg.dms_grace_secs > 0
        && state.last_heartbeat != 0
        && now.saturating_sub(state.last_heartbeat) > cfg.dms_grace_secs
    {
        Some(Error::HeartbeatExpired)
    } else if cfg.paused {
        Some(Error::Paused)
    } else if (cfg.active_from != 0 && now < cfg.active_from)
        || (cfg.active_until != 0 && now > cfg.active_until)
    {
        Some(Error::OutsideActiveWindow)
    } else {
        None
    };

    if let Some(e) = account_error {
        for _ in 0..contexts.len() {
            verdicts.push(Decision::Blocked(e));
        }
        return verdicts;
    }

    // ── Per-context rules (SPEC §6) ──────────────────────────────────────
    // Window: prune expired entries once up front, then check every transfer
    // against the running total (current total + amounts already admitted in
    // this request). Admission is staged and committed only after every
    // context passes. Per-recipient overrides run alongside the global window.
    if cfg.window_cap > 0 || !cfg.recipient_window_caps.is_empty() {
        ledger.prune(now, cfg.window_secs);
    }
    let mut pending: i128 = 0;
    let mut admission: Vec<crate::types::SpendEntry> = Vec::new(env);
    // Running per-recipient totals staged in this request. Parallel Vecs keep
    // iteration deterministic and avoid pulling `Map` into the pure engine.
    let mut pending_recipients: Vec<Address> = Vec::new(env);
    let mut pending_recipient_amounts: Vec<i128> = Vec::new(env);
    let mut all_passed = true;

    for ctx in contexts.iter() {
        let call = parse_call(env, self_addr, &ctx, cfg);
        let ctx_decision = match call {
            ParsedCall::SelfCall { fname } => {
                if fname == Symbol::new(env, "heartbeat") {
                    Decision::Allowed
                } else {
                    Decision::Blocked(Error::SelfFunctionNotAllowed)
                }
            }
            ParsedCall::CreateContract => Decision::Blocked(Error::CreateContractNotAllowed),
            ParsedCall::Unknown { .. } => Decision::Blocked(Error::UnknownContract),
            ParsedCall::AssetOther { .. } => Decision::Blocked(Error::FunctionNotAllowed),
            ParsedCall::AssetTransfer { to, amount, .. } => {
                if amount <= 0 {
                    Decision::Blocked(Error::InvalidAmount)
                } else if contains_addr(&cfg.blocked_recipients, &to) {
                    Decision::Blocked(Error::RecipientBlocked)
                } else if !cfg.allow_any_recipient && !contains_addr(&cfg.recipients, &to) {
                    Decision::Blocked(Error::RecipientNotAllowed)
                } else if cfg.per_tx_cap > 0 && amount > cfg.per_tx_cap {
                    Decision::Blocked(Error::PerTxCapExceeded)
                } else {
                    // Window accounting: global cap plus an optional
                    // per-recipient override keyed by the destination.
                    // Projections are computed first; staging happens only
                    // when this context clears both caps.
                    let recip_cap = recipient_override_cap(cfg, &to);
                    let mut staged_recip: i128 = 0;
                    let mut staged_idx: Option<u32> = None;
                    if recip_cap.is_some() {
                        for i in 0..pending_recipients.len() {
                            if let Some(r) = pending_recipients.get(i) {
                                if r == to {
                                    staged_idx = Some(i);
                                    staged_recip = pending_recipient_amounts.get(i).unwrap_or(0);
                                    break;
                                }
                            }
                        }
                    }
                    // Cumulative against the current windows: existing totals +
                    // amounts staged earlier in this same request.
                    let global_projected =
                        ledger.total.saturating_add(pending).saturating_add(amount);
                    let recip_projected = ledger
                        .recipient_total(&to)
                        .saturating_add(staged_recip)
                        .saturating_add(amount);
                    if (cfg.window_cap > 0 && global_projected > cfg.window_cap)
                        || recip_cap.is_some_and(|cap| recip_projected > cap)
                    {
                        Decision::Blocked(Error::WindowCapExceeded)
                    } else {
                        if cfg.window_cap > 0 {
                            pending = pending.saturating_add(amount);
                            admission.push_back(crate::types::SpendEntry { ts: now, amount });
                        }
                        if recip_cap.is_some() {
                            let next = staged_recip.saturating_add(amount);
                            if let Some(idx) = staged_idx {
                                pending_recipient_amounts.set(idx, next);
                            } else {
                                pending_recipients.push_back(to.clone());
                                pending_recipient_amounts.push_back(next);
                            }
                        }
                        Decision::Allowed
                    }
                }
            }
            ParsedCall::Protocol { contract, fname } => {
                let mut found = false;
                let mut fn_ok = true;
                for i in 0..cfg.protocols.len() {
                    if let Some(rule) = cfg.protocols.get(i) {
                        if rule.contract == contract {
                            found = true;
                            fn_ok = match &rule.fns {
                                None => true,
                                Some(fns) => contains_sym(fns, &fname),
                            };
                            break;
                        }
                    }
                }
                if !found {
                    Decision::Blocked(Error::ProtocolNotAllowed)
                } else if !fn_ok {
                    Decision::Blocked(Error::FunctionNotAllowed)
                } else {
                    Decision::Allowed
                }
            }
        };

        if let Decision::Blocked(_) = &ctx_decision {
            all_passed = false;
        }
        verdicts.push(ctx_decision);
    }

    // ── Commit staged window admissions (all contexts admissible) ────────
    if all_passed {
        for e in admission.iter() {
            ledger.admit(e.ts, e.amount);
        }
        for i in 0..pending_recipients.len() {
            if let (Some(recipient), Some(amount)) =
                (pending_recipients.get(i), pending_recipient_amounts.get(i))
            {
                ledger.admit_for_recipient(env, now, recipient, amount);
            }
        }
    }

    verdicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProtocolRule, RecipientCap};
    use soroban_sdk::{auth::ContractContext, vec, Address, Env, IntoVal, Symbol, Val, Vec};

    fn addr(env: &Env, n: u8) -> Address {
        use soroban_sdk::xdr::{ContractId, Hash, ScAddress};
        let sc = ScAddress::Contract(ContractId(Hash([n; 32])));
        Address::try_from_val(env, &sc).unwrap()
    }

    fn base_policy(env: &Env) -> PolicyConfig {
        PolicyConfig {
            per_tx_cap: 0,
            window_secs: 86_400,
            window_cap: 0,
            assets: vec![env, addr(env, 1)],
            protocols: Vec::new(env),
            recipients: vec![env, addr(env, 2)],
            recipient_window_caps: Vec::new(env),
            blocked_recipients: Vec::new(env),
            allow_any_recipient: false,
            active_from: 0,
            active_until: 0,
            paused: false,
            dms_grace_secs: 0,
        }
    }

    fn alive() -> AccountState {
        AccountState {
            admin_frozen: false,
            last_heartbeat: 0,
        }
    }

    fn transfer_ctx(env: &Env, asset: u8, to: u8, amount: i128) -> Context {
        let mut args: Vec<Val> = Vec::new(env);
        args.push_back(addr(env, 9).into_val(env)); // from (ignored)
        args.push_back(addr(env, to).into_val(env));
        args.push_back(amount.into_val(env));
        Context::Contract(ContractContext {
            contract: addr(env, asset),
            fn_name: Symbol::new(env, "transfer"),
            args,
        })
    }

    fn heartbeat_ctx(env: &Env, self_addr: &Address) -> Context {
        Context::Contract(ContractContext {
            contract: self_addr.clone(),
            fn_name: Symbol::new(env, "heartbeat"),
            args: Vec::new(env),
        })
    }

    fn proto_ctx(env: &Env, c: u8, f: &str) -> Context {
        Context::Contract(ContractContext {
            contract: addr(env, c),
            fn_name: Symbol::new(env, f),
            args: Vec::new(env),
        })
    }

    fn self_addr(env: &Env) -> Address {
        addr(env, 200)
    }

    #[test]
    fn no_policy_is_default_deny() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_ctx(&env, 1, 2, 5)];
        let d = decide(&env, &sa, None, &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::NoPolicy)
        ));
    }

    #[test]
    fn allowed_transfer_admits_to_window() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.window_cap = 100;
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_ctx(&env, 1, 2, 5)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(d.first().unwrap(), Decision::Allowed));
        assert_eq!(l.total, 5);
    }

    #[test]
    fn per_tx_cap_enforced() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.per_tx_cap = 10;
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_ctx(&env, 1, 2, 11)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::PerTxCapExceeded)
        ));
        assert_eq!(l.total, 0);
    }

    #[test]
    fn recipient_allowlist_enforced_and_escaped() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = Some(base_policy(&env));
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_ctx(&env, 1, 99, 5)];
        let d = decide(&env, &sa, p.as_ref(), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::RecipientNotAllowed)
        ));
        let mut p2 = base_policy(&env);
        p2.allow_any_recipient = true;
        let ctx2 = vec![&env, transfer_ctx(&env, 1, 99, 5)];
        let d2 = decide(&env, &sa, Some(&p2), &alive(), &mut l, 1000, ctx2.clone());
        assert!(matches!(d2.first().unwrap(), Decision::Allowed));
    }

    #[test]
    fn blocked_recipient_wins_over_allowlist_and_escape_hatch() {
        let env = Env::default();
        let sa = self_addr(&env);
        let blocked_addr = addr(&env, 3);

        // Listed in both allowlist and denylist -> blocked wins.
        let mut p = base_policy(&env);
        p.recipients = vec![&env, addr(&env, 2), blocked_addr.clone()];
        p.blocked_recipients = vec![&env, blocked_addr.clone()];
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_ctx(&env, 1, 3, 5)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::RecipientBlocked)
        ));

        // allow_any_recipient true but address is blocked -> still blocked.
        let mut p2 = base_policy(&env);
        p2.allow_any_recipient = true;
        p2.blocked_recipients = vec![&env, blocked_addr.clone()];
        let d2 = decide(&env, &sa, Some(&p2), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d2.first().unwrap(),
            Decision::Blocked(Error::RecipientBlocked)
        ));

        // A different non-blocked recipient passes under the escape hatch.
        let ctx3 = vec![&env, transfer_ctx(&env, 1, 4, 5)];
        let d3 = decide(&env, &sa, Some(&p2), &alive(), &mut l, 1000, ctx3);
        assert!(matches!(d3.first().unwrap(), Decision::Allowed));
    }

    #[test]
    fn empty_blocked_recipients_list_is_no_op() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = base_policy(&env);
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_ctx(&env, 1, 2, 5)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(d.first().unwrap(), Decision::Allowed));
    }

    #[test]
    fn unlisted_asset_is_unknown_contract() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = Some(base_policy(&env));
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_ctx(&env, 7, 2, 5)];
        let d = decide(&env, &sa, p.as_ref(), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::UnknownContract)
        ));
    }

    #[test]
    fn window_cap_blocks_across_transactions_and_rolls_over() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.window_cap = 100;
        let mut l = Ledger::empty(&env);
        let d1 = decide(
            &env,
            &sa,
            Some(&p.clone()),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 60)],
        );
        assert!(matches!(d1.first().unwrap(), Decision::Allowed));
        let d2 = decide(
            &env,
            &sa,
            Some(&p.clone()),
            &alive(),
            &mut l,
            2000,
            vec![&env, transfer_ctx(&env, 1, 2, 60)],
        );
        assert!(matches!(
            d2.first().unwrap(),
            Decision::Blocked(Error::WindowCapExceeded)
        ));
        let d3 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            200_000,
            vec![&env, transfer_ctx(&env, 1, 2, 60)],
        );
        assert!(matches!(d3.first().unwrap(), Decision::Allowed));
    }

    #[test]
    fn window_checks_all_contexts_before_commit() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.window_cap = 100;
        let mut l = Ledger::empty(&env);
        let ctx = vec![
            &env,
            transfer_ctx(&env, 1, 2, 60),
            transfer_ctx(&env, 1, 2, 60),
        ];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.get(1).unwrap(),
            Decision::Blocked(Error::WindowCapExceeded)
        ));
        assert_eq!(l.total, 0);
    }

    #[test]
    fn protocol_and_function_allowlists() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.protocols = vec![
            &env,
            ProtocolRule {
                contract: addr(&env, 3),
                fns: Some(vec![&env, Symbol::new(&env, "swap")]),
            },
        ];
        let mut l = Ledger::empty(&env);
        assert!(matches!(
            decide(
                &env,
                &sa,
                Some(&p),
                &alive(),
                &mut l,
                1000,
                vec![&env, proto_ctx(&env, 3, "swap")]
            )
            .first()
            .unwrap(),
            Decision::Allowed
        ));
        assert!(matches!(
            decide(
                &env,
                &sa,
                Some(&p),
                &alive(),
                &mut l,
                1000,
                vec![&env, proto_ctx(&env, 3, "drain")]
            )
            .first()
            .unwrap(),
            Decision::Blocked(Error::FunctionNotAllowed)
        ));
        assert!(matches!(
            decide(
                &env,
                &sa,
                Some(&p),
                &alive(),
                &mut l,
                1000,
                vec![&env, proto_ctx(&env, 4, "swap")]
            )
            .first()
            .unwrap(),
            Decision::Blocked(Error::UnknownContract)
        ));
    }

    #[test]
    fn account_gates_order_beats_calls() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = Some(base_policy(&env));
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_ctx(&env, 1, 2, 1)];

        let frozen = AccountState {
            admin_frozen: true,
            last_heartbeat: 0,
        };
        assert!(matches!(
            decide(&env, &sa, p.as_ref(), &frozen, &mut l, 1000, ctx.clone())
                .first()
                .unwrap(),
            Decision::Blocked(Error::AdminFrozen)
        ));

        let mut paused = base_policy(&env);
        paused.paused = true;
        assert!(matches!(
            decide(
                &env,
                &sa,
                Some(&paused),
                &alive(),
                &mut l,
                1000,
                ctx.clone()
            )
            .first()
            .unwrap(),
            Decision::Blocked(Error::Paused)
        ));

        let mut dms = base_policy(&env);
        dms.dms_grace_secs = 100;
        let st = AccountState {
            admin_frozen: false,
            last_heartbeat: 500,
        };
        assert!(matches!(
            decide(&env, &sa, Some(&dms), &st, &mut l, 700, ctx.clone())
                .first()
                .unwrap(),
            Decision::Blocked(Error::HeartbeatExpired)
        ));
        let st2 = AccountState {
            admin_frozen: false,
            last_heartbeat: 650,
        };
        assert!(matches!(
            decide(&env, &sa, Some(&dms), &st2, &mut l, 700, ctx.clone())
                .first()
                .unwrap(),
            Decision::Allowed
        ));
    }

    #[test]
    fn heartbeat_allowed_but_expired_blocked_even_for_heartbeat() {
        let env = Env::default();
        let sa = self_addr(&env);
        let hb = vec![&env, heartbeat_ctx(&env, &sa)];
        let mut p = base_policy(&env);
        p.dms_grace_secs = 100;
        let expired = AccountState {
            admin_frozen: false,
            last_heartbeat: 500,
        };
        let mut l = Ledger::empty(&env);
        assert!(matches!(
            decide(&env, &sa, Some(&p), &expired, &mut l, 700, hb.clone())
                .first()
                .unwrap(),
            Decision::Blocked(Error::HeartbeatExpired)
        ));
        let fresh = AccountState {
            admin_frozen: false,
            last_heartbeat: 650,
        };
        assert!(matches!(
            decide(&env, &sa, Some(&p), &fresh, &mut l, 700, hb.clone())
                .first()
                .unwrap(),
            Decision::Allowed
        ));
    }

    #[test]
    fn other_self_function_rejected() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = Some(base_policy(&env));
        let mut l = Ledger::empty(&env);
        let ctx = vec![
            &env,
            Context::Contract(ContractContext {
                contract: sa.clone(),
                fn_name: Symbol::new(&env, "set_policy"),
                args: Vec::new(&env),
            }),
        ];
        let d = decide(&env, &sa, p.as_ref(), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::SelfFunctionNotAllowed)
        ));
    }

    fn transfer_ctx_with_extra_args(
        env: &Env,
        asset: u8,
        to: u8,
        amount: i128,
        extra: u32,
    ) -> Context {
        let mut args: Vec<Val> = Vec::new(env);
        args.push_back(addr(env, 9).into_val(env));
        args.push_back(addr(env, to).into_val(env));
        args.push_back(amount.into_val(env));
        for i in 0..extra {
            args.push_back(i128::from(i).into_val(env));
        }
        Context::Contract(ContractContext {
            contract: addr(env, asset),
            fn_name: Symbol::new(env, "transfer"),
            args,
        })
    }

    fn transfer_from_ctx_with_arg_count(
        env: &Env,
        asset: u8,
        to: u8,
        amount: i128,
        count: u32,
    ) -> Context {
        let mut args: Vec<Val> = Vec::new(env);
        args.push_back(addr(env, 9).into_val(env));
        args.push_back(addr(env, 8).into_val(env));
        args.push_back(addr(env, to).into_val(env));
        args.push_back(amount.into_val(env));
        if count < 4 {
            let mut short: Vec<Val> = Vec::new(env);
            for i in 0..count {
                if let Some(v) = args.get(i) {
                    short.push_back(v);
                }
            }
            args = short;
        } else {
            for i in 4..count {
                args.push_back(i128::from(i).into_val(env));
            }
        }
        Context::Contract(ContractContext {
            contract: addr(env, asset),
            fn_name: Symbol::new(env, "transfer_from"),
            args,
        })
    }

    #[test]
    fn arity_guard_transfer_4_args_is_denied() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = base_policy(&env);
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_ctx_with_extra_args(&env, 1, 2, 5, 1)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::UnknownContract)
        ));
    }

    #[test]
    fn arity_guard_transfer_2_args_is_denied() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = base_policy(&env);
        let mut l = Ledger::empty(&env);
        let mut args: Vec<Val> = Vec::new(&env);
        args.push_back(addr(&env, 9).into_val(&env));
        args.push_back(addr(&env, 2).into_val(&env));
        let ctx = vec![
            &env,
            Context::Contract(ContractContext {
                contract: addr(&env, 1),
                fn_name: Symbol::new(&env, "transfer"),
                args,
            }),
        ];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::UnknownContract)
        ));
    }

    #[test]
    fn arity_guard_transfer_from_5_args_is_denied() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = base_policy(&env);
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_from_ctx_with_arg_count(&env, 1, 2, 5, 5)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::UnknownContract)
        ));
    }

    #[test]
    fn arity_guard_transfer_from_3_args_is_denied() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = base_policy(&env);
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_from_ctx_with_arg_count(&env, 1, 2, 5, 3)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::UnknownContract)
        ));
    }

    #[test]
    fn arity_guard_transfer_from_4_args_is_allowed() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = base_policy(&env);
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_from_ctx_with_arg_count(&env, 1, 2, 5, 4)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(d.first().unwrap(), Decision::Allowed));
    }

    #[test]
    fn per_recipient_cap_enforced_independently() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        let r2 = addr(&env, 2);
        let r3 = addr(&env, 3);
        p.recipients = vec![&env, r2.clone(), r3.clone()];
        p.window_cap = 1_000; // generous global cap
        p.recipient_window_caps = vec![
            &env,
            RecipientCap {
                recipient: r2.clone(),
                cap: 100,
            },
        ];
        let mut l = Ledger::empty(&env);

        // r2 is bound by its per-recipient cap.
        let d1 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 101)],
        );
        assert!(matches!(
            d1.first().unwrap(),
            Decision::Blocked(Error::WindowCapExceeded)
        ));

        // r3 is not in the override map, so it falls back to the global cap.
        let d2 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 3, 500)],
        );
        assert!(matches!(d2.first().unwrap(), Decision::Allowed));

        // Allowed spends to r2 are tracked only in its own ledger.
        let d3 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 80)],
        );
        assert!(matches!(d3.first().unwrap(), Decision::Allowed));
        let d4 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 21)],
        );
        assert!(matches!(
            d4.first().unwrap(),
            Decision::Blocked(Error::WindowCapExceeded)
        ));
    }

    #[test]
    fn per_recipient_cap_stages_cumulatively_within_request() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.window_cap = 1_000;
        p.recipient_window_caps = vec![
            &env,
            RecipientCap {
                recipient: addr(&env, 2),
                cap: 100,
            },
        ];
        let mut l = Ledger::empty(&env);

        let ctx = vec![
            &env,
            transfer_ctx(&env, 1, 2, 60),
            transfer_ctx(&env, 1, 2, 50), // cumulative 110 > 100
        ];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx);
        assert!(matches!(
            d.get(1).unwrap(),
            Decision::Blocked(Error::WindowCapExceeded)
        ));
        assert_eq!(l.recipient_total(&addr(&env, 2)), 0);
    }

    #[test]
    fn per_recipient_and_global_caps_both_bind() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        let r2 = addr(&env, 2);
        p.window_cap = 50; // tighter global cap
        p.recipient_window_caps = vec![
            &env,
            RecipientCap {
                recipient: r2.clone(),
                cap: 100,
            },
        ];
        let mut l = Ledger::empty(&env);

        // The per-recipient cap (100) is higher, but the global cap (50) blocks first.
        let d = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 60)],
        );
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::WindowCapExceeded)
        ));
    }

    #[test]
    fn per_recipient_cap_with_allow_any_recipient() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.allow_any_recipient = true;
        p.window_cap = 1_000;
        p.recipient_window_caps = vec![
            &env,
            RecipientCap {
                recipient: addr(&env, 2),
                cap: 50,
            },
        ];
        let mut l = Ledger::empty(&env);

        // Listed recipient is bound by its per-recipient cap.
        let d1 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 51)],
        );
        assert!(matches!(
            d1.first().unwrap(),
            Decision::Blocked(Error::WindowCapExceeded)
        ));

        // Unlisted recipient falls back to the global cap and is allowed.
        let d2 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 99, 500)],
        );
        assert!(matches!(d2.first().unwrap(), Decision::Allowed));
    }
}
