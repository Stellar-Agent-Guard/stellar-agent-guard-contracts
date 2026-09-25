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

pub enum Decision {
    /// Every context admitted; window updates applied to `ledger`.
    Allowed,
    /// First failing reason.
    Blocked(Error),
}

/// Return advisory cap metrics from an already-loaded ledger. The current
/// policy has no per-asset overrides, so effective asset caps equal the
/// configured caps.
pub fn cap_metrics(
    policy: &PolicyConfig,
    ledger: &Ledger,
) -> (Option<i128>, Option<i128>, Option<i128>) {
    let window_cap = (policy.window_cap > 0).then_some(policy.window_cap);
    let per_tx_cap = (policy.per_tx_cap > 0).then_some(policy.per_tx_cap);
    let remaining = window_cap.map(|cap| cap.saturating_sub(ledger.total).max(0));
    (remaining, per_tx_cap, window_cap)
}

// ── Small contains helpers (soroban Vec has no `contains`) ───────────────

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

// ── Context parsing (SPEC §6) ────────────────────────────────────────────

fn parse_call(env: &Env, self_addr: &Address, ctx: &Context, cfg: &PolicyConfig) -> ParsedCall {
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

#[allow(clippy::needless_pass_by_value)] // by-value host Vec avoids slice/coercion limits
pub fn decide(
    env: &Env,
    self_addr: &Address,
    policy: Option<&PolicyConfig>,
    state: &AccountState,
    ledger: &mut Ledger,
    now: u64,
    contexts: soroban_sdk::Vec<Context>,
) -> Decision {
    let Some(cfg) = policy else {
        return Decision::Blocked(Error::NoPolicy);
    };

    // ── Account-level gates (SPEC §4, rules 1-5) ─────────────────────────
    if state.admin_frozen {
        return Decision::Blocked(Error::AdminFrozen);
    }
    if cfg.dms_grace_secs > 0
        && state.last_heartbeat != 0
        && now.saturating_sub(state.last_heartbeat) > cfg.dms_grace_secs
    {
        return Decision::Blocked(Error::HeartbeatExpired);
    }
    if cfg.paused {
        return Decision::Blocked(Error::Paused);
    }
    if (cfg.active_from != 0 && now < cfg.active_from)
        || (cfg.active_until != 0 && now > cfg.active_until)
    {
        return Decision::Blocked(Error::OutsideActiveWindow);
    }

    // ── Per-context rules (SPEC §6) ──────────────────────────────────────
    // Window: prune expired entries once up front, then check every transfer
    // against the running total (current total + amounts already admitted in
    // this request). Admission is staged and committed only after every
    // context passes.
    if cfg.window_cap > 0 {
        ledger.prune(now, cfg.window_secs);
    }
    let mut pending: i128 = 0;
    let mut admission: Vec<crate::types::SpendEntry> = Vec::new(env);
    for ctx in contexts.iter() {
        let call = parse_call(env, self_addr, &ctx, cfg);
        match call {
            // heartbeat is the only allowed self-call.
            ParsedCall::SelfCall { fname } => {
                if fname != Symbol::new(env, "heartbeat") {
                    return Decision::Blocked(Error::SelfFunctionNotAllowed);
                }
            }
            ParsedCall::CreateContract => {
                return Decision::Blocked(Error::CreateContractNotAllowed);
            }
            ParsedCall::Unknown { .. } => return Decision::Blocked(Error::UnknownContract),
            ParsedCall::AssetOther { .. } => return Decision::Blocked(Error::FunctionNotAllowed),
            ParsedCall::AssetTransfer { to, amount, .. } => {
                if amount <= 0 {
                    return Decision::Blocked(Error::InvalidAmount);
                }
                if !cfg.allow_any_recipient && !contains_addr(&cfg.recipients, &to) {
                    return Decision::Blocked(Error::RecipientNotAllowed);
                }
                if cfg.per_tx_cap > 0 && amount > cfg.per_tx_cap {
                    return Decision::Blocked(Error::PerTxCapExceeded);
                }
                if cfg.window_cap > 0 {
                    // Cumulative against the current window: existing total +
                    // amounts staged earlier in this same request.
                    let projected = ledger.total.saturating_add(pending);
                    if projected.saturating_add(amount) > cfg.window_cap {
                        return Decision::Blocked(Error::WindowCapExceeded);
                    }
                    pending = pending.saturating_add(amount);
                    admission.push_back(crate::types::SpendEntry { ts: now, amount });
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
                    return Decision::Blocked(Error::ProtocolNotAllowed);
                }
                if !fn_ok {
                    return Decision::Blocked(Error::FunctionNotAllowed);
                }
            }
        }
    }

    // ── Commit staged window admissions (all contexts admissible) ────────
    for e in admission.iter() {
        ledger.admit(e.ts, e.amount);
    }

    Decision::Allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ProtocolRule;
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
        assert!(matches!(d, Decision::Blocked(Error::NoPolicy)));
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
        assert!(matches!(d, Decision::Allowed));
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
        assert!(matches!(d, Decision::Blocked(Error::PerTxCapExceeded)));
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
        assert!(matches!(d, Decision::Blocked(Error::RecipientNotAllowed)));
        let mut p2 = base_policy(&env);
        p2.allow_any_recipient = true;
        let ctx2 = vec![&env, transfer_ctx(&env, 1, 99, 5)];
        let d2 = decide(&env, &sa, Some(&p2), &alive(), &mut l, 1000, ctx2.clone());
        assert!(matches!(d2, Decision::Allowed));
    }

    #[test]
    fn unlisted_asset_is_unknown_contract() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = Some(base_policy(&env));
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_ctx(&env, 7, 2, 5)];
        let d = decide(&env, &sa, p.as_ref(), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(d, Decision::Blocked(Error::UnknownContract)));
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
        assert!(matches!(d1, Decision::Allowed));
        let d2 = decide(
            &env,
            &sa,
            Some(&p.clone()),
            &alive(),
            &mut l,
            2000,
            vec![&env, transfer_ctx(&env, 1, 2, 60)],
        );
        assert!(matches!(d2, Decision::Blocked(Error::WindowCapExceeded)));
        let d3 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            200_000,
            vec![&env, transfer_ctx(&env, 1, 2, 60)],
        );
        assert!(matches!(d3, Decision::Allowed));
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
        assert!(matches!(d, Decision::Blocked(Error::WindowCapExceeded)));
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
            ),
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
            ),
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
            ),
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
            decide(&env, &sa, p.as_ref(), &frozen, &mut l, 1000, ctx.clone()),
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
            ),
            Decision::Blocked(Error::Paused)
        ));

        let mut dms = base_policy(&env);
        dms.dms_grace_secs = 100;
        let st = AccountState {
            admin_frozen: false,
            last_heartbeat: 500,
        };
        assert!(matches!(
            decide(&env, &sa, Some(&dms), &st, &mut l, 700, ctx.clone()),
            Decision::Blocked(Error::HeartbeatExpired)
        ));
        let st2 = AccountState {
            admin_frozen: false,
            last_heartbeat: 650,
        };
        assert!(matches!(
            decide(&env, &sa, Some(&dms), &st2, &mut l, 700, ctx.clone()),
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
            decide(&env, &sa, Some(&p), &expired, &mut l, 700, hb.clone()),
            Decision::Blocked(Error::HeartbeatExpired)
        ));
        let fresh = AccountState {
            admin_frozen: false,
            last_heartbeat: 650,
        };
        assert!(matches!(
            decide(&env, &sa, Some(&p), &fresh, &mut l, 700, hb.clone()),
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
            d,
            Decision::Blocked(Error::SelfFunctionNotAllowed)
        ));
    }
}
