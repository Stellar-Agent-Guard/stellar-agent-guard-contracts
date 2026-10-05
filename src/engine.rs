//! Decision engine (SPEC §4/§6). Pure policy evaluation over the auth
//! `Context`s the host hands to `__check_auth` — no storage access — so the
//! whole decision table is unit-testable.

use crate::types::{Error, ParsedCall, PolicyConfig};
use crate::window::Ledger;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::{Address, Env, Symbol, TryFromVal, Vec};

/// Account-level state the account gates (SPEC §4 rows 1–2) are evaluated against.
pub struct AccountState {
    /// Admin-initiated freeze flag (`AdminFrozen`).
    pub admin_frozen: bool,
    /// Unix seconds of the last agent heartbeat; `0` = never.
    pub last_heartbeat: u64,
}

/// Verdict for one authorization context.
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

/// Global remaining window headroom for a policy: the rolling `window_cap`
/// minus the (already pruned) global ledger total, or `None` when the global
/// cap is disabled. This is the no-recipient branch of [`cap_metrics`], so
/// `status().window_remaining` always agrees with the `remaining_window` a
/// `check_detailed` call reports for a recipient without a per-recipient
/// override. Per-recipient headroom stays recipient-targeted and is not
/// reflected here (a global status has no recipient to project for).
#[allow(clippy::must_use_candidate)]
pub fn global_window_remaining(policy: &PolicyConfig, ledger: &Ledger) -> Option<i128> {
    let remaining = policy.window_cap.saturating_sub(ledger.total).max(0);
    (policy.window_cap > 0).then_some(remaining)
}

/// Overflow-checked three-term running sum for a rolling-window projection:
/// `base + staged + amount`.
///
/// Window totals are `i128`, caps are validated `>= 0`, and individual amounts
/// are validated `> 0`, but nothing stops a crafted amount (or an accumulated
/// total) from pushing the running sum past `i128::MAX`. The release profile
/// sets `overflow-checks = true` under `panic = "abort"`, so a raw `+` there
/// would be an accidental trap — which CONTRIBUTING rule 1 forbids on the
/// authorization path. `checked_add` turns that case into an explicit `None`;
/// the caller maps `None` to the stable `WindowCapExceeded` error (a sum that
/// exceeds `i128` necessarily exceeds any `i128` cap).
fn checked_window_projection(base: i128, staged: i128, amount: i128) -> Option<i128> {
    base.checked_add(staged)?.checked_add(amount)
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

/// Whether `a` is in `list` (soroban `Vec` has no `contains`).
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

/// Effective per-transaction cap for `asset`: a per-asset override when
/// present, otherwise the global `per_tx_cap`. Returns `None` when no cap
/// applies.
#[allow(clippy::must_use_candidate)]
pub fn effective_per_tx_cap(cfg: &PolicyConfig, asset: &Address) -> Option<i128> {
    for i in 0..cfg.asset_caps.len() {
        if let Some(ac) = cfg.asset_caps.get(i) {
            if &ac.asset == asset {
                return (ac.per_tx_cap > 0).then_some(ac.per_tx_cap);
            }
        }
    }
    (cfg.per_tx_cap > 0).then_some(cfg.per_tx_cap)
}

// ── Context parsing (SPEC §6) ────────────────────────────────────────────

/// Classifies one auth context into a [`ParsedCall`] (SPEC §6); test-only entry point.
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

/// Evaluates the SPEC §4 decision table over every auth context, returning one
/// [`Decision`] per context. Window admissions are staged and committed to
/// `ledger` only when every context is allowed.
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

    if state.admin_frozen {
        for _ in 0..contexts.len() {
            verdicts.push(Decision::Blocked(Error::AdminFrozen));
        }
        return verdicts;
    }

    let Some(cfg) = policy else {
        for _ in 0..contexts.len() {
            verdicts.push(Decision::Blocked(Error::NoPolicy));
        }
        return verdicts;
    };

    let account_error = if cfg.dms_grace_secs > 0
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
    // Protocol call rate limiting uses the same lazy pruning semantics.
    if cfg.window_cap > 0
        || !cfg.recipient_window_caps.is_empty()
        || cfg.protocol_calls_per_window > 0
    {
        ledger.prune(now, cfg.window_secs);
    }
    let mut pending: i128 = 0;
    let mut admission: Vec<crate::types::SpendEntry> = Vec::new(env);
    // Running per-recipient totals staged in this request. Parallel Vecs keep
    // iteration deterministic and avoid pulling `Map` into the pure engine.
    let mut pending_recipients: Vec<Address> = Vec::new(env);
    let mut pending_recipient_amounts: Vec<i128> = Vec::new(env);
    let mut pending_protocol_calls: u32 = 0;
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
            ParsedCall::AssetTransfer { asset, to, amount } => {
                if amount <= 0 {
                    Decision::Blocked(Error::InvalidAmount)
                } else if contains_addr(&cfg.blocked_recipients, &to) {
                    Decision::Blocked(Error::RecipientBlocked)
                } else if !cfg.allow_any_recipient && !contains_addr(&cfg.recipients, &to) {
                    Decision::Blocked(Error::RecipientNotAllowed)
                } else if effective_per_tx_cap(cfg, &asset).is_some_and(|cap| amount > cap) {
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
                    // amounts staged earlier in this same request. The sums are
                    // overflow-checked (`None` = would exceed `i128`), so a
                    // near-`i128::MAX` amount or accumulated total is a
                    // deliberate `WindowCapExceeded`, never an arithmetic trap.
                    let global_projected = checked_window_projection(ledger.total, pending, amount);
                    let recip_projected = checked_window_projection(
                        ledger.recipient_total(&to),
                        staged_recip,
                        amount,
                    );
                    let global_over = cfg.window_cap > 0
                        && match global_projected {
                            Some(projected) => projected > cfg.window_cap,
                            None => true,
                        };
                    let recip_over = match recip_cap {
                        Some(cap) => match recip_projected {
                            Some(projected) => projected > cap,
                            None => true,
                        },
                        None => false,
                    };
                    if global_over || recip_over {
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
                } else if cfg.protocol_calls_per_window > 0 {
                    // Protocol call rate limiting: check if admitting this call
                    // would exceed the per-window cap.
                    let projected_calls = ledger
                        .protocol_call_total
                        .saturating_add(pending_protocol_calls)
                        .saturating_add(1);
                    if projected_calls > cfg.protocol_calls_per_window {
                        Decision::Blocked(Error::ProtocolCallRateExceeded)
                    } else {
                        pending_protocol_calls = pending_protocol_calls.saturating_add(1);
                        Decision::Allowed
                    }
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
        for _ in 0..pending_protocol_calls {
            ledger.admit_protocol_call(now);
        }
    }

    verdicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProtocolRule, RecipientCap, MAX_WINDOW_ENTRIES};
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
            asset_caps: Vec::new(env),
            allow_any_recipient: false,
            active_from: 0,
            active_until: 0,
            paused: false,
            dms_grace_secs: 0,
            protocol_calls_per_window: 0,
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

    /// `transfer_from` context per SPEC §6.2: `(from, spender, to, amount)`.
    /// The `spender` occupies args[1] and must never be read as the recipient;
    /// the recipient is args[2] and the amount is args[3].
    fn transfer_from_ctx(
        env: &Env,
        asset: u8,
        from: u8,
        spender: u8,
        to: u8,
        amount: i128,
    ) -> Context {
        let mut args: Vec<Val> = Vec::new(env);
        args.push_back(addr(env, from).into_val(env)); // args[0] from
        args.push_back(addr(env, spender).into_val(env)); // args[1] spender
        args.push_back(addr(env, to).into_val(env)); // args[2] recipient
        args.push_back(amount.into_val(env)); // args[3] amount
        Context::Contract(ContractContext {
            contract: addr(env, asset),
            fn_name: Symbol::new(env, "transfer_from"),
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

    // ── SPEC §6.2: `transfer_from` argument positions ─────────────────────
    //
    // `transfer_from(from, spender, to, amount)`: the recipient is args[2] and
    // the amount is args[3] — the spender at args[1] is *not* the recipient.
    // Reading the wrong offset would check the allowlist against the spender
    // (letting funds reach an unlisted destination) and debit the window with
    // an address. These tests pin the offsets with cases where swapping them
    // would change the verdict.

    #[test]
    fn transfer_from_extracts_recipient_from_args_2_and_amount_from_args_3() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.allow_any_recipient = true;
        // from=9, spender=7, recipient=2, amount=5.
        let ctx = transfer_from_ctx(&env, 1, 9, 7, 2, 5);

        let parsed = parse_call(&env, &sa, &ctx, &p);
        assert!(
            matches!(parsed, ParsedCall::AssetTransfer { .. }),
            "transfer_from must parse as a fully-enforceable AssetTransfer"
        );
        if let ParsedCall::AssetTransfer { to, amount, .. } = parsed {
            assert_eq!(
                to,
                addr(&env, 2),
                "recipient must come from args[2], not the spender at args[1]"
            );
            assert_eq!(amount, 5, "amount must come from args[3]");
        }
    }

    #[test]
    fn transfer_from_checks_the_recipient_not_the_spender() {
        let env = Env::default();
        let sa = self_addr(&env);
        // Allowlist is [addr(2)]; the spender addr(7) is deliberately NOT listed.
        let mut p = base_policy(&env);
        p.window_cap = 100;
        let mut l = Ledger::empty(&env);
        // Recipient args[2]=addr(2) is allowlisted even though spender
        // args[1]=addr(7) is not.
        let ctx = vec![&env, transfer_from_ctx(&env, 1, 9, 7, 2, 5)];

        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(d.first().unwrap(), Decision::Allowed));
        assert_eq!(l.total, 5, "the window is debited with the args[3] amount");
    }

    #[test]
    fn transfer_from_swapped_offsets_would_block_the_wrong_address() {
        let env = Env::default();
        let sa = self_addr(&env);
        // Allowlist is [addr(2)].
        let p = base_policy(&env);
        let mut l = Ledger::empty(&env);
        // Swap the middle two: the *unlisted* addr(7) is now args[2] (recipient)
        // and the allowlisted addr(2) is args[1] (spender). An off-by-one that
        // read the recipient from args[1] would (wrongly) allow this.
        let ctx = vec![&env, transfer_from_ctx(&env, 1, 9, 2, 7, 5)];

        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::RecipientNotAllowed)
        ));
    }

    #[test]
    fn transfer_from_reads_amount_from_args_3_for_the_cap() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.allow_any_recipient = true;
        p.per_tx_cap = 10;
        let mut l = Ledger::empty(&env);
        // The amount lives at args[3]=50 and exceeds the cap; args[2] is an
        // address, not a number, so an off-by-one would not see 50 here.
        let ctx = vec![&env, transfer_from_ctx(&env, 1, 9, 7, 2, 50)];

        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::PerTxCapExceeded)
        ));
    }

    #[test]
    fn invalid_amount_rejections_do_not_mutate_window() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.window_cap = 100;
        let mut l = Ledger::empty(&env);
        l.admit(1000, 7);

        for amount in [0, -1] {
            let before = l.clone();
            let d = decide(
                &env,
                &sa,
                Some(&p),
                &alive(),
                &mut l,
                1000,
                vec![&env, transfer_ctx(&env, 1, 2, amount)],
            );
            assert!(matches!(
                d.first().unwrap(),
                Decision::Blocked(Error::InvalidAmount)
            ));
            assert_eq!(l, before, "rejected amount {amount} mutated the window");
        }
    }

    #[test]
    fn per_tx_cap_enforced() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.per_tx_cap = 10;
        let mut l = Ledger::empty(&env);
        l.admit(1000, 7);
        let before = l.clone();
        let ctx = vec![&env, transfer_ctx(&env, 1, 2, 11)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::PerTxCapExceeded)
        ));
        assert_eq!(l, before);
    }

    #[test]
    fn recipient_allowlist_enforced_and_escaped() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = Some(base_policy(&env));
        let mut l = Ledger::empty(&env);
        l.admit(1000, 7);
        let before = l.clone();
        let ctx = vec![&env, transfer_ctx(&env, 1, 99, 5)];
        let d = decide(&env, &sa, p.as_ref(), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::RecipientNotAllowed)
        ));
        assert_eq!(l, before);
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
        l.admit(1000, 7);
        let before = l.clone();
        let ctx = vec![&env, transfer_ctx(&env, 1, 3, 5)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::RecipientBlocked)
        ));
        assert_eq!(l, before);

        // allow_any_recipient true but address is blocked -> still blocked.
        let mut p2 = base_policy(&env);
        p2.allow_any_recipient = true;
        p2.blocked_recipients = vec![&env, blocked_addr.clone()];
        let d2 = decide(&env, &sa, Some(&p2), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d2.first().unwrap(),
            Decision::Blocked(Error::RecipientBlocked)
        ));
        assert_eq!(l, before);

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

    /// SPEC §6.2: a listed asset invoked with anything other than
    /// `transfer`/`transfer_from` (e.g. `mint`, `burn`) is classified as
    /// `AssetOther` and denied. The account is an authorizer, never a minter.
    #[test]
    fn asset_other_function_is_function_not_allowed() {
        let env = Env::default();
        let sa = self_addr(&env);
        let p = Some(base_policy(&env));
        let mut l = Ledger::empty(&env);
        // Contract 1 is in `assets`; `mint` is not a SAC transfer function.
        let ctx = vec![&env, proto_ctx(&env, 1, "mint")];
        let d = decide(&env, &sa, p.as_ref(), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.first().unwrap(),
            Decision::Blocked(Error::FunctionNotAllowed)
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
        let before_rejection = l.clone();
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
        assert_eq!(l, before_rejection);
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
        let before = l.clone();
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(
            d.get(1).unwrap(),
            Decision::Blocked(Error::WindowCapExceeded)
        ));
        assert_eq!(l, before);
    }

    #[test]
    fn caps_disabled_huge_amount_is_allowed_and_leaves_window_empty() {
        // Issue #17/#20: with both caps off the window is disabled, so an
        // amount at the i128 ceiling is a plain allowed transfer — it must
        // neither trap nor leave any spend accounting behind.
        let env = Env::default();
        let sa = self_addr(&env);
        let p = base_policy(&env); // per_tx_cap 0, window_cap 0
        let mut l = Ledger::empty(&env);
        let ctx = vec![&env, transfer_ctx(&env, 1, 2, i128::MAX)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx);
        assert!(matches!(d.first().unwrap(), Decision::Allowed));
        assert_eq!(l.total, 0);
        assert_eq!(l.entries.len(), 0);
    }

    #[test]
    fn accumulated_total_at_i128_ceiling_blocks_overflow_stably() {
        // Issue #17: once the rolled total is within reach of i128::MAX, an
        // amount that would overflow the running sum must block with the
        // stable `WindowCapExceeded` reason. Saturating arithmetic would
        // instead clamp to i128::MAX and (at a cap of i128::MAX) admit spend
        // past the cap; a raw `+` would trap under `overflow-checks`.
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.window_cap = i128::MAX;
        p.window_secs = 1_000;
        let mut l = Ledger::empty(&env);

        let d1 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, i128::MAX - 5)],
        );
        assert!(matches!(d1.first().unwrap(), Decision::Allowed));
        assert_eq!(l.total, i128::MAX - 5);

        // 6 more would overflow i128 -> deliberate stable block, no mutation.
        let before = l.clone();
        let d2 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 6)],
        );
        assert!(matches!(
            d2.first().unwrap(),
            Decision::Blocked(Error::WindowCapExceeded)
        ));
        assert_eq!(l, before);

        // 5 more lands exactly on the ceiling and is still admitted.
        let d3 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        );
        assert!(matches!(d3.first().unwrap(), Decision::Allowed));
        assert_eq!(l.total, i128::MAX);

        // Any further unit at the ceiling overflows -> blocked, not trapped.
        let before = l.clone();
        let d4 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 1)],
        );
        assert!(matches!(
            d4.first().unwrap(),
            Decision::Blocked(Error::WindowCapExceeded)
        ));
        assert_eq!(l, before);
    }

    #[test]
    fn recipient_accumulated_total_at_i128_ceiling_blocks_overflow_stably() {
        // Issue #17: the per-recipient window projection is checked too, even
        // when the global window is disabled.
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.window_cap = 0; // global window off
        p.window_secs = 1_000;
        p.recipient_window_caps = vec![
            &env,
            RecipientCap {
                recipient: addr(&env, 2),
                cap: i128::MAX,
            },
        ];
        let mut l = Ledger::empty(&env);

        let d1 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, i128::MAX - 5)],
        );
        assert!(matches!(d1.first().unwrap(), Decision::Allowed));
        assert_eq!(l.recipient_total(&addr(&env, 2)), i128::MAX - 5);

        let before = l.clone();
        let d2 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 6)],
        );
        assert!(matches!(
            d2.first().unwrap(),
            Decision::Blocked(Error::WindowCapExceeded)
        ));
        assert_eq!(l, before, "an overflowing recipient spend must not mutate");
    }

    #[test]
    /// SPEC §6.3: `fns: None` allows any fn on that contract.
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
    /// SPEC §6.3: `fns: None` wildcard — any fn on the listed contract is allowed.
    fn protocol_fns_none_allows_any_fn() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.protocols = vec![
            &env,
            ProtocolRule {
                contract: addr(&env, 3),
                fns: None,
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
                vec![&env, proto_ctx(&env, 3, "anything_else")]
            )
            .first()
            .unwrap(),
            Decision::Allowed
        ));
    }

    #[test]
    /// SPEC §6.3: listed fn allowed.
    fn protocol_listed_fn_allowed() {
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
    }

    #[test]
    /// SPEC §6.3: unlisted fn on a listed contract → `FunctionNotAllowed`.
    fn protocol_unlisted_fn_denied() {
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
                vec![&env, proto_ctx(&env, 3, "drain")]
            )
            .first()
            .unwrap(),
            Decision::Blocked(Error::FunctionNotAllowed)
        ));
    }

    #[test]
    /// SPEC §6.3: contract not in protocols → `UnknownContract`.
    fn protocol_unknown_contract_denied() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.protocols = vec![
            &env,
            ProtocolRule {
                contract: addr(&env, 3),
                fns: None,
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
                vec![&env, proto_ctx(&env, 4, "swap")]
            )
            .first()
            .unwrap(),
            Decision::Blocked(Error::UnknownContract)
        ));
    }

    #[test]
    /// SPEC §6.3: allowlist classification happens before arg inspection —
    /// a protocol contract named like an SAC is not parsed as a transfer.
    fn protocol_classification_precedes_arg_inspection() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        // Protocol contract 3 is NOT in cfg.assets, but is in cfg.protocols.
        p.protocols = vec![
            &env,
            ProtocolRule {
                contract: addr(&env, 3),
                fns: None,
            },
        ];
        let mut l = Ledger::empty(&env);
        // Call named "transfer" on protocol contract 3 with SAC-shaped args.
        // Must be classified as Protocol (allowed), not AssetTransfer.
        let ctx = vec![&env, transfer_ctx(&env, 3, 2, 5)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx.clone());
        assert!(matches!(d.first().unwrap(), Decision::Allowed));
        assert_eq!(l.total, 0);
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

    /// SPEC §4 rule 5: outside `active_from`/`active_until` every context is
    /// blocked before classification, and nothing is admitted to the window.
    #[test]
    fn outside_active_window_blocks_before_classification() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.active_from = 2_000;
        p.active_until = 3_000;
        let mut l = Ledger::empty(&env);
        // A transfer every other gate would admit, plus the self-call the
        // dead-man path allows: neither may slip past the account-level gate.
        let ctx = vec![&env, transfer_ctx(&env, 1, 2, 5), heartbeat_ctx(&env, &sa)];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1_000, ctx.clone());
        assert_eq!(d.len(), 2);
        for verdict in &d {
            assert!(matches!(
                verdict,
                Decision::Blocked(Error::OutsideActiveWindow)
            ));
        }
        assert_eq!(l.total, 0, "a blocked window must not admit spend");
    }

    #[test]
    fn active_window_boundaries_are_inclusive() {
        // SPEC §4 row 5: block when `now < active_from` or `now > active_until`,
        // so `now == active_from` and `now == active_until` are allowed. Pin
        // the exact boundary instants so an off-by-one in a refactor cannot
        // silently shift operator-defined execution windows.
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.active_from = 1_000;
        p.active_until = 2_000;
        let mut l = Ledger::empty(&env);

        // One second before the window opens: blocked.
        let d_before = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            p.active_from - 1,
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        );
        assert!(matches!(
            d_before.first().unwrap(),
            Decision::Blocked(Error::OutsideActiveWindow)
        ));

        // Exactly at `active_from`: allowed (inclusive lower bound).
        let d_from = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            p.active_from,
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        );
        assert!(matches!(d_from.first().unwrap(), Decision::Allowed));

        // Exactly at `active_until`: allowed (inclusive upper bound).
        let d_until = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            p.active_until,
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        );
        assert!(matches!(d_until.first().unwrap(), Decision::Allowed));

        // One second after the window closes: blocked.
        let d_after = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            p.active_until + 1,
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        );
        assert!(matches!(
            d_after.first().unwrap(),
            Decision::Blocked(Error::OutsideActiveWindow)
        ));
    }

    #[test]
    fn active_window_open_bounds_are_ignored() {
        // `active_from == 0` and `active_until == 0` disable the respective
        // bound entirely, so the boundary semantics above only apply to
        // configured (non-zero) bounds.
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.active_from = 0;
        p.active_until = 0;
        let mut l = Ledger::empty(&env);

        // Far before any configured window and far after: still allowed.
        for now in [0u64, 1, u64::MAX] {
            let d = decide(
                &env,
                &sa,
                Some(&p),
                &alive(),
                &mut l,
                now,
                vec![&env, transfer_ctx(&env, 1, 2, 5)],
            );
            assert!(
                matches!(d.first().unwrap(), Decision::Allowed),
                "now={now} should be allowed when both bounds are disabled"
            );
        }
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

    #[test]
    fn protocol_call_rate_limit_disabled_by_default() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.protocols = vec![
            &env,
            ProtocolRule {
                contract: addr(&env, 3),
                fns: None,
            },
        ];
        p.protocol_calls_per_window = 0; // disabled
        let mut l = Ledger::empty(&env);

        // Should allow unlimited protocol calls when disabled
        for _ in 0..10 {
            let d = decide(
                &env,
                &sa,
                Some(&p),
                &alive(),
                &mut l,
                1000,
                vec![&env, proto_ctx(&env, 3, "swap")],
            );
            assert!(matches!(d.first().unwrap(), Decision::Allowed));
        }
    }

    #[test]
    fn protocol_call_rate_limit_blocks_at_threshold() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.protocols = vec![
            &env,
            ProtocolRule {
                contract: addr(&env, 3),
                fns: None,
            },
        ];
        p.protocol_calls_per_window = 3;
        let mut l = Ledger::empty(&env);

        // First 3 calls allowed
        for i in 0..3 {
            let d = decide(
                &env,
                &sa,
                Some(&p),
                &alive(),
                &mut l,
                1000,
                vec![&env, proto_ctx(&env, 3, "swap")],
            );
            assert!(
                matches!(d.first().unwrap(), Decision::Allowed),
                "Call {} should be allowed",
                i + 1
            );
        }
        assert_eq!(l.protocol_call_total, 3);

        // 4th call blocked
        let d4 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, proto_ctx(&env, 3, "swap")],
        );
        assert!(matches!(
            d4.first().unwrap(),
            Decision::Blocked(Error::ProtocolCallRateExceeded)
        ));
        // Ledger should not be updated
        assert_eq!(l.protocol_call_total, 3);
    }

    #[test]
    fn protocol_call_rate_limit_resets_with_window() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.window_secs = 100;
        p.protocols = vec![
            &env,
            ProtocolRule {
                contract: addr(&env, 3),
                fns: None,
            },
        ];
        p.protocol_calls_per_window = 2;
        let mut l = Ledger::empty(&env);

        // Use up the limit at time 1000
        let d1 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, proto_ctx(&env, 3, "swap")],
        );
        assert!(matches!(d1.first().unwrap(), Decision::Allowed));
        let d2 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1000,
            vec![&env, proto_ctx(&env, 3, "swap")],
        );
        assert!(matches!(d2.first().unwrap(), Decision::Allowed));
        assert_eq!(l.protocol_call_total, 2);

        // Third call within window blocked
        let d3 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1050,
            vec![&env, proto_ctx(&env, 3, "swap")],
        );
        assert!(matches!(
            d3.first().unwrap(),
            Decision::Blocked(Error::ProtocolCallRateExceeded)
        ));

        // After window expires (1000 + 100 = 1100), new calls allowed
        let d4 = decide(
            &env,
            &sa,
            Some(&p),
            &alive(),
            &mut l,
            1200,
            vec![&env, proto_ctx(&env, 3, "swap")],
        );
        assert!(matches!(d4.first().unwrap(), Decision::Allowed));
        assert_eq!(l.protocol_call_total, 1);
    }

    #[test]
    fn protocol_call_rate_limit_stages_within_request() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.protocols = vec![
            &env,
            ProtocolRule {
                contract: addr(&env, 3),
                fns: None,
            },
        ];
        p.protocol_calls_per_window = 2;
        let mut l = Ledger::empty(&env);

        // Batch request: 1 call allowed, 2nd allowed, 3rd blocked (cumulative)
        let ctx = vec![
            &env,
            proto_ctx(&env, 3, "swap"),
            proto_ctx(&env, 3, "swap"),
            proto_ctx(&env, 3, "swap"), // cumulative 3 > limit of 2
        ];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx);
        assert!(matches!(d.first().unwrap(), Decision::Allowed));
        assert!(matches!(d.get(1).unwrap(), Decision::Allowed));
        assert!(matches!(
            d.get(2).unwrap(),
            Decision::Blocked(Error::ProtocolCallRateExceeded)
        ));
        // Ledger should not be updated (all-or-nothing commit)
        assert_eq!(l.protocol_call_total, 0);
    }

    #[test]
    fn self_call_and_asset_transfer_do_not_consume_protocol_rate_limit() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.window_cap = 1_000;
        p.protocols = vec![
            &env,
            ProtocolRule {
                contract: addr(&env, 3),
                fns: None,
            },
        ];
        p.protocol_calls_per_window = 2;
        let mut l = Ledger::empty(&env);

        // Mix of self-call, asset transfer, and protocol calls
        let ctx = vec![
            &env,
            heartbeat_ctx(&env, &sa),      // SelfCall - should not count
            transfer_ctx(&env, 1, 2, 100), // AssetTransfer - should not count
            proto_ctx(&env, 3, "swap"),    // Protocol - counts
            proto_ctx(&env, 3, "swap"),    // Protocol - counts
        ];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx);
        assert!(matches!(d.first().unwrap(), Decision::Allowed));
        assert!(matches!(d.get(1).unwrap(), Decision::Allowed));
        assert!(matches!(d.get(2).unwrap(), Decision::Allowed));
        assert!(matches!(d.get(3).unwrap(), Decision::Allowed));
        // Only 2 protocol calls should be counted
        assert_eq!(l.protocol_call_total, 2);
        assert_eq!(l.total, 100); // asset transfer counted separately
    }

    #[test]
    fn backstop_merge_never_admits_what_true_rolling_sum_would_reject() {
        // Issue #19: drive the ledger to exactly MAX_WINDOW_ENTRIES and one
        // past it, then assert the merge-forward backstop never *loosens*
        // enforcement: any admission the merged (over-counted) ledger allows
        // is an admission the true, un-merged rolling sum would also allow.
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.window_secs = 5_000;
        let mut l = Ledger::empty(&env);

        // Exactly MAX_WINDOW_ENTRIES distinct seconds (amount 1 each): the
        // bound is not exceeded, so no merge has happened yet.
        for ts in 0..(MAX_WINDOW_ENTRIES as u64) {
            l.admit(ts, 1);
        }
        assert_eq!(l.entries.len() as usize, MAX_WINDOW_ENTRIES);

        // One more distinct second crosses the bound: the two oldest entries
        // merge forward into a single entry at the NEWER timestamp.
        l.admit(MAX_WINDOW_ENTRIES as u64, 1);
        assert_eq!(l.entries.len() as usize, MAX_WINDOW_ENTRIES);
        let head = l.entries.first().unwrap();
        assert_eq!(head.ts, 1, "merged ts must be the newer of the two");
        assert_eq!(head.amount, 2);

        // Prune at the exact point where the true (un-merged) ts-0 spend has
        // expired; the merged entry keeps ts 1, so that amount is retained.
        p.window_cap = (MAX_WINDOW_ENTRIES as i128) + 1;
        l.prune(p.window_secs, p.window_secs);
        let true_rolling_sum = MAX_WINDOW_ENTRIES as i128; // ts 1..=MAX alive
        assert!(
            l.total >= true_rolling_sum,
            "merge must over-count, never under-count"
        );

        // Property: merged_allows(amount) => true_allows(amount).
        let mut observed_strictness = false;
        for amount in [1i128, 2, 3, 5, 8] {
            let mut trial = l.clone();
            let verdict = decide(
                &env,
                &sa,
                Some(&p),
                &alive(),
                &mut trial,
                p.window_secs,
                vec![&env, transfer_ctx(&env, 1, 2, amount)],
            );
            let merged_allows = matches!(verdict.first().unwrap(), Decision::Allowed);
            let true_allows = true_rolling_sum + amount <= p.window_cap;
            assert!(
                !merged_allows || true_allows,
                "post-merge admitted {amount} that the true rolling sum rejects"
            );
            if !merged_allows && true_allows {
                observed_strictness = true;
            }
        }
        assert!(
            observed_strictness,
            "expected the over-count to make at least one admission stricter"
        );
    }

    #[test]
    fn multi_asset_batch_unit_mixing_summation() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.assets = vec![&env, addr(&env, 1), addr(&env, 2)];
        p.window_cap = 150;
        p.per_tx_cap = 100;
        let mut l = Ledger::empty(&env);
        let ctx = vec![
            &env,
            transfer_ctx(&env, 1, 2, 40),
            transfer_ctx(&env, 2, 2, 60),
        ];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, ctx);
        assert!(matches!(d.first().unwrap(), Decision::Allowed));
        assert_eq!(l.total, 100);
    }

    /// SPEC §3.1 / §6 Invariant: Staged window admissions commit only if every context passes.
    ///
    /// When evaluating a multi-context batch where one context passes and another is blocked,
    /// the staged spend of the passing context must never be committed to the ledger.
    /// A subsequent transfer within the window must still fit the pre-batch budget.
    #[test]
    fn failed_multi_context_batch_never_commits_staged_window_admissions() {
        let env = Env::default();
        let sa = self_addr(&env);
        let mut p = base_policy(&env);
        p.window_cap = 100;
        p.per_tx_cap = 80;
        let mut l = Ledger::empty(&env);

        // Batch: context 1 is valid (40 <= 80 per-tx, 40 <= 100 window),
        // context 2 is blocked (90 > 80 per-tx).
        let batch = vec![
            &env,
            transfer_ctx(&env, 1, 2, 40),
            transfer_ctx(&env, 1, 2, 90),
        ];
        let d = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, batch);
        assert_eq!(d.len(), 2);
        assert!(matches!(d.first().unwrap(), Decision::Allowed));
        assert!(matches!(
            d.get(1).unwrap(),
            Decision::Blocked(Error::PerTxCapExceeded)
        ));

        // Ledger total and entries must be unchanged (all-or-nothing).
        assert_eq!(l.total, 0);
        assert_eq!(l.len(), 0);

        // Subsequent in-window transfer of 70 must succeed against the unconsumed budget of 100.
        // (If the staged 40 had committed, 40 + 70 = 110 would have exceeded window_cap 100).
        let subsequent = vec![&env, transfer_ctx(&env, 1, 2, 70)];
        let d2 = decide(&env, &sa, Some(&p), &alive(), &mut l, 1000, subsequent);
        assert!(matches!(d2.first().unwrap(), Decision::Allowed));
        assert_eq!(l.total, 70);
        assert_eq!(l.len(), 1);
    }
}
