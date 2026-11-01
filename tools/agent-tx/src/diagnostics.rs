//! Classify policy-denial evidence without trusting error-message text.

use stellar_xdr::{
    ContractEventBody, ContractEventType, DiagnosticEvent, Limits, ReadXdr, ScAddress, ScVal,
};

// Keep this vocabulary aligned with Error::reason() in src/types.rs. The unit
// test below checks the contract's canonical auth-checked vocabulary fixture.
const GUARD_BLOCK_REASONS: &[&str] = &[
    "unauthorized",
    "already_initialized",
    "not_initialized",
    "invalid_config",
    "invalid_amount",
    "no_pending_admin",
    "admin_frozen",
    "heartbeat_expired",
    "no_policy",
    "paused",
    "outside_active_window",
    "asset_not_allowed",
    "recipient_not_allowed",
    "per_tx_cap_exceeded",
    "window_cap_exceeded",
    "protocol_not_allowed",
    "function_not_allowed",
    "unknown_contract",
    "self_function_not_allowed",
    "create_contract_not_allowed",
    "recipient_blocked",
    "protocol_call_rate_exceeded",
    "decision_invariant_violation",
    "asset_fn_not_allowed",
    "too_many_auth_contexts",
];

/// A block must be a contract event from this guard, with exactly the canonical
/// ordered topics: event_auth_checked, blocked, and a known reason symbol.
/// Invalid diagnostics and unrelated failures must never count as evidence.
pub(super) fn block_reason(
    events: &[serde_json::Value],
    guard: &ScAddress,
) -> Option<&'static str> {
    let ScAddress::Contract(guard_id) = guard else {
        return None;
    };
    events.iter().find_map(|event| {
        let b64 = event["xdr"].as_str().or_else(|| event.as_str())?;
        let decoded = DiagnosticEvent::from_xdr_base64(b64, Limits::none()).ok()?;
        if decoded.event.contract_id.as_ref() != Some(guard_id)
            || decoded.event.type_ != ContractEventType::Contract
        {
            return None;
        }
        let ContractEventBody::V0(body) = decoded.event.body;
        let [ScVal::Symbol(name), ScVal::Symbol(result), ScVal::Symbol(reason)] =
            body.topics.as_slice()
        else {
            return None;
        };
        if name.0.as_slice() != b"event_auth_checked" || result.0.as_slice() != b"blocked" {
            return None;
        }
        GUARD_BLOCK_REASONS
            .iter()
            .copied()
            .find(|known| reason.0.as_slice() == known.as_bytes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::{
        ContractEvent, ContractEventV0, ContractId, ExtensionPoint, Hash, ScSymbol, VecM, WriteXdr,
    };

    fn guard() -> ScAddress {
        ScAddress::Contract(ContractId(Hash([7; 32])))
    }

    fn event(topics: &[&str]) -> DiagnosticEvent {
        DiagnosticEvent {
            in_successful_contract_call: false,
            event: ContractEvent {
                ext: ExtensionPoint::V0,
                contract_id: Some(ContractId(Hash([7; 32]))),
                type_: ContractEventType::Contract,
                body: ContractEventBody::V0(ContractEventV0 {
                    topics: VecM::try_from(
                        topics
                            .iter()
                            .map(|value| ScVal::Symbol(ScSymbol((*value).try_into().unwrap())))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap(),
                    data: ScVal::Void,
                }),
            },
        }
    }

    fn encoded(event: &DiagnosticEvent) -> serde_json::Value {
        serde_json::json!(event.to_xdr_base64(Limits::none()).unwrap())
    }

    fn valid_event() -> DiagnosticEvent {
        event(&["event_auth_checked", "blocked", "per_tx_cap_exceeded"])
    }

    #[test]
    fn all_known_guard_reasons_are_accepted_in_both_rpc_event_encodings() {
        for reason in GUARD_BLOCK_REASONS {
            let encoded = encoded(&event(&["event_auth_checked", "blocked", reason]));
            assert_eq!(
                block_reason(std::slice::from_ref(&encoded), &guard()),
                Some(*reason)
            );
            assert_eq!(
                block_reason(&[serde_json::json!({"xdr":encoded})], &guard()),
                Some(*reason)
            );
        }
    }

    #[test]
    fn known_reasons_match_the_contracts_canonical_vocabulary() {
        let vocabulary: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/auth-checked-vocabulary.json"
        ))
        .unwrap();
        let mut expected: Vec<_> = vocabulary["outcomes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|outcome| outcome["topics"][1] == "blocked")
            .map(|outcome| outcome["symbol"].as_str().unwrap())
            .collect();
        let mut actual = GUARD_BLOCK_REASONS.to_vec();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected);
    }

    #[test]
    fn missing_unknown_empty_and_non_symbol_reasons_are_rejected() {
        for topics in [
            vec!["event_auth_checked", "blocked"],
            vec!["event_auth_checked", "blocked", "future_unknown_reason"],
            vec!["event_auth_checked", "blocked", ""],
        ] {
            assert_eq!(block_reason(&[encoded(&event(&topics))], &guard()), None);
        }
        let mut wrong_type = valid_event();
        let ContractEventBody::V0(body) = &mut wrong_type.event.body;
        body.topics = vec![
            ScVal::Symbol(ScSymbol("event_auth_checked".try_into().unwrap())),
            ScVal::Symbol(ScSymbol("blocked".try_into().unwrap())),
            ScVal::U32(22),
        ]
        .try_into()
        .unwrap();
        assert_eq!(block_reason(&[encoded(&wrong_type)], &guard()), None);
    }

    #[test]
    fn reordered_extra_and_allowed_topics_do_not_prove_a_block() {
        for topics in [
            vec!["blocked", "event_auth_checked", "per_tx_cap_exceeded"],
            vec!["event_auth_checked", "per_tx_cap_exceeded", "blocked"],
            vec![
                "event_auth_checked",
                "blocked",
                "per_tx_cap_exceeded",
                "extra",
            ],
            vec!["event_auth_checked", "allowed", "per_tx_cap_exceeded"],
            vec!["unrelated", "event_auth_checked", "blocked"],
        ] {
            assert_eq!(block_reason(&[encoded(&event(&topics))], &guard()), None);
        }
    }

    #[test]
    fn another_contract_host_and_diagnostic_events_are_rejected() {
        let mut other = valid_event();
        other.event.contract_id = Some(ContractId(Hash([8; 32])));
        assert_eq!(block_reason(&[encoded(&other)], &guard()), None);
        other.event.contract_id = None;
        assert_eq!(block_reason(&[encoded(&other)], &guard()), None);
        for kind in [ContractEventType::System, ContractEventType::Diagnostic] {
            let mut other = valid_event();
            other.event.type_ = kind;
            assert_eq!(block_reason(&[encoded(&other)], &guard()), None);
        }
    }

    #[test]
    fn account_guard_and_malformed_diagnostics_are_rejected_without_panicking() {
        let account = ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([7; 32])),
        ));
        assert_eq!(block_reason(&[encoded(&valid_event())], &account), None);
        for value in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!(123),
            serde_json::json!("not base64"),
            serde_json::json!({"xdr":"AAAA"}),
        ] {
            assert_eq!(block_reason(&[value], &guard()), None);
        }
        assert_eq!(block_reason(&[], &guard()), None);
    }

    #[test]
    fn malformed_and_unrelated_events_do_not_hide_a_valid_block() {
        let events = [
            serde_json::json!({"xdr":"not base64"}),
            encoded(&event(&["unrelated"])),
            encoded(&valid_event()),
        ];
        assert_eq!(block_reason(&events, &guard()), Some("per_tx_cap_exceeded"));
    }

    #[test]
    fn expect_blocked_exit_zero_requires_verified_policy_evidence() {
        for (events, expected) in [
            (vec![encoded(&valid_event())], 0),
            (vec![], 1),
            (
                vec![encoded(&event(&[
                    "event_auth_checked",
                    "blocked",
                    "unknown_reason",
                ]))],
                1,
            ),
        ] {
            let outcome = crate::RunOutcome::SimulationBlocked {
                policy_block: block_reason(&events, &guard()).is_some(),
                error_code: None,
                error_message: Some("simulation failed".into()),
                events: Some(events),
            };
            assert_eq!(outcome.exit_code(true), expected);
            assert_eq!(outcome.exit_code(false), 1);
        }
        let failed = crate::RunOutcome::TransactionFailure {
            hash: "hash".into(),
            result_xdr: None,
        };
        assert_eq!(failed.exit_code(true), 1);
    }
    #[test]
    fn nested_rpc_errors_preserve_the_verified_reason_when_top_level_events_are_empty() {
        let simulation = serde_json::json!({
            "events": [],
            "error": {"message": "host failure", "data": {"events": [{"xdr":encoded(&valid_event())}]}},
        });
        assert_eq!(
            crate::guard_auth_checked_block_reason(&simulation, &guard()),
            Some("per_tx_cap_exceeded")
        );
        assert_eq!(
            crate::simulation_error_message(&simulation).as_deref(),
            Some("host failure")
        );
    }

    #[test]
    fn error_messages_alone_never_prove_a_policy_denial() {
        for message in [
            "tx_insufficient_fee",
            "signature expired",
            "malformed address",
            "RPC unavailable",
            "event_auth_checked blocked per_tx_cap_exceeded",
        ] {
            let simulation = serde_json::json!({"error":message});
            assert_eq!(
                crate::guard_auth_checked_block_reason(&simulation, &guard()),
                None
            );
        }
    }

    #[test]
    fn malformed_diagnostic_printing_does_not_panic() {
        for json in [false, true] {
            let reporter = crate::Reporter {
                json,
                network: None,
            };
            crate::print_events(
                &serde_json::json!(["invalid base64", {"xdr":"AAAA"}, null]),
                &reporter,
            );
        }
    }

    #[test]
    fn signed_json_reports_only_verified_guard_denials_as_blocked() {
        let simulation = serde_json::json!({
            "error": "host failure",
            "events": [encoded(&valid_event())],
        });
        let report = crate::guard_simulation_report(&simulation, &guard());
        assert_eq!(report.outcome, "blocked");
        assert_eq!(report.reason.as_deref(), Some("per_tx_cap_exceeded"));
    }

    #[test]
    fn signed_json_reports_unverified_errors_as_failures() {
        let mut other_guard = valid_event();
        other_guard.event.contract_id = Some(ContractId(Hash([8; 32])));
        for simulation in [
            serde_json::json!({"error": "RPC unavailable"}),
            serde_json::json!({"error": {"message": "auth_checked: per_tx_cap_exceeded"}}),
            serde_json::json!({"error": "host failure", "events": [encoded(&other_guard)]}),
            serde_json::json!({"error": "host failure", "events": ["invalid XDR"]}),
        ] {
            let report = crate::guard_simulation_report(&simulation, &guard());
            assert_eq!(report.outcome, "failed");
            assert_eq!(report.reason.as_deref(), Some("simulation_failed"));
        }
    }

    #[test]
    fn signed_json_reports_success_without_an_error() {
        for simulation in [serde_json::json!({}), serde_json::json!({"error": null})] {
            let report = crate::guard_simulation_report(&simulation, &guard());
            assert_eq!(report.outcome, "allowed");
            assert_eq!(report.reason, None);
        }
    }
}
