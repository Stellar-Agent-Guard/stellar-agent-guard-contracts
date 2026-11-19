Closes #317

## Summary

`transfer_context` built the pre-flight auth context as `args = [asset, to, amount]`
while the SAC `transfer` signature is `(from, to, amount)`, so slot 0 held the
token address instead of the guarded account. Nothing in the decision table reads
`args[0]` today, so no verdict changes with this fix — but the synthetic context
claims to be a replica of the context the host hands `__check_auth`, and a replica
with the wrong `from` is not a replica. The moment the `from`-is-the-guarded-account
check that #10 calls for lands, that wrong slot would make `check()` block every
transfer `__check_auth` admits.

## What changed

- `src/lib.rs` (`transfer_context`): `args[0]` is now
  `env.current_contract_address()` — the guarded account, i.e. the SAC `from` the
  host will actually see at authorization time. The helper is `pub(crate)` (it was
  already private to the crate; no ABI or wasm-surface change) so the regression
  test can read the exact context `check()` constructs.
- `src/integration_tests.rs`
  (`check_and_check_auth_agree_on_the_synthetic_transfer_context`): pins the
  synthetic context shape — `contract == asset`, `fn_name == "transfer"`, arity 3,
  `args == [guard, to, amount]` — and then runs the identical transfer through both
  paths, asserting they agree for one **allowed** case (`__check_auth` admits it)
  and one **blocked** case (`check()` returns `recipient_not_allowed` and the
  host-routed `__check_auth` reports the same reason, moving nothing).
- `SPEC.md` §7 `check` entry: states the exact synthetic context shape it
  constructs, including which SAC slot each argument occupies.

## Ordering / dependency with #10

This PR is the prerequisite for #10 (*reject transfer contexts where `from` is not
the guarded account itself*), which is assigned separately. **#10 must land after
this one**: once `parse_call` validates `args[0] == self`, a pre-flight context with
the token address in slot 0 would disagree with `__check_auth` on every call. With
this merged first, #10's from-validation runs against a correct replica on both
paths.

## Lints

No new `#[allow]` anywhere; `cargo clippy --all-targets --all-features -- -D warnings`
is clean.

## Testing

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release --target wasm32v1-none
```

The new test was verified to **fail** on the pre-fix shape (it reports the token
address where the guard account is expected) and to pass after the fix. The full
suite is green: 217 lib tests plus every `tests/` binary.

## Out of scope

Sibling repositories (`stellar-agent-guard-sdk`, `stellar-agent-guard-dashboard`)
— cross-repo work is tracked in its own repository.
