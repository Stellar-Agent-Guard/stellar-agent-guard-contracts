# fix(tests): no test runs the full lifecycle from a fresh registration with admin auth enforced

## Summary

This PR adds a regression test that exercises the real end-to-end lifecycle from a fresh registration with auth enforcement enabled from the start:

- admin `initialize` under real host auth
- admin `set_policy` under real host auth
- agent-authenticated transfer under the enforced policy path
- no blanket `env.mock_all_auths()` for the test flow itself

The existing harness is still intentionally permissive by default for the broader suite, but this new path makes the exception explicit and documents why the suite keeps a mock-heavy default for readability while the lifecycle test exercises the real auth semantics.

## What changed

- Added a dedicated harness mode / test path that registers the guard and runs the fresh-registration flow with explicit `env.set_auths(...)` entries instead of blanket mocking.
- Ensured the test covers the full chain without any `mock_all_auths()` call in that path.
- Explicitly exercises:
  - admin authorization on `initialize`
  - admin authorization on `set_policy`
  - agent authorization on the guarded transfer path
  - policy enforcement in one continuous lifecycle
- Documented why the regular suite retains blanket mocking as a deliberate harness choice rather than an accidental omission.
- Kept the change lint-clean without adding any `#[allow]` annotations.

## Why

The suite previously used blanket auth mocking around harness setup, so tests never forced the host to validate the real admin and agent auth entries. That hid a genuine class of regressions:

- broken `require_auth` on admin calls
- wrong admin identity stored at initialize
- auth entry construction bugs that only show up under real custom-account enforcement

This PR closes that gap with one focused test that exercises the actual lifecycle under real host auth semantics, while keeping the non-enforced suite helper behavior documented and intentional.

## Testing

Validated locally with the repo's standard gates:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```

## Related

Closes #438
