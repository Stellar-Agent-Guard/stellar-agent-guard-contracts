# Fuzz targets

This crate fuzzes two entry surfaces under `fuzz/fuzz_targets/`:

| Target | Entry surface | Corpus directory | Artifact directory | CI workflow |
|---|---|---|---|---|
| `check_auth_full_path` | `PolicyEngine::__check_auth` with valid Ed25519 signature and hostile auth-context vectors | `fuzz/corpus/check_auth_full_path/` | `fuzz/artifacts/check_auth_full_path/` | `.github/workflows/fuzz.yml` (`check-auth-fuzz-artifacts`) |
| `policy_config_deserialization` | `ScVal::from_xdr` + `validate_policy_config_scval` + §8 validation | `fuzz/corpus/policy_config_deserialization/` | `fuzz/artifacts/policy_config_deserialization/` | `.github/workflows/ci.yml` (`policy-config-fuzz-artifacts`) |

## Running locally

Install `cargo-fuzz` once (`nightly` is required by libFuzzer):

```bash
cargo install cargo-fuzz --locked
```

### `check_auth_full_path`

Bounded 60-second smoke run (matches `.github/workflows/fuzz.yml`):

```bash
cargo +nightly fuzz run check_auth_full_path --fuzz-dir fuzz -- -max_total_time=60
```

### `policy_config_deserialization`

Seed valid empty and non-empty `PolicyConfig` XDR inputs, then run the bounded 60-second fuzz loop (matches `.github/workflows/ci.yml`):

```bash
cargo +nightly run --manifest-path fuzz/Cargo.toml --bin seed-policy-config
cargo +nightly fuzz run policy_config_deserialization -- -max_total_time=60 -max_len=4096
```

## Reproducing and minimizing findings

When either target fails in CI, download the uploaded workflow artifact (`check-auth-fuzz-artifacts` or `policy-config-fuzz-artifacts`), place the file under the target's artifact directory, and replay it directly:

```bash
# check_auth_full_path
cargo +nightly fuzz run check_auth_full_path --fuzz-dir fuzz fuzz/artifacts/check_auth_full_path/<artifact>

# policy_config_deserialization
cargo +nightly fuzz run policy_config_deserialization -- fuzz/artifacts/policy_config_deserialization/<artifact>
```

Before inspecting or promoting a finding, minimize it with `tmin` so redundant bytes are stripped while preserving the crash or failure condition:

```bash
# check_auth_full_path
cargo +nightly fuzz tmin check_auth_full_path --fuzz-dir fuzz fuzz/artifacts/check_auth_full_path/<artifact>

# policy_config_deserialization
cargo +nightly fuzz tmin policy_config_deserialization fuzz/artifacts/policy_config_deserialization/<artifact>
```

---

## Corpus triage and retention policy

A fuzz corpus is only useful if maintainers can reproduce, review, and retain meaningful findings without accumulating opaque binary blobs.

### When minimized artifacts become regression fixtures

1. **Always promote bug-revealing inputs to deterministic tests.** Once a crash, timeout, OOM, or model mismatch (`result.is_ok() != model_decide(input)`) is minimized, decode what the input triggered and add a deterministic unit or integration test (for example in `src/integration_tests.rs`, `src/engine.rs`, or `tests/policyconfig_scval_encoding.rs`).
2. **Do not commit raw crash artifacts.** Never leave `fuzz/artifacts/<target>/crash-*`, `timeout-*`, or `oom-*` files in git history; deterministic Rust tests are the permanent regression gate run by `cargo test`.
3. **Retain a minimized corpus seed only for hard-to-reach parser or boundary shapes.** Commit a minimized input under `fuzz/corpus/<target>/` only when:
   - it exercises a specific malformed wire/XDR shape or edge-case vector that `seed-policy-config` or random mutation is unlikely to hit quickly in a 60-second CI run;
   - it uses a descriptive, human-readable kebab-case filename (never a raw SHA-1 hash); and
   - it has a short rationale entry in the [Retained corpus inventory](#retained-corpus-inventory) below.

### How to prune noise

- **Never commit ad-hoc libFuzzer output dumps.** Local `fuzz run` sessions generate thousands of SHA-1-named inputs in `fuzz/corpus/<target>/` and transient seed files (`valid_empty_policy`, `valid_nonempty_policy`) from `seed-policy-config`. Keep those untracked or discard them (`git clean` / `cmin`) before opening a PR.
- **Deduplicate with `cmin` before retaining anything.** Run corpus minimization (`cargo +nightly fuzz cmin <target> --fuzz-dir fuzz`) to drop inputs that contribute zero unique coverage edges.
- **Delete retired corpus files when superseded.** If a seed's code path is covered by `seed-policy-config` or deterministic tests and removing it does not reduce fuzz coverage of distinct error/guard branches, delete it and remove its entry from the table below.
- **Clean transient artifacts after triage.** Remove local `fuzz/artifacts/<target>/` files once the underlying bug is fixed and verified by a regression test.

### Retained corpus inventory

Every committed file in `fuzz/corpus/` has an explicit rationale:

| File | Size | Rationale |
|---|---|---|
| `fuzz/corpus/check_auth_full_path/seed` | 8 B | Minimal deterministic seed from which libFuzzer mutates empty, duplicate, mixed, and 32-context authorization vectors. |
| `fuzz/corpus/policy_config_deserialization/invalid-assets-bool-element` | 544 B | Malformed `PolicyConfig` `ScVal::Map` XDR whose `assets` vector contains a `ScVal::Bool` element instead of an `Address`, pinning the `scval_vec_is_addresses` pre-conversion guard against SDK `ConversionError` aborts. |
| `fuzz/corpus/policy_config_deserialization/invalid-assets-muxed-account` | 712 B | Malformed `PolicyConfig` `ScVal::Map` XDR whose `assets` vector contains a `ScAddress::MuxedAccount`, verifying deterministic `Error::InvalidConfig` rejection instead of a conversion panic. |
| `fuzz/corpus/policy_config_deserialization/invalid-policy-field-symbol` | 504 B | Malformed `PolicyConfig` `ScVal::Map` XDR with a mistyped field symbol (`allow_any_reciPient`), pinning deterministic rejection of unexpected map keys. |
