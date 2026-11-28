# Fuzz targets

## `check_auth_full_path`

Calls the real `PolicyEngine::__check_auth` entry point with a valid Ed25519
signature and hostile auth-context vectors. The smoke command is bounded to
60 seconds:

```bash
cargo fuzz run check_auth_full_path --fuzz-dir fuzz -- -max_total_time=60
```

The committed seed is intentionally small; libFuzzer expands it into empty,
duplicate, mixed, and 32-context inputs during the smoke run.

## `policy_config_deserialization`

Decodes arbitrary XDR `ScVal` bytes into `PolicyConfig` and validates them via
`validate_policy_config_scval`, asserting that malformed shapes never panic and
always resolve to `Ok(())` or `Err(Error::InvalidConfig)`:

```bash
cargo +nightly run --manifest-path fuzz/Cargo.toml --bin seed-policy-config
cargo +nightly fuzz run policy_config_deserialization --fuzz-dir fuzz -- -max_total_time=60 -max_len=4096
```

## `invocation_parser`

Fuzzes call-shape parsing (`parse_call`) and function-symbol / argument `ScVal`
decoding across every `ParsedCall` variant (`AssetTransfer` for both `transfer`
and `transfer_from`, `AssetOther`, `Protocol`, `SelfCall`, `CreateContract` for
both host-function variants, and `Unknown`). Verifies that malformed inputs
(invalid symbol encodings, wrong SAC arities, mistyped arguments, non-positive
amounts, and unlisted contracts) never panic and resolve to stable errors or
safe denial (`UnknownContract` / `AssetFnNotAllowed` / `FunctionNotAllowed` /
`SelfFunctionNotAllowed` / `CreateContractNotAllowed` / `InvalidAmount`) without
mutating window state:

```bash
cargo +nightly fuzz run invocation_parser --fuzz-dir fuzz -- -max_total_time=60
```
