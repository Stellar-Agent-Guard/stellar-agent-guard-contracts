# Fuzz targets

Every target runs bounded by the fuzzer's `-max_len`/`-max_total_time`, and a
panic is treated as a finding: reproduce it from the artifact, minimize it, and
keep the minimized input in the committed corpus.

Install the pinned toolchain and cargo-fuzz once:

```bash
cargo install cargo-fuzz --locked
```

## `check_auth_full_path`

Calls the real `PolicyEngine::__check_auth` entry point with a valid Ed25519
signature and hostile auth-context vectors. The committed seed is intentionally
small; libFuzzer expands it into empty, duplicate, mixed, and 32-context inputs
during the smoke run.

```bash
cargo fuzz run check_auth_full_path --fuzz-dir fuzz -- -max_total_time=60
```

## `policy_config_deserialization`

Decodes arbitrary bytes as an XDR `ScVal` (bounded depth/length) and runs the
production `validate_policy_config_scval` path. Invalid XDR is a normal
rejection; malformed policy shapes must map to the stable `InvalidConfig` error,
never a trap.

Regenerate its seeds, then run the bounded smoke test:

```bash
cargo run --manifest-path fuzz/Cargo.toml --bin seed-policy-config
cargo +nightly fuzz run policy_config_deserialization --fuzz-dir fuzz -- -max_total_time=60 -max_len=4096
```

### Minimized malformed-`ScVal` fixtures

Three minimized malformed shapes are committed twice: as corpus entries and as
byte-identical fixtures under `tests/fixtures/malformed-scval/`, described by
`tests/fixtures/malformed-scval/manifest.json`. The
`minimized_malformed_scval_fixtures_fail_stably_with_invalid_config` unit test
locks their size, their byte equality with the corpus, and their stable
`InvalidConfig` rejection. To replay one directly against the target:

```bash
cargo +nightly fuzz run policy_config_deserialization --fuzz-dir fuzz -- \
  tests/fixtures/malformed-scval/assets-bool-element.xdr
```

## `heartbeat_input`

Fuzzes dead-man-switch freshness together with malformed authorization
contexts, through the real `__check_auth` path (signature verification plus the
production decision engine). Input layout (little-endian; missing bytes read as
zero):

```text
byte 0        flags: bit0 admin_frozen, bit1 install policy,
                     bit2 paused, bit3 active_from gate in the future
bytes 1..5    u32 dms_grace_secs
bytes 5..13   u64 LastHeartbeat (0 = never)
bytes 13..21  u64 ledger timestamp
byte 21       context count (mod 17)
then 2 bytes per context: shape selector (mod 9), parameter byte
```

Shapes cover `heartbeat` with 0/1/2 args, `self_lock`, another self-function, a
valid transfer, malformed `transfer`/`transfer_from` arity or types, and an
unknown contract. The target models the account-gate precedence (missing policy
→ `NoPolicy`, then freeze → dead-man → pause → active window) and asserts the
exact stable error, so a changed precedence or an unstable error is a finding
too. Input over 4096 bytes and more than 16 contexts are ignored to keep host
work bounded.

Regenerate the seed corpus, then run the bounded smoke test:

```bash
cargo run --manifest-path fuzz/Cargo.toml --bin seed-heartbeat
cargo +nightly fuzz run heartbeat_input --fuzz-dir fuzz -- -max_total_time=60 -max_len=4096
```

Seeds: fresh/expired/frozen heartbeats, a paused transfer, malformed heartbeat
and transfer contexts, and an unknown contract.

## Reproducing and minimizing an artifact

A failure writes an input under `fuzz/artifacts/<target>/`. Replay it exactly,
then shrink it:

```bash
cargo +nightly fuzz run <target> --fuzz-dir fuzz -- fuzz/artifacts/<target>/<artifact>
cargo +nightly fuzz tmin <target> --fuzz-dir fuzz -- fuzz/artifacts/<target>/<artifact>
```

`tmin` overwrites the artifact with the minimized bytes. Copy that file into
`fuzz/corpus/<target>/` with a descriptive name in the same PR as the fix, and
reference it from the PR description so the regression is reproducible without
the original artifact. If the minimized input is a malformed policy `ScVal`,
also add it to `tests/fixtures/malformed-scval/` and update the manifest.

## CI

`.github/workflows/fuzz.yml` runs a 60-second bounded smoke run for
`check_auth_full_path` and `heartbeat_input` on pull requests that touch
`src/**`, `fuzz/**`, `Cargo.toml`, or `Cargo.lock`. The policy-deserialization
target is documented in `CONTRIBUTING.md` and available for longer local runs.
