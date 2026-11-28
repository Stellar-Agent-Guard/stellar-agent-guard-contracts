Closes #379

## Summary

There is now exactly **one** implementation of the hand-rolled base-32
decoder, CRC16-XModem checksum and StrKey envelope, and both key readers use
it:

- `tools/agent-tx` — the submission tool, via its `strkey.rs` CLI validation;
- `examples/agent_pubkey.rs` — the agent-pubkey derivation example, which no
  longer carries its own `ALPHABET` / `base32_decode` copy.

The shared code lives in a new dependency-free crate,
`tools/agent-strkey/` (`base32` + `strkey` modules). `tools/agent-tx` depends
on it by path; the contract crate takes it as a **dev-dependency** for the
example. Before this change, `examples/agent_pubkey.rs` had a second base-32
decoder and re-implemented the 35-byte StrKey layout inline, so a fix to key
parsing had to be made twice — the failure mode the issue describes.

`crate::base32` inside `agent-tx` (added in #380) is gone; its code moved into
the shared crate and its tests moved with it. `agent-tx`'s `strkey.rs` is now
only the CLI's field-level policy (`--guard` wants `C...`, `--agent-secret`
wants `S...`, etc.) on top of the shared decoder.

## Why a separate crate, and why this shape

The example and the tool are separate cargo projects (`tools/agent-tx` has its
own `Cargo.toml`/`Cargo.lock` and is not a workspace member; the example is a
target of the contract crate), so neither can `mod` the other's files. The
alternatives considered:

1. **Have the contract crate depend on `agent-tx`** (make the tool a library).
   Rejected: it would pull `ureq`, `dirs`, `getrandom`, `serde`, `serde_json`
   and `stellar-xdr` into the contract crate's dev graph for a key codec, and
   register all of their licenses and advisories against `deny.toml`, whose
   `Cargo.lock` currently stays clean of them.
2. **Move the example into `tools/agent-tx/examples/`.** Rejected: it changes
   documented UX (`cargo run --example agent_pubkey` from the repo root is
   referenced from `README.md`, `CONTRIBUTING.md`, `docs/installation.md`,
   `docs/functions/initialize.md`, `docs/key-rotation.md` and
   `tests/fixtures/README.md`).
3. **A small shared library crate (chosen).** Zero dependencies, so it adds
   one crate to each consumer's lockfile (`Cargo.lock` diff is 2 lines here,
   5 lines for the tool) and no new transitive surface to audit. It also keeps
   the tool's "no Stellar SDK, just `stellar-xdr`" trade-off intact, which is
   now a recorded decision rather than an accident: see the crate-level docs
   in `tools/agent-strkey/src/lib.rs`.
4. **`#[path]`-including the tool's source file into the example.** Rejected:
   it compiles a second copy of the module in the example crate, and the
   unused half of the codec would need a blanket `#[allow(dead_code)]` to keep
   the lint gate green.

## Behaviour difference between the two copies, resolved deliberately

They were not identical, and the resolution keeps the stricter behaviour:

| | old example | `agent-tx` |
| --- | --- | --- |
| alphabet check | yes | yes (with a lowercase-specific message) |
| 56-character length | no (only "decodes to 35 bytes") | yes |
| CRC16-XModem checksum | **no** | yes |
| version byte | `0x90` | `0x90` |

The example now uses the strict decoder, so it validates the CRC16 checksum,
the 56-character length and rejects lowercase/whitespace-padded input. This is
observable: a secret whose *checksum* characters are mistyped used to derive a
pubkey silently (the seed bytes were untouched, so the printed value could be
"right" while the secret was wrong), and is now rejected:

```text
$ printf '%s\n' SBRVOEN5IIWAROJVJI2OHN2IYD2H3S75UOM3UKY7RQ42JRDPH5KRHQC2 | cargo run --example agent_pubkey
invalid secret seed: its CRC16-XModem checksum does not match (computed 0x5cc0, found 0x5ac0) — the key is mistyped or truncated; ...
```

The example's own trust-boundary docs were updated to match (bullet 3 no
longer claims the checksum is unchecked), and the successful output for the
repository's known vector is unchanged byte for byte:

```text
$ printf '%s\n' SBRVOEN5IIWAROJVJI2OHN2IYD2H3S75UOM3UKY7RQ42JRDPH5KRHQC4 | cargo run --example agent_pubkey
1cb479acb9bb7d9b3a04a6865f5c44216f8a463d64ea7ceeb1447fee21cdcc05
```

(Verified against the pre-change example compiled from `HEAD`: identical.)

## Tests

- The codec's property/negative/vector tests (`base32` round-trip, RFC 4648
  alphabet and no padding, StrKey encode↔decode identity over random
  payloads, bad character/length/CRC/lowercase/whitespace rejection, and the
  contract/account/secret known vectors) moved from `agent-tx`'s test module
  into the shared crate, so they now cover it directly and still run in CI.
- The existing strkey tests named in the issue stay where they are and now
  cover the shared implementation through the tool:
  `known_secret_decodes_to_seed`, `known_pubkey_encodes_to_address`,
  `guard_contract_address_roundtrip`; `strkey.rs`'s field/rule rejection
  tests are unchanged.
- CI: three gates added for the new crate (`fmt --check`, `clippy -D warnings`,
  `test`), because the root gates never see `tools/` projects and
  `agent-tx`'s `cargo test` does not run a dependency's tests.
  `CONTRIBUTING.md` and `docs/contributing.md` list the same commands.

## Verification

Run locally on the pinned `1.99.0` toolchain:

```text
cargo fmt --check                                  # pass
cargo clippy --all-targets --all-features -- -D warnings   # pass
cargo test                                         # 228 tests, pass
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps      # pass
cargo build --release --target wasm32v1-none        # pass
scripts/check-wasm-panic-strings.sh                 # pass (allowlist unchanged)
scripts/verify-readme.sh / verify-docs-reachability.sh     # pass

cargo fmt/clippy/test --manifest-path tools/agent-tx/Cargo.toml        # pass (62 tests)
cargo build --release --manifest-path tools/agent-tx/Cargo.toml        # pass
cargo fmt/clippy/test --manifest-path tools/agent-strkey/Cargo.toml    # pass (12 tests)
```

No contract source, no `SPEC.md` behaviour and no released artifact changes;
the new dependency is dev-only for the contract crate.
