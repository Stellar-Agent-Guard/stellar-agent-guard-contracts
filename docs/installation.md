# Installation

## Prerequisites

- **Rust 1.85+** with the `wasm32v1-none` target (Soroban 27 targets `wasm32v1-none`, not `wasm32-unknown-unknown`):

```bash
rustup target add wasm32v1-none
```

- **Soroban CLI** (`stellar` / `stellar-cli` 22+ — verified against 27.1.0) for deployment and admin invocations
- **Network access** to a Soroban RPC endpoint for anything on-chain

| Network | Endpoint |
|---|---|
| `testnet` | `https://soroban-testnet.stellar.org` |
| `mainnet` | `https://soroban.stellar.org` |
| `futurenet` | `https://rpc-futurenet.stellar.org` |

## Build from source

```bash
git clone https://github.com/aigbagbobila/stellar-agent-guard-contracts.git
cd stellar-agent-guard-contracts

# Contract WASM (the artifact to deploy)
cargo build --release --target wasm32v1-none
# → target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm

# Submission helper (agent-tx: signs auth entries for the guard address;
# the stellar CLI cannot — see the heartbeat function docs)
cargo build --release --manifest-path tools/agent-tx/Cargo.toml
# → target/release/agent-tx
```

## Run tests

```bash
cargo test                                      # 34 tests (31 contract + 3 agent-tx), isolated (no network)
cargo clippy --all-targets --all-features       # clippy all + pedantic denied
cargo fmt --check                               # format check
```

## Read live state from the testnet deployment

No auth required — simulation only:

```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- status
# → {"admin_frozen":false,"has_policy":true,"heartbeat_expired":true,
#    "last_heartbeat":1788855212,"now":1788863857}
```

## Repository layout

```
src/
  lib.rs               # Contract: lifecycle, admin, __check_auth (CustomAccount)
  engine.rs            # Pure decision table over auth Contexts
  window.rs            # Genuinely rolling spend window (lazy prune, bounded)
  types.rs             # Policy model, storage keys, errors, parsed-call enum
  integration_tests.rs # Host-routed tests incl. real Ed25519 auth signatures
examples/
  agent_pubkey.rs      # Derive raw Ed25519 pubkey from a Stellar secret key
tools/
  agent-tx/            # Sign+submit helper for the custom-account address
tests/fixtures/        # Real testnet evidence (tx hashes, contract IDs, events)
SPEC.md                # Architecture specification (mechanism is settled)
```
