//! Writes the committed seed corpus for the `heartbeat_input` fuzz target.
//!
//! Run with:
//!
//! ```bash
//! cargo run --manifest-path fuzz/Cargo.toml --bin seed-heartbeat
//! ```
//!
//! The byte layout is documented in `fuzz/fuzz_targets/heartbeat_input.rs`.
//! Seeds are deliberately tiny and hand-built so the minimized shape of every
//! acceptance case is reviewable in the diff, not hidden in a generator.

use std::{fs, path::PathBuf};

/// Flags: bit0 admin_frozen, bit1 policy installed, bit2 paused,
/// bit3 active-from gate in the future.
const POLICY: u8 = 0b0010;
const FROZEN: u8 = 0b0001;
const PAUSED: u8 = 0b0100;

fn seed(flags: u8, grace: u32, last_heartbeat: u64, now: u64, shapes: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(22 + shapes.len() * 2);
    bytes.push(flags);
    bytes.extend_from_slice(&grace.to_le_bytes());
    bytes.extend_from_slice(&last_heartbeat.to_le_bytes());
    bytes.extend_from_slice(&now.to_le_bytes());
    bytes.push(u8::try_from(shapes.len()).expect("seed context count fits in u8"));
    for shape in shapes {
        bytes.push(*shape);
        bytes.push(0);
    }
    bytes
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join("heartbeat_input");
    fs::create_dir_all(&corpus)?;

    let seeds: [(&str, Vec<u8>); 6] = [
        // Fresh DMS clock: heartbeat admitted.
        (
            "allowed-fresh-heartbeat",
            seed(POLICY, 60, 1_000, 1_030, &[0]),
        ),
        // Grace elapsed: heartbeat cannot self-revive.
        (
            "denied-expired-heartbeat",
            seed(POLICY, 60, 1_000, 1_061, &[0]),
        ),
        // Admin kill switch beats a fresh clock, including for heartbeats.
        (
            "denied-frozen-heartbeat",
            seed(POLICY | FROZEN, 0, 1_000, 1_000, &[0]),
        ),
        // Pause gate, with a valid transfer in the same batch.
        (
            "denied-paused-transfer",
            seed(POLICY | PAUSED, 0, 1_000, 1_000, &[5]),
        ),
        // Malformed authorization contexts: heartbeat with spurious args,
        // wrong-arity transfer, and a bad `transfer_from` argument type.
        (
            "denied-malformed-contexts",
            seed(POLICY, 60, 1_000, 1_030, &[1, 2, 6, 7]),
        ),
        // Unknown contract stays default-deny.
        (
            "denied-unknown-contract",
            seed(POLICY, 0, 1_000, 1_000, &[8]),
        ),
    ];

    for (name, bytes) in seeds {
        fs::write(corpus.join(name), bytes)?;
    }
    Ok(())
}
