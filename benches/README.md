# `__check_auth` decision-cost baseline

Run the bounded decision-path benchmark with:

```bash
cargo run --manifest-path benches/Cargo.toml --bin denial_path_gas
```

It measures Soroban test-environment CPU instructions via `Env::cost_estimate()` (not wall-clock
time). Reference run: Rust stable, Soroban SDK 27.0.6, macOS arm64, 2026-09-30. The asserted
ceilings are regression guards with headroom over the measured baseline; CI runs the same binary.
Host instruction counts are useful for relative regression tracking, not a promise of identical
on-network fee/resource usage.

| Scenario | Measured CPU instructions | CI ceiling |
| --- | ---: | ---: |
| 256-entry assets, recipients, blocked recipients, and recipient-cap overrides; successful tail match | 953,642 | 1,250,000 |
| 256-entry protocol allowlist; successful tail match | 380,961 | 500,000 |
| Rolling window with 0 live entries | 22,582 | 35,000 |
| Rolling window with 100 live entries | 22,782 | 35,000 |
| Rolling window at maximum 8,192 live entries | 38,964 | 60,000 |
| Batch of 16 allowlisted protocol contexts | 92,845 | 150,000 |

The program also reports the existing denial-gate baselines. Each listed stress ceiling is
asserted by the benchmark, so a regression over the bound exits non-zero and fails CI.
