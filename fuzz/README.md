# Fuzz targets

The `check_auth_full_path` target calls the real `PolicyEngine::__check_auth`
entry point with a valid Ed25519 signature and hostile auth-context vectors.
The smoke command is bounded to 60 seconds:

```bash
cargo fuzz run check_auth_full_path --fuzz-dir fuzz -- -max_total_time=60
```

The committed seed is intentionally small; libFuzzer expands it into empty,
duplicate, mixed, and 32-context inputs during the smoke run.