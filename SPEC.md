# Stellar Agent Guard — Technical Specification

## 5. Dead-Man Switch (DMS)

The guarded account may configure a dead-man switch grace period (`dms_grace_secs`). If no heartbeat is recorded within `dms_grace_secs` of the last heartbeat, all contract-enforced transfers are frozen until an admin unfreezes or updates the state.

Installing or replacing a policy via `set_policy` re-arms the dead-man clock (`LastHeartbeat = now`), and the admin's action counts as a liveness attestation. By contrast, `revoke_policy` removes the active policy but leaves `LastHeartbeat` untouched.