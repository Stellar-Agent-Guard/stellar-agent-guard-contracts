# Stellar Agent Guard Contracts

Smart contract implementation for the Stellar Agent Guard protocol.

## `set_policy`

The `set_policy` function installs or replaces the spend policy on the guarded account. Installing or replacing a policy re-arms the dead-man clock (`LastHeartbeat = now`), with the admin's action counting as a liveness attestation. By contrast, `revoke_policy` removes the active policy but leaves `LastHeartbeat` untouched.
