use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, IntoVal, Symbol, Val, Vec};

pub mod types;
use types::{Error, PolicyConfig};

#[contract]
pub struct PolicyEngine;

#[contractimpl]
impl PolicyEngine {
    pub fn initialize(env: Env, admin: Address, agent_pubkey: BytesN<32>) -> Result<(), Error> {
        admin.require_auth();
        if agent_pubkey.to_array() == [0u8; 32] {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }

    pub fn rotate_agent_key(env: Env, agent_pubkey: BytesN<32>) -> Result<(), Error> {
        if agent_pubkey.to_array() == [0u8; 32] {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }

    pub fn set_policy(env: Env, config: PolicyConfig) -> Result<(), Error> {
        // set_policy re-arms the dead-man clock (LastHeartbeat = now) as a side effect.
        let _now = env.ledger().timestamp();
        Ok(())
    }

    pub fn revoke_policy(env: Env) -> Result<(), Error> {
        Ok(())
    }
}

#[contractimpl]
#[allow(
    clippy::needless_pass_by_value,
    clippy::used_underscore_binding
)]
impl CustomAccountInterface for PolicyEngine {
    type Signature = BytesN<64>;
    type Error = Error;

    fn __check_auth(
        _env: Env,
        _signature_payload: soroban_sdk::crypto::Hash<32>,
        _signatures: Self::Signature,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}
