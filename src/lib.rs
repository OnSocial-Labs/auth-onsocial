use near_sdk::{near, env, AccountId, PublicKey, PanicOnDefault};
use crate::state::AuthContractState;
use crate::types::KeyInfo;
use crate::errors::AuthError;

mod state;
mod types;
mod errors;
mod events;

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct AuthContract {
    state: AuthContractState,
}

#[near]
impl AuthContract {
    #[init]
    pub fn new() -> Self {
        Self {
            state: AuthContractState::new(),
        }
    }

    pub fn is_authorized(
        &mut self,
        account_id: AccountId,
        public_key: PublicKey,
        signatures: Option<Vec<Vec<u8>>>,
    ) -> bool {
        self.state.is_authorized(&account_id, &public_key, signatures)
    }

    #[handle_result]
    pub fn register_key(
        &mut self,
        account_id: AccountId,
        public_key: PublicKey,
        expiration_days: Option<u32>,
        is_multi_sig: bool,
        multi_sig_threshold: Option<u32>,
    ) -> Result<(), AuthError> {
        self.state.register_key(
            &env::predecessor_account_id(),
            &account_id,
            public_key,
            expiration_days,
            is_multi_sig,
            multi_sig_threshold,
        )
    }

    #[handle_result]
    pub fn remove_key(
        &mut self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Result<(), AuthError> {
        self.state.remove_key(&env::predecessor_account_id(), &account_id, public_key)
    }

    #[handle_result]
    pub fn remove_expired_keys(&mut self, account_id: AccountId) -> Result<(), AuthError> {
        self.state.remove_expired_keys(&account_id)
    }

    #[handle_result]
    pub fn remove_inactive_accounts(&mut self, account_id: AccountId) -> Result<(), AuthError> {
        self.state.remove_inactive_accounts(account_id)
    }

    pub fn get_inactive_accounts(&self, limit: u32) -> Vec<AccountId> {
        self.state.get_inactive_accounts(limit)
    }

    pub fn get_key_info(&self, account_id: AccountId, public_key: PublicKey) -> Option<KeyInfo> {
        self.state.get_key_info(&account_id, &public_key)
    }
}