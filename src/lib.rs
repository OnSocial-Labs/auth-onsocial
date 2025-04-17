#[macro_use]
extern crate near_sdk_macros;

use near_sdk::{near, AccountId, PublicKey};
use state::AuthOnSocial;
use errors::AuthError;

mod state;
mod events;
mod errors;
mod types;

#[near]
impl AuthOnSocial {
    #[init]
    pub fn new() -> Self {
        Self::default()
    }

    #[handle_result]
    pub fn is_authorized(
        &self,
        account_id: AccountId,
        public_key: PublicKey,
        signatures: Option<Vec<Vec<u8>>>,
        delegate_action: Vec<u8>, // Serialized DelegateAction
    ) -> Result<bool, AuthError> {
        self.is_authorized_internal(account_id, public_key, signatures, delegate_action)
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
        self.register_key_internal(account_id, public_key, expiration_days, is_multi_sig, multi_sig_threshold)
    }

    #[handle_result]
    pub fn remove_key(
        &mut self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Result<(), AuthError> {
        self.remove_key_internal(account_id, public_key)
    }

    #[handle_result]
    pub fn extend_key_expiration(
        &mut self,
        account_id: AccountId,
        public_key: PublicKey,
        additional_days: u32,
    ) -> Result<(), AuthError> {
        self.extend_key_expiration_internal(account_id, public_key, additional_days)
    }

    pub fn check_key_expiration(
        &self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Option<u64> {
        self.check_key_expiration_internal(account_id, public_key)
    }

    pub fn get_key_info(
        &self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Option<types::KeyInfo> {
        self.get_key_info_internal(account_id, public_key)
    }
}