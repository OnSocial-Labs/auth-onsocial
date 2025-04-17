use near_sdk::{env, AccountId, PublicKey, BorshStorageKey};
use near_sdk::store::{LookupMap, Vector};
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use crate::types::KeyInfo;
use crate::errors::AuthError;
use crate::events::AuthEvent;

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
enum StorageKey {
    Keys,
    KeyList { account_id: AccountId },
}

#[derive(BorshSerialize, BorshDeserialize, near_sdk_macros::NearSchema)]
#[borsh(crate = "near_sdk::borsh")]
#[abi(borsh)]
pub struct AuthContractState {
    pub keys: LookupMap<AccountId, Vector<KeyInfo>>,
}

impl AuthContractState {
    pub fn new() -> Self {
        Self {
            keys: LookupMap::new(StorageKey::Keys),
        }
    }

    pub fn is_authorized(
        &self,
        account_id: &AccountId,
        public_key: &PublicKey,
        signatures: Option<Vec<Vec<u8>>>,
    ) -> bool {
        let key_list = match self.keys.get(account_id) {
            Some(list) => list,
            None => return false,
        };

        let key_info = match key_list.iter().find(|k| k.public_key == *public_key) {
            Some(info) => info,
            None => return false,
        };

        if let Some(expiration) = key_info.expiration_timestamp {
            if env::block_timestamp_ms() > expiration {
                return false;
            }
        }

        if key_info.is_multi_sig {
            let threshold = key_info.multi_sig_threshold.unwrap_or(1);
            let signatures = signatures.unwrap_or_default();
            signatures.len() as u32 >= threshold
        } else {
            true
        }
    }

    pub fn register_key(
        &mut self,
        caller: &AccountId,
        account_id: &AccountId,
        public_key: PublicKey,
        expiration_days: Option<u32>,
        is_multi_sig: bool,
        multi_sig_threshold: Option<u32>,
    ) -> Result<(), AuthError> {
        if caller != account_id {
            return Err(AuthError::Unauthorized);
        }

        let expiration_timestamp = expiration_days.map(|days| {
            env::block_timestamp_ms() + (days as u64 * 24 * 60 * 60 * 1000)
        });

        let key_info = KeyInfo {
            public_key: public_key.clone(),
            expiration_timestamp,
            is_multi_sig,
            multi_sig_threshold,
        };

        if self.keys.get(account_id).is_none() {
            self.keys.insert(account_id.clone(), Vector::new(StorageKey::KeyList {
                account_id: account_id.clone(),
            }));
        }

        let key_list = self.keys.get_mut(account_id).expect("Key list should exist");
        if key_list.iter().any(|k| k.public_key == public_key) {
            return Err(AuthError::KeyAlreadyExists);
        }
        key_list.push(key_info);

        AuthEvent::KeyRegistered {
            account_id: account_id.clone(),
            public_key: format!("{:?}", public_key),
        }.emit();

        Ok(())
    }

    pub fn remove_key(
        &mut self,
        caller: &AccountId,
        account_id: &AccountId,
        public_key: PublicKey,
    ) -> Result<(), AuthError> {
        if caller != account_id {
            return Err(AuthError::Unauthorized);
        }

        let key_list = self.keys.get_mut(account_id).ok_or(AuthError::KeyNotFound)?;
        let index = key_list
            .iter()
            .position(|k| k.public_key == public_key)
            .ok_or(AuthError::KeyNotFound)?;
        key_list.swap_remove(index as u32);
        if key_list.is_empty() {
            self.keys.remove(account_id);
        }

        AuthEvent::KeyRemoved {
            account_id: account_id.clone(),
            public_key: format!("{:?}", public_key),
        }.emit();

        Ok(())
    }

    pub fn get_key_info(&self, account_id: &AccountId, public_key: &PublicKey) -> Option<KeyInfo> {
        self.keys
            .get(account_id)
            .and_then(|list| list.iter().find(|k| k.public_key == *public_key).cloned())
    }
}