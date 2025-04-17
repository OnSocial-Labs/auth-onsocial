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
    LastActiveTimestamps,
    RegisteredAccounts,
}

#[derive(BorshSerialize, BorshDeserialize, near_sdk_macros::NearSchema)]
#[borsh(crate = "near_sdk::borsh")]
#[abi(borsh)]
pub struct AuthContractState {
    pub keys: LookupMap<AccountId, Vector<KeyInfo>>,
    pub last_active_timestamps: LookupMap<AccountId, u64>,
    pub registered_accounts: Vector<AccountId>,
}

impl AuthContractState {
    pub fn new() -> Self {
        Self {
            keys: LookupMap::new(StorageKey::Keys),
            last_active_timestamps: LookupMap::new(StorageKey::LastActiveTimestamps),
            registered_accounts: Vector::new(StorageKey::RegisteredAccounts),
        }
    }

    pub fn is_authorized(
        &mut self,
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

        let authorized = if key_info.is_multi_sig {
            let threshold = key_info.multi_sig_threshold.unwrap_or(1);
            let signatures = signatures.unwrap_or_default();
            signatures.len() as u32 >= threshold
        } else {
            true
        };

        if authorized {
            self.last_active_timestamps.insert(account_id.clone(), env::block_timestamp_ms());
        }

        authorized
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
            self.registered_accounts.push(account_id.clone());
        }

        let key_list = self.keys.get_mut(account_id).expect("Key list should exist");
        if key_list.iter().any(|k| k.public_key == public_key) {
            return Err(AuthError::KeyAlreadyExists);
        }
        key_list.push(key_info);

        self.last_active_timestamps.insert(account_id.clone(), env::block_timestamp_ms());

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
            self.last_active_timestamps.remove(account_id);
            if let Some(index) = self.registered_accounts.iter().position(|id| id == account_id) {
                self.registered_accounts.swap_remove(index as u32);
            }
        }

        AuthEvent::KeyRemoved {
            account_id: account_id.clone(),
            public_key: format!("{:?}", public_key),
        }.emit();

        Ok(())
    }

    pub fn remove_expired_keys(&mut self, account_id: &AccountId) -> Result<(), AuthError> {
        let key_list = self.keys.get_mut(account_id).ok_or(AuthError::KeyNotFound)?;
        let current_timestamp = env::block_timestamp_ms();
        let mut i = 0;
        while i < key_list.len() {
            if let Some(key_info) = key_list.get(i) {
                if key_info.expiration_timestamp.map_or(false, |exp| current_timestamp > exp) {
                    let public_key = key_list.swap_remove(i);
                    AuthEvent::KeyRemoved {
                        account_id: account_id.clone(),
                        public_key: format!("{:?}", public_key.public_key),
                    }.emit();
                    continue;
                }
            }
            i += 1;
        }

        if key_list.is_empty() {
            self.keys.remove(account_id);
            self.last_active_timestamps.remove(account_id);
            if let Some(index) = self.registered_accounts.iter().position(|id| id == account_id) {
                self.registered_accounts.swap_remove(index as u32);
            }
        }

        Ok(())
    }

    pub fn remove_inactive_accounts(&mut self, account_id: AccountId) -> Result<(), AuthError> {
        let last_active = self.last_active_timestamps.get(&account_id).ok_or(AuthError::KeyNotFound)?;
        let current_timestamp = env::block_timestamp_ms();
        const ONE_YEAR_MS: u64 = 31_536_000_000; // 1 year in milliseconds

        if current_timestamp <= last_active + ONE_YEAR_MS {
            return Err(AuthError::AccountStillActive);
        }

        let key_list = self.keys.get_mut(&account_id).ok_or(AuthError::KeyNotFound)?;
        while !key_list.is_empty() {
            let public_key = key_list.swap_remove(0);
            AuthEvent::KeyRemoved {
                account_id: account_id.clone(),
                public_key: format!("{:?}", public_key.public_key),
            }.emit();
        }

        self.keys.remove(&account_id);
        self.last_active_timestamps.remove(&account_id);
        if let Some(index) = self.registered_accounts.iter().position(|id| id == &account_id) {
            self.registered_accounts.swap_remove(index as u32);
        }

        Ok(())
    }

    pub fn get_inactive_accounts(&self, limit: u32) -> Vec<AccountId> {
        let current_timestamp = env::block_timestamp_ms();
        const ONE_YEAR_MS: u64 = 31_536_000_000; // 1 year in milliseconds
        let mut inactive_accounts = Vec::new();
        for account_id in self.registered_accounts.iter() {
            if let Some(timestamp) = self.last_active_timestamps.get(account_id) {
                if current_timestamp > timestamp + ONE_YEAR_MS {
                    inactive_accounts.push(account_id.clone());
                    if inactive_accounts.len() >= limit as usize {
                        break;
                    }
                }
            }
        }
        inactive_accounts
    }

    pub fn get_key_info(&self, account_id: &AccountId, public_key: &PublicKey) -> Option<KeyInfo> {
        self.keys
            .get(account_id)
            .and_then(|list| list.iter().find(|k| k.public_key == *public_key).cloned())
    }
}