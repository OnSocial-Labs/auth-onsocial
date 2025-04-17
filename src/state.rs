use near_sdk::{env, AccountId, PublicKey, BorshStorageKey};
use near_sdk::store::{LookupMap, IterableSet};
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use crate::types::KeyInfo;
use crate::errors::AuthError;
use crate::events::AuthEvent;

#[derive(BorshSerialize, BorshDeserialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
enum StorageKey {
    Keys,
    KeySet { account_id: AccountId },
    LastActive,
    Accounts,
}

#[derive(BorshSerialize, BorshDeserialize, near_sdk_macros::NearSchema)]
#[borsh(crate = "near_sdk::borsh")]
#[abi(borsh)]
pub struct AuthContractState {
    pub keys: LookupMap<AccountId, IterableSet<KeyInfo>>,
    pub last_active_timestamps: LookupMap<AccountId, u64>,
    pub registered_accounts: IterableSet<AccountId>,
}

impl AuthContractState {
    pub fn new() -> Self {
        Self {
            keys: LookupMap::new(StorageKey::Keys),
            last_active_timestamps: LookupMap::new(StorageKey::LastActive),
            registered_accounts: IterableSet::new(StorageKey::Accounts),
        }
    }

    pub fn is_authorized(
        &mut self,
        account_id: &AccountId,
        public_key: &PublicKey,
        signatures: Option<Vec<Vec<u8>>>,
    ) -> bool {
        let key_set = match self.keys.get(account_id) {
            Some(set) => set,
            None => return false,
        };

        let key_info = match key_set.iter().find(|k| k.public_key == *public_key) {
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
            self.keys.insert(account_id.clone(), IterableSet::new(StorageKey::KeySet {
                account_id: account_id.clone(),
            }));
            self.registered_accounts.insert(account_id.clone());
        }

        let key_set = self.keys.get_mut(account_id).expect("Key set should exist");
        if key_set.contains(&key_info) {
            return Err(AuthError::KeyAlreadyExists);
        }
        key_set.insert(key_info);

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

        let key_set = self.keys.get_mut(account_id).ok_or(AuthError::KeyNotFound)?;
        let key_info = KeyInfo {
            public_key: public_key.clone(),
            expiration_timestamp: None,
            is_multi_sig: false,
            multi_sig_threshold: None,
        };
        if !key_set.remove(&key_info) {
            return Err(AuthError::KeyNotFound);
        }

        if key_set.is_empty() {
            self.keys.remove(account_id);
            self.last_active_timestamps.remove(account_id);
            self.registered_accounts.remove(account_id);
        }

        AuthEvent::KeyRemoved {
            account_id: account_id.clone(),
            public_key: format!("{:?}", public_key),
        }.emit();

        Ok(())
    }

    pub fn rotate_key(
        &mut self,
        caller: &AccountId,
        account_id: &AccountId,
        old_public_key: PublicKey,
        new_public_key: PublicKey,
        expiration_days: Option<u32>,
        is_multi_sig: bool,
        multi_sig_threshold: Option<u32>,
    ) -> Result<(), AuthError> {
        if caller != account_id {
            return Err(AuthError::Unauthorized);
        }

        let key_set = self.keys.get_mut(account_id).ok_or(AuthError::KeyNotFound)?;
        let old_key_info = KeyInfo {
            public_key: old_public_key.clone(),
            expiration_timestamp: None,
            is_multi_sig: false,
            multi_sig_threshold: None,
        };
        if !key_set.contains(&old_key_info) {
            return Err(AuthError::KeyNotFound);
        }

        let new_key_info = KeyInfo {
            public_key: new_public_key.clone(),
            expiration_timestamp: expiration_days.map(|days| {
                env::block_timestamp_ms() + (days as u64 * 24 * 60 * 60 * 1000)
            }),
            is_multi_sig,
            multi_sig_threshold,
        };
        if key_set.contains(&new_key_info) {
            return Err(AuthError::KeyAlreadyExists);
        }

        key_set.remove(&old_key_info);
        key_set.insert(new_key_info);
        self.last_active_timestamps.insert(account_id.clone(), env::block_timestamp_ms());

        AuthEvent::KeyRotated {
            account_id: account_id.clone(),
            old_public_key: format!("{:?}", old_public_key),
            new_public_key: format!("{:?}", new_public_key),
        }.emit();

        Ok(())
    }

    pub fn remove_expired_keys(&mut self, account_id: &AccountId) -> Result<(), AuthError> {
        let key_set = self.keys.get_mut(account_id).ok_or(AuthError::KeyNotFound)?;
        let current_timestamp = env::block_timestamp_ms();
        let mut to_remove = Vec::new();

        for key_info in key_set.iter() {
            if key_info.expiration_timestamp.map_or(false, |exp| current_timestamp > exp) {
                to_remove.push(key_info.clone());
            }
        }

        for key_info in to_remove {
            key_set.remove(&key_info);
            AuthEvent::KeyRemoved {
                account_id: account_id.clone(),
                public_key: format!("{:?}", key_info.public_key),
            }.emit();
        }

        if key_set.is_empty() {
            self.keys.remove(account_id);
            self.last_active_timestamps.remove(account_id);
            self.registered_accounts.remove(account_id);
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

        let key_set = self.keys.get_mut(&account_id).ok_or(AuthError::KeyNotFound)?;
        let to_remove: Vec<_> = key_set.iter().cloned().collect();
        for key_info in to_remove {
            key_set.remove(&key_info);
            AuthEvent::KeyRemoved {
                account_id: account_id.clone(),
                public_key: format!("{:?}", key_info.public_key),
            }.emit();
        }

        self.keys.remove(&account_id);
        self.last_active_timestamps.remove(&account_id);
        self.registered_accounts.remove(&account_id);

        Ok(())
    }

    pub fn get_inactive_accounts(&self, limit: u32, offset: u32) -> Vec<AccountId> {
        assert!(limit <= 100, "Limit exceeds maximum allowed value");
        let current_timestamp = env::block_timestamp_ms();
        const ONE_YEAR_MS: u64 = 31_536_000_000; // 1 year in milliseconds
        let mut inactive_accounts = Vec::new();
        let start = offset as usize;
        let end = (offset + limit) as usize;

        let mut count = 0;
        let mut index = 0;
        for account_id in self.registered_accounts.iter() {
            if index >= start && count < limit {
                if let Some(timestamp) = self.last_active_timestamps.get(account_id) {
                    if current_timestamp > timestamp + ONE_YEAR_MS {
                        inactive_accounts.push(account_id.clone());
                        count += 1;
                    }
                }
            }
            index += 1;
            if index >= end {
                break;
            }
        }
        inactive_accounts
    }

    pub fn get_key_info(&self, account_id: &AccountId, public_key: &PublicKey) -> Option<KeyInfo> {
        self.keys
            .get(account_id)
            .and_then(|set| set.iter().find(|k| k.public_key == *public_key).cloned())
    }

    pub fn get_keys(&self, account_id: &AccountId, limit: u32, offset: u32) -> Vec<KeyInfo> {
        assert!(limit <= 100, "Limit exceeds maximum allowed value");
        let key_set = match self.keys.get(account_id) {
            Some(set) => set,
            None => return Vec::new(),
        };
        let start = offset as usize;
        let end = (offset + limit) as usize;
        key_set.iter().skip(start).take(end - start).cloned().collect()
    }
}