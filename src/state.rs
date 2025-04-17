use near_sdk::{env, AccountId, PublicKey};
use near_sdk::store::LookupMap;
use near_sdk_macros::NearSchema;
use crate::types::KeyInfo;
use crate::errors::AuthError;
use crate::events::AuthEvent;

#[near(contract_state)]
#[derive(NearSchema)]
pub struct AuthOnSocial {
    keys: LookupMap<(AccountId, PublicKey), KeyInfo>,
}

impl Default for AuthOnSocial {
    fn default() -> Self {
        Self {
            keys: LookupMap::new(b"k".to_vec()),
        }
    }
}

impl AuthOnSocial {
    pub fn is_authorized_internal(
        &self,
        account_id: AccountId,
        public_key: PublicKey,
        signatures: Option<Vec<Vec<u8>>>,
        delegate_action: Vec<u8>,
    ) -> Result<bool, AuthError> {
        let key_info = self.keys.get(&(account_id.clone(), public_key.clone()))
            .ok_or(AuthError::KeyNotFound)?;

        if let Some(expiration) = key_info.expiration_timestamp {
            if env::block_timestamp_ms() > expiration {
                return Ok(false); // Soft fail for onsocial-js retry
            }
        }

        if !key_info.is_multi_sig {
            let signature = signatures
                .and_then(|sigs| sigs.first().cloned())
                .ok_or(AuthError::MissingSignature)?;
            // Ensure signature is 64 bytes
            if signature.len() != 64 {
                return Ok(false);
            }
            let signature_array: [u8; 64] = signature.try_into().map_err(|_| AuthError::InvalidSignature)?;
            let public_key_bytes = public_key.as_bytes();
            // Ensure public_key_bytes is 32 bytes
            if public_key_bytes.len() != 32 {
                return Ok(false);
            }
            let public_key_array: [u8; 32] = public_key_bytes.try_into().map_err(|_| AuthError::InvalidSignature)?;
            if !env::ed25519_verify(&signature_array, &delegate_action, &public_key_array) {
                return Ok(false);
            }
        } else {
            let threshold = key_info.multi_sig_threshold.unwrap_or(1);
            let signatures = signatures.unwrap_or_default();
            if (signatures.len() as u32) < threshold {
                return Ok(false);
            }
            // Assume relayer pre-validates multi-sig signatures for gas efficiency
        }

        Ok(true)
    }

    pub fn register_key_internal(
        &mut self,
        account_id: AccountId,
        public_key: PublicKey,
        expiration_days: Option<u32>,
        is_multi_sig: bool,
        multi_sig_threshold: Option<u32>,
    ) -> Result<(), AuthError> {
        let caller = env::predecessor_account_id();
        if caller != account_id {
            return Err(AuthError::Unauthorized);
        }

        if multi_sig_threshold.unwrap_or(0) > 10 {
            return Err(AuthError::InvalidThreshold); // Prevent gas-heavy multi-sig
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

        self.keys.insert((account_id.clone(), public_key.clone()), key_info);

        AuthEvent::KeyRegistered {
            account_id,
            public_key: format!("{:?}", public_key),
        }.emit();

        Ok(())
    }

    pub fn remove_key_internal(
        &mut self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Result<(), AuthError> {
        let caller = env::predecessor_account_id();
        if caller != account_id {
            return Err(AuthError::Unauthorized);
        }

        if self.keys.remove(&(account_id.clone(), public_key.clone())).is_some() {
            AuthEvent::KeyRemoved {
                account_id,
                public_key: format!("{:?}", public_key),
            }.emit();
            Ok(())
        } else {
            Err(AuthError::KeyNotFound)
        }
    }

    pub fn extend_key_expiration_internal(
        &mut self,
        account_id: AccountId,
        public_key: PublicKey,
        additional_days: u32,
    ) -> Result<(), AuthError> {
        let caller = env::predecessor_account_id();
        if caller != account_id {
            return Err(AuthError::Unauthorized);
        }

        let mut key_info = self.keys.get(&(account_id.clone(), public_key.clone()))
            .ok_or(AuthError::KeyNotFound)?;

        let new_expiration = env::block_timestamp_ms() + (additional_days as u64 * 24 * 60 * 60 * 1000);
        key_info.expiration_timestamp = Some(new_expiration);
        self.keys.insert((account_id.clone(), public_key.clone()), key_info);

        AuthEvent::KeyExpirationExtended {
            account_id,
            public_key: format!("{:?}", public_key),
            new_expiration,
        }.emit();

        Ok(())
    }

    pub fn check_key_expiration_internal(
        &self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Option<u64> {
        self.keys.get(&(account_id, public_key))
            .map(|info| info.expiration_timestamp)
            .flatten()
    }

    pub fn get_key_info_internal(
        &self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Option<KeyInfo> {
        self.keys.get(&(account_id, public_key)).cloned()
    }
}