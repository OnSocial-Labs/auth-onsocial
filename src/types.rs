use near_sdk::{PublicKey};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk_macros::NearSchema;

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, NearSchema)]
#[serde(crate = "near_sdk::serde")]
#[borsh(crate = "near_sdk::borsh")]
#[abi(json, borsh)]
pub struct KeyInfo {
    pub public_key: PublicKey,
    pub expiration_timestamp: Option<u64>,
    pub is_multi_sig: bool,
    pub multi_sig_threshold: Option<u32>,
}