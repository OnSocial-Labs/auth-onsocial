use near_sdk::PublicKey;
use near_sdk::serde::{Serialize, Deserialize};
use near_sdk::borsh::{self, BorshSerialize, BorshDeserialize};
use near_sdk_macros::NearSchema;

#[derive(
    NearSchema,
    Serialize,
    Deserialize,
    Clone,
    BorshSerialize,
    BorshDeserialize
)]
#[abi(json, borsh)]
#[serde(crate = "near_sdk::serde")]
#[borsh(crate = "near_sdk::borsh")]
pub struct KeyInfo {
    pub public_key: PublicKey,
    pub expiration_timestamp: Option<u64>,
    pub is_multi_sig: bool,
    pub multi_sig_threshold: Option<u32>,
}