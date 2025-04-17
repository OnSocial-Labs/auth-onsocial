use near_sdk::borsh::{self, BorshSerialize};
use near_sdk_macros::NearSchema;

#[derive(BorshSerialize, NearSchema)]
#[abi(borsh)]
pub enum AuthError {
    Unauthorized,
    KeyNotFound,
    MissingSignature,
    InvalidSignature,
    InvalidThreshold,
}