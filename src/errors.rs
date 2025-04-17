use near_sdk::{FunctionError};
use near_sdk_macros::NearSchema;
use near_sdk::borsh::{BorshSerialize, BorshDeserialize};

#[derive(Debug, NearSchema, BorshSerialize, BorshDeserialize)]
#[abi(borsh)]
pub enum AuthError {
    Unauthorized,
    KeyNotFound,
    KeyAlreadyExists,
    AccountStillActive,
}

impl FunctionError for AuthError {
    fn panic(&self) -> ! {
        panic!("{}", match self {
            AuthError::Unauthorized => "Unauthorized access",
            AuthError::KeyNotFound => "Key not found",
            AuthError::KeyAlreadyExists => "Key already exists",
            AuthError::AccountStillActive => "Account is still active",
        })
    }
}