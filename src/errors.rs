use near_sdk::{FunctionError};
use near_sdk_macros::NearSchema;
use near_sdk::borsh::{BorshSerialize, BorshDeserialize};

#[derive(Debug, NearSchema, BorshSerialize, BorshDeserialize)]
#[abi(borsh)]
pub enum AuthError {
    Unauthorized,
    KeyNotFound,
    KeyAlreadyExists,
    ContractPaused,
    AdminAlreadyExists,
    AdminNotFound,
    LastAdmin,
}

impl FunctionError for AuthError {
    fn panic(&self) -> ! {
        panic!("{}", match self {
            AuthError::Unauthorized => "Unauthorized access",
            AuthError::KeyNotFound => "Key not found",
            AuthError::KeyAlreadyExists => "Key already exists",
            AuthError::ContractPaused => "Contract is paused",
            AuthError::AdminAlreadyExists => "Admin already exists",
            AuthError::AdminNotFound => "Admin not found",
            AuthError::LastAdmin => "Cannot remove the last admin",
        })
    }
}