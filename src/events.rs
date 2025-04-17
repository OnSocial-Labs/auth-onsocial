use near_sdk::{near, AccountId};

#[near(event_json(standard = "nep297"))]
pub enum AuthEvent {
    #[event_version("1.0.0")]
    KeyRegistered { account_id: AccountId, public_key: String },
    #[event_version("1.0.0")]
    KeyRemoved { account_id: AccountId, public_key: String },
}