use serde::{Deserialize, Serialize};

/// `spec/schemas/ap2/types/amount.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Amount {
    pub amount: i64,
    pub currency: String,
}
