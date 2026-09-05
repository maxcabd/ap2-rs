use serde::{Deserialize, Serialize};

/// `spec/schemas/ap2/types/pisp.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pisp {
    pub legal_name: String,
    pub brand_name: String,
    pub domain_name: String,
}
