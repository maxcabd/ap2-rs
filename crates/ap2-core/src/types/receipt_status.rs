use serde::{Deserialize, Serialize};

/// `spec/schemas/ap2/types/receipt_status.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptStatus {
    Success,
    Error,
}
