use serde::{Deserialize, Serialize};

use crate::types::ReceiptStatus;

/// The status-specific fields of a [`CheckoutReceipt`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum CheckoutOutcome {
    Success {
        order_id: String,
    },
    Error {
        error: String,
        error_description: String,
    },
}

/// `spec/schemas/ap2/checkout_receipt.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckoutReceipt {
    #[serde(flatten)]
    pub outcome: CheckoutOutcome,
    pub iss: String,
    pub iat: i64,
    /// Hash of the closed Mandate this receipt binds to.
    pub reference: String,
}

impl CheckoutReceipt {
    pub fn status(&self) -> ReceiptStatus {
        match self.outcome {
            CheckoutOutcome::Success { .. } => ReceiptStatus::Success,
            CheckoutOutcome::Error { .. } => ReceiptStatus::Error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trips_a_success_receipt() {
        let value = json!({
            "status": "Success",
            "iss": "https://merchant.example.com",
            "iat": 1700000000,
            "reference": "hash",
            "order_id": "order-1",
        });
        let parsed: CheckoutReceipt = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.status(), ReceiptStatus::Success);
        assert!(
            matches!(&parsed.outcome, CheckoutOutcome::Success { order_id } if order_id == "order-1")
        );

        let round_tripped: CheckoutReceipt =
            serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(parsed, round_tripped);
    }

    #[test]
    fn round_trips_an_error_receipt() {
        let value = json!({
            "status": "Error",
            "iss": "https://merchant.example.com",
            "iat": 1700000000,
            "reference": "hash",
            "error": "declined",
            "error_description": "card declined",
        });
        let parsed: CheckoutReceipt = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.status(), ReceiptStatus::Error);
    }

    #[test]
    fn success_without_order_id_fails_to_parse() {
        let value = json!({
            "status": "Success",
            "iss": "https://merchant.example.com",
            "iat": 1700000000,
            "reference": "hash",
        });
        let result: Result<CheckoutReceipt, _> = serde_json::from_value(value);
        assert!(result.is_err());
    }
}
