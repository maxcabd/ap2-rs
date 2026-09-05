use serde::{Deserialize, Serialize};

use crate::types::ReceiptStatus;

/// The status-specific fields of a [`PaymentReceipt`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum PaymentOutcome {
    Success {
        psp_confirmation_id: String,
        network_confirmation_id: String,
    },
    Error {
        error: String,
        error_description: String,
    },
}

/// `spec/schemas/ap2/payment_receipt.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentReceipt {
    #[serde(flatten)]
    pub outcome: PaymentOutcome,
    pub iss: String,
    pub iat: i64,
    /// Hash of the closed Mandate this receipt binds to.
    pub reference: String,
    pub payment_id: String,
}

impl PaymentReceipt {
    pub fn status(&self) -> ReceiptStatus {
        match self.outcome {
            PaymentOutcome::Success { .. } => ReceiptStatus::Success,
            PaymentOutcome::Error { .. } => ReceiptStatus::Error,
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
            "iss": "https://psp.example.com",
            "iat": 1700000000,
            "reference": "hash",
            "payment_id": "pay-1",
            "psp_confirmation_id": "psp-1",
            "network_confirmation_id": "net-1",
        });
        let parsed: PaymentReceipt = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.status(), ReceiptStatus::Success);
        assert_eq!(parsed.payment_id, "pay-1");

        let round_tripped: PaymentReceipt =
            serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(parsed, round_tripped);
    }

    #[test]
    fn round_trips_an_error_receipt() {
        let value = json!({
            "status": "Error",
            "iss": "https://psp.example.com",
            "iat": 1700000000,
            "reference": "hash",
            "payment_id": "pay-1",
            "error": "declined",
            "error_description": "insufficient funds",
        });
        let parsed: PaymentReceipt = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.status(), ReceiptStatus::Error);
    }

    #[test]
    fn success_without_confirmation_ids_fails_to_parse() {
        let value = json!({
            "status": "Success",
            "iss": "https://psp.example.com",
            "iat": 1700000000,
            "reference": "hash",
            "payment_id": "pay-1",
        });
        let result: Result<PaymentReceipt, _> = serde_json::from_value(value);
        assert!(result.is_err());
    }
}
