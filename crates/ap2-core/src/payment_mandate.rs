use serde::{Deserialize, Serialize};

use crate::mandate_type::MandateType;
use crate::types::{Amount, Merchant, PaymentInstrument, Pisp};

/// `spec/schemas/ap2/payment_mandate.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PaymentMandate {
    pub vct: MandateType,
    /// Hash of the bound `checkout_jwt` -- see `ap2-verify` for binding.
    pub transaction_id: String,
    pub payee: Merchant,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pisp: Option<Pisp>,
    pub payment_amount: Amount,
    pub payment_instrument: PaymentInstrument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_date: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_data: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trips_a_well_formed_payment_mandate() {
        let value = json!({
            "vct": "mandate.payment.1",
            "transaction_id": "abc123",
            "payee": {"id": "m-1", "name": "Store"},
            "payment_amount": {"amount": 2799, "currency": "USD"},
            "payment_instrument": {"id": "pi-1", "type": "credit"},
        });
        let parsed: PaymentMandate = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.vct, MandateType::PaymentV1);
        assert_eq!(parsed.payment_amount.amount, 2799);

        let round_tripped: PaymentMandate =
            serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
        assert_eq!(parsed, round_tripped);
    }
}
