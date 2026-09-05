use serde::{Deserialize, Serialize};

use crate::mandate_type::MandateType;
use crate::types::{Amount, Merchant, PaymentInstrument, Pisp};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frequency {
    #[serde(rename = "ON_DEMAND")]
    OnDemand,
    #[serde(rename = "DAILY")]
    Daily,
    #[serde(rename = "WEEKLY")]
    Weekly,
    #[serde(rename = "BIWEEKLY")]
    Biweekly,
    #[serde(rename = "MONTHLY")]
    Monthly,
    #[serde(rename = "QUARTERLY")]
    Quarterly,
    #[serde(rename = "ANNUALLY")]
    Annually,
}

/// One constraint the future Payment must satisfy. An unrecognized `type`
/// fails to parse rather than being silently dropped -- see
/// `open_checkout_mandate::Constraint` for why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Constraint {
    #[serde(rename = "payment.agent_recurrence")]
    AgentRecurrence {
        frequency: Frequency,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_occurrences: Option<u32>,
    },
    #[serde(rename = "payment.allowed_payees")]
    AllowedPayees { allowed: Vec<Merchant> },
    #[serde(rename = "payment.allowed_payment_instruments")]
    AllowedPaymentInstruments { allowed: Vec<PaymentInstrument> },
    #[serde(rename = "payment.allowed_pisps")]
    AllowedPisps { allowed: Vec<Pisp> },
    #[serde(rename = "payment.amount_range")]
    AmountRange {
        currency: String,
        max: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<i64>,
    },
    #[serde(rename = "payment.budget")]
    Budget { max: f64, currency: String },
    #[serde(rename = "payment.execution_date")]
    ExecutionDate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        not_before: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        not_after: Option<String>,
    },
    #[serde(rename = "payment.reference")]
    PaymentReference { conditional_transaction_id: String },
}

/// `spec/schemas/ap2/open_payment_mandate.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenPaymentMandate {
    pub vct: MandateType,
    pub constraints: Vec<Constraint>,
    /// RFC 7800 `cnf`. Left as raw JSON -- see `OpenCheckoutMandate::cnf`.
    pub cnf: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee: Option<Merchant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_amount: Option<Amount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_instrument: Option<PaymentInstrument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pisp: Option<Pisp>,
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

    fn sample() -> serde_json::Value {
        json!({
            "vct": "mandate.payment.open.1",
            "constraints": [
                {"type": "payment.agent_recurrence", "frequency": "MONTHLY", "max_occurrences": 12},
                {"type": "payment.allowed_payees", "allowed": [{"id": "m-1", "name": "Store"}]},
                {"type": "payment.amount_range", "currency": "USD", "max": 5000},
                {"type": "payment.budget", "max": 100.0, "currency": "USD"},
                {"type": "payment.execution_date", "not_before": "2026-01-01"},
                {"type": "payment.reference", "conditional_transaction_id": "abc"},
                {"type": "payment.allowed_payment_instruments", "allowed": [{"id": "pi-1", "type": "credit"}]},
                {"type": "payment.allowed_pisps", "allowed": [{"legal_name": "A", "brand_name": "B", "domain_name": "c.com"}]},
            ],
            "cnf": {"jwk": {"kty": "EC"}},
        })
    }

    #[test]
    fn parses_all_constraint_types() {
        let mandate: OpenPaymentMandate = serde_json::from_value(sample()).unwrap();
        assert_eq!(mandate.vct, MandateType::OpenPaymentV1);
        assert_eq!(mandate.constraints.len(), 8);
        assert!(matches!(
            mandate.constraints[0],
            Constraint::AgentRecurrence {
                frequency: Frequency::Monthly,
                max_occurrences: Some(12)
            }
        ));
    }

    #[test]
    fn rejects_an_unrecognized_constraint_type() {
        let mut value = sample();
        value["constraints"] = json!([{"type": "payment.something_new"}]);
        let result: Result<OpenPaymentMandate, _> = serde_json::from_value(value);
        assert!(result.is_err());
    }
}
