use ap2_core::{MandateType, OpenPaymentMandate, PaymentMandate};
use serde_json::Value;

use crate::error::VerifyError;
use crate::payment_constraints::{check_payment_constraints, MandateContext};

const CHAIN_LEN: usize = 2;

/// A parsed (not yet policy-checked) Open + Closed Payment Mandate
/// delegation pair, typically the output of [`crate::verify_chain`].
#[derive(Debug, Clone)]
pub struct PaymentMandateChain {
    pub open_mandate: OpenPaymentMandate,
    pub closed_mandate: PaymentMandate,
}

impl PaymentMandateChain {
    pub fn parse(payloads: Vec<serde_json::Map<String, Value>>) -> Result<Self, VerifyError> {
        if payloads.len() != CHAIN_LEN {
            return Err(VerifyError::MalformedChainHop(
                "payment mandate chain requires exactly 2 payloads",
            ));
        }
        let mut hops = payloads.into_iter();
        let open_mandate: OpenPaymentMandate =
            serde_json::from_value(Value::Object(hops.next().unwrap()))?;
        let closed_mandate: PaymentMandate =
            serde_json::from_value(Value::Object(hops.next().unwrap()))?;

        if open_mandate.vct != MandateType::OpenPaymentV1 {
            return Err(VerifyError::WrongMandateType(open_mandate.vct));
        }
        if closed_mandate.vct != MandateType::PaymentV1 {
            return Err(VerifyError::WrongMandateType(closed_mandate.vct));
        }

        Ok(Self {
            open_mandate,
            closed_mandate,
        })
    }

    /// Checks the open mandate's pre-set claims and constraints against
    /// the closed mandate. Returns violation messages; empty means
    /// compliant.
    pub fn verify(
        &self,
        open_checkout_hash: Option<&str>,
        mandate_context: Option<&MandateContext>,
    ) -> Vec<String> {
        check_payment_constraints(
            &self.open_mandate,
            &self.closed_mandate,
            open_checkout_hash,
            mandate_context,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(value: Value) -> serde_json::Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn open_mandate_payload() -> Value {
        json!({
            "vct": "mandate.payment.open.1",
            "constraints": [
                {"type": "payment.allowed_payees", "allowed": [{"id": "m-1", "name": "Good Store"}]},
            ],
            "cnf": {"jwk": {"kty": "EC"}},
        })
    }

    fn closed_mandate_payload(payee_id: &str, payee_name: &str) -> Value {
        json!({
            "vct": "mandate.payment.1",
            "transaction_id": "tx-1",
            "payee": {"id": payee_id, "name": payee_name},
            "payment_amount": {"amount": 1000, "currency": "USD"},
            "payment_instrument": {"id": "pi-1", "type": "credit"},
        })
    }

    #[test]
    fn verify_reports_no_violations_for_a_compliant_payment() {
        let chain = PaymentMandateChain::parse(vec![
            obj(open_mandate_payload()),
            obj(closed_mandate_payload("m-1", "Good Store")),
        ])
        .unwrap();

        assert!(chain.verify(None, None).is_empty());
    }

    #[test]
    fn verify_reports_a_payee_violation() {
        let chain = PaymentMandateChain::parse(vec![
            obj(open_mandate_payload()),
            obj(closed_mandate_payload("m-evil", "Evil Store")),
        ])
        .unwrap();

        let violations = chain.verify(None, None);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("not in allowed list"));
    }

    #[test]
    fn rejects_wrong_number_of_payloads() {
        let err = PaymentMandateChain::parse(vec![obj(open_mandate_payload())]).unwrap_err();
        assert!(matches!(err, VerifyError::MalformedChainHop(_)));
    }
}
