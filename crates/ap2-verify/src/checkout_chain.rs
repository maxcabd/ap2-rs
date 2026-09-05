use ap2_core::{MandateType, OpenCheckoutMandate, UnverifiedCheckoutMandate};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;

use crate::constraints::{check_checkout_constraints, CheckoutForConstraints};
use crate::error::VerifyError;

const CHAIN_LEN: usize = 2;

/// A parsed (not yet policy-checked) Open + Closed Checkout Mandate
/// delegation pair, typically the output of [`crate::verify_chain`].
#[derive(Debug, Clone)]
pub struct CheckoutMandateChain {
    pub open_mandate: OpenCheckoutMandate,
    pub closed_mandate: UnverifiedCheckoutMandate,
}

impl CheckoutMandateChain {
    pub fn parse(payloads: Vec<serde_json::Map<String, Value>>) -> Result<Self, VerifyError> {
        if payloads.len() != CHAIN_LEN {
            return Err(VerifyError::MalformedChainHop(
                "checkout mandate chain requires exactly 2 payloads",
            ));
        }
        let mut hops = payloads.into_iter();
        let open_mandate: OpenCheckoutMandate =
            serde_json::from_value(Value::Object(hops.next().unwrap()))?;
        let closed_mandate: UnverifiedCheckoutMandate =
            serde_json::from_value(Value::Object(hops.next().unwrap()))?;

        if open_mandate.vct != MandateType::OpenCheckoutV1 {
            return Err(VerifyError::WrongMandateType(open_mandate.vct));
        }
        if closed_mandate.vct != MandateType::CheckoutV1 {
            return Err(VerifyError::WrongMandateType(closed_mandate.vct));
        }

        Ok(Self {
            open_mandate,
            closed_mandate,
        })
    }

    /// Checks the open mandate's constraints against `checkout_jwt`'s
    /// (unverified -- see below) payload, and optionally that
    /// `expected_checkout_hash` matches the closed mandate's own hash.
    ///
    /// Returns violation messages; empty means compliant. Does not verify
    /// `checkout_jwt`'s signature itself: the closed mandate's own
    /// signature (already checked before this is called) attests to
    /// `checkout_hash = sha256(checkout_jwt)`, so a caller who independently
    /// trusts they hold the right `checkout_jwt` bytes gets that binding
    /// for free by also passing `expected_checkout_hash`.
    pub fn verify(
        &self,
        expected_checkout_hash: Option<&str>,
        checkout_jwt: Option<&str>,
    ) -> Vec<String> {
        let mut violations = Vec::new();

        let Some(checkout_jwt) = checkout_jwt else {
            violations.push("checkout_jwt is required to verify checkout constraints.".into());
            return violations;
        };

        let checkout = match extract_checkout_payload(checkout_jwt) {
            Ok(checkout) => checkout,
            Err(message) => {
                violations.push(message);
                return violations;
            }
        };

        violations.extend(check_checkout_constraints(&self.open_mandate, &checkout));

        if let Some(expected) = expected_checkout_hash {
            if expected != self.closed_mandate.checkout_hash {
                violations.push(format!(
                    "Checkout checkout_hash mismatch: expected {expected}, got {}",
                    self.closed_mandate.checkout_hash
                ));
            }
        }

        violations
    }
}

fn extract_checkout_payload(checkout_jwt: &str) -> Result<CheckoutForConstraints, String> {
    let parts: Vec<&str> = checkout_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("Malformed checkout_jwt: expected header.payload.signature".into());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("Base64 decoding failed for checkout_jwt: {e}"))?;
    serde_json::from_slice(&decoded)
        .map_err(|e| format!("checkout_jwt payload failed schema validation: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(value: Value) -> serde_json::Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn encode_checkout_jwt(payload: &Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#);
        let body = URL_SAFE_NO_PAD.encode(payload.to_string());
        format!("{header}.{body}.sig")
    }

    fn open_mandate_payload() -> Value {
        json!({
            "vct": "mandate.checkout.open.1",
            "constraints": [
                {"type": "checkout.allowed_merchants", "allowed": [{"id": "m-1", "name": "Good Store"}]},
            ],
            "cnf": {"jwk": {"kty": "EC"}},
        })
    }

    fn closed_mandate_payload(checkout_hash: &str) -> Value {
        json!({
            "vct": "mandate.checkout.1",
            "checkout_hash": checkout_hash,
        })
    }

    #[test]
    fn parses_a_well_formed_chain() {
        let chain = CheckoutMandateChain::parse(vec![
            obj(open_mandate_payload()),
            obj(closed_mandate_payload("hash")),
        ])
        .unwrap();

        assert_eq!(chain.closed_mandate.checkout_hash, "hash");
    }

    #[test]
    fn rejects_wrong_number_of_payloads() {
        let err = CheckoutMandateChain::parse(vec![obj(open_mandate_payload())]).unwrap_err();
        assert!(matches!(err, VerifyError::MalformedChainHop(_)));
    }

    #[test]
    fn rejects_hops_in_the_wrong_order() {
        // The closed mandate's shape (no constraints/cnf) fails to
        // deserialize as an OpenCheckoutMandate before vct is even checked.
        let err = CheckoutMandateChain::parse(vec![
            obj(closed_mandate_payload("hash")),
            obj(open_mandate_payload()),
        ])
        .unwrap_err();
        assert!(matches!(err, VerifyError::MalformedClaims(_)));
    }

    #[test]
    fn verify_reports_no_violations_for_a_compliant_checkout() {
        let chain = CheckoutMandateChain::parse(vec![
            obj(open_mandate_payload()),
            obj(closed_mandate_payload("hash")),
        ])
        .unwrap();

        let checkout_jwt = encode_checkout_jwt(&json!({
            "merchant": {"id": "m-1", "name": "Good Store"},
        }));

        let violations = chain.verify(None, Some(&checkout_jwt));
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn verify_reports_a_merchant_violation() {
        let chain = CheckoutMandateChain::parse(vec![
            obj(open_mandate_payload()),
            obj(closed_mandate_payload("hash")),
        ])
        .unwrap();

        let checkout_jwt = encode_checkout_jwt(&json!({
            "merchant": {"id": "m-evil", "name": "Evil Store"},
        }));

        let violations = chain.verify(None, Some(&checkout_jwt));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("not in allowed list"));
    }

    #[test]
    fn verify_reports_a_checkout_hash_mismatch() {
        let chain = CheckoutMandateChain::parse(vec![
            obj(open_mandate_payload()),
            obj(closed_mandate_payload("hash")),
        ])
        .unwrap();

        let checkout_jwt = encode_checkout_jwt(&json!({
            "merchant": {"id": "m-1", "name": "Good Store"},
        }));

        let violations = chain.verify(Some("expected-hash"), Some(&checkout_jwt));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("checkout_hash mismatch"));
    }

    #[test]
    fn verify_requires_a_checkout_jwt() {
        let chain = CheckoutMandateChain::parse(vec![
            obj(open_mandate_payload()),
            obj(closed_mandate_payload("hash")),
        ])
        .unwrap();

        let violations = chain.verify(None, None);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("checkout_jwt is required"));
    }
}
