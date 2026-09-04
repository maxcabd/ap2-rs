use serde::{Deserialize, Serialize};

use crate::mandate_type::MandateType;

/// A Checkout Mandate that has been parsed but not yet cryptographically
/// verified. Parsing succeeding here says nothing about whether the
/// signature, expiry, or checkout binding are valid; see `ap2-verify` for
/// the transition from unverified to verified.
///
///
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnverifiedCheckoutMandate {
    pub vct: MandateType,
    pub checkout_jwt: String,
    pub checkout_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json() -> &'static str {
        r#"{
            "vct": "mandate.checkout.1",
            "checkout_jwt": "eyJhbGciOiJFUzI1NiJ9.example.signature",
            "checkout_hash": "3f39d5c348e5b79d06e842c114e6cc571583bbf44e4b0ebfda1a01ec05745d43",
            "iat": 1735689600,
            "exp": 1735693200
        }"#
    }

    #[test]
    fn round_trips_a_well_formed_checkout_mandate() {
        let parsed: UnverifiedCheckoutMandate = serde_json::from_str(sample_json()).unwrap();

        assert_eq!(parsed.vct, MandateType::CheckoutV1);
        assert_eq!(
            parsed.checkout_jwt,
            "eyJhbGciOiJFUzI1NiJ9.example.signature"
        );
        assert_eq!(parsed.iat, Some(1735689600));
        assert_eq!(parsed.exp, Some(1735693200));

        let json = serde_json::to_string(&parsed).unwrap();
        let round_tripped: UnverifiedCheckoutMandate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, round_tripped);
    }

    #[test]
    fn parses_without_optional_iat_and_exp() {
        let json = r#"{
            "vct": "mandate.checkout.1",
            "checkout_jwt": "eyJhbGciOiJFUzI1NiJ9.example.signature",
            "checkout_hash": "3f39d5c348e5b79d06e842c114e6cc571583bbf44e4b0ebfda1a01ec05745d43"
        }"#;

        let parsed: UnverifiedCheckoutMandate = serde_json::from_str(json).unwrap();

        assert_eq!(parsed.iat, None);
        assert_eq!(parsed.exp, None);
    }

    #[test]
    fn unknown_vct_still_parses_into_unknown_variant() {
        let json = r#"{
            "vct": "mandate.checkout.2",
            "checkout_jwt": "eyJhbGciOiJFUzI1NiJ9.example.signature",
            "checkout_hash": "3f39d5c348e5b79d06e842c114e6cc571583bbf44e4b0ebfda1a01ec05745d43"
        }"#;

        let parsed: UnverifiedCheckoutMandate = serde_json::from_str(json).unwrap();

        assert_eq!(
            parsed.vct,
            MandateType::Unknown("mandate.checkout.2".to_string())
        );
    }

    #[test]
    fn missing_required_field_fails_to_parse() {
        let json = r#"{
            "vct": "mandate.checkout.1",
            "checkout_hash": "3f39d5c348e5b79d06e842c114e6cc571583bbf44e4b0ebfda1a01ec05745d43"
        }"#;

        let result: Result<UnverifiedCheckoutMandate, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }
}
