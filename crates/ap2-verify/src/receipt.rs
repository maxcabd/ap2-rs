use ap2_core::{CheckoutReceipt, PaymentReceipt};
use ap2_credentials::{verify_compact_jws, Jwk, ALLOWED_ALGORITHMS};
use serde_json::Value;

use crate::error::VerifyError;

/// Verifies a receipt JWT (a plain compact JWS, not an SD-JWT -- receipts
/// carry no selective disclosure) and optionally checks its `reference`
/// against a value the caller already knows (e.g. the hash of the closed
/// mandate it should be binding to).
pub fn verify_checkout_receipt(
    receipt_jwt: &str,
    issuer_key: &Jwk,
    expected_reference: Option<&str>,
) -> Result<CheckoutReceipt, VerifyError> {
    let verified = verify_compact_jws::<Value>(receipt_jwt, issuer_key, ALLOWED_ALGORITHMS)?;
    let receipt: CheckoutReceipt = serde_json::from_value(verified.claims)?;
    check_reference(&receipt.reference, expected_reference)?;
    Ok(receipt)
}

pub fn verify_payment_receipt(
    receipt_jwt: &str,
    issuer_key: &Jwk,
    expected_reference: Option<&str>,
) -> Result<PaymentReceipt, VerifyError> {
    let verified = verify_compact_jws::<Value>(receipt_jwt, issuer_key, ALLOWED_ALGORITHMS)?;
    let receipt: PaymentReceipt = serde_json::from_value(verified.claims)?;
    check_reference(&receipt.reference, expected_reference)?;
    Ok(receipt)
}

fn check_reference(actual: &str, expected: Option<&str>) -> Result<(), VerifyError> {
    match expected {
        Some(expected) if expected != actual => Err(VerifyError::ReceiptReferenceMismatch),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;
    use serde_json::json;

    fn issuer_keypair() -> (EncodingKey, Jwk) {
        let signing_key = SigningKey::random(&mut OsRng);
        let der = signing_key.to_pkcs8_der().unwrap();
        let encoding_key = EncodingKey::from_ec_der(der.as_bytes());
        let point = signing_key.verifying_key().to_encoded_point(false);
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }))
        .unwrap();
        (encoding_key, jwk)
    }

    #[test]
    fn verifies_a_well_formed_checkout_receipt() {
        let (signing_key, issuer_key) = issuer_keypair();
        let claims = json!({
            "status": "Success",
            "iss": "https://merchant.example.com",
            "iat": 1700000000,
            "reference": "mandate-hash",
            "order_id": "order-1",
        });
        let receipt_jwt = encode(&Header::new(Algorithm::ES256), &claims, &signing_key).unwrap();

        let receipt = verify_checkout_receipt(&receipt_jwt, &issuer_key, Some("mandate-hash"))
            .expect("well-formed receipt must verify");

        assert_eq!(receipt.reference, "mandate-hash");
    }

    #[test]
    fn rejects_a_reference_mismatch() {
        let (signing_key, issuer_key) = issuer_keypair();
        let claims = json!({
            "status": "Success",
            "iss": "https://merchant.example.com",
            "iat": 1700000000,
            "reference": "mandate-hash",
            "order_id": "order-1",
        });
        let receipt_jwt = encode(&Header::new(Algorithm::ES256), &claims, &signing_key).unwrap();

        let err =
            verify_checkout_receipt(&receipt_jwt, &issuer_key, Some("wrong-hash")).unwrap_err();

        assert!(matches!(err, VerifyError::ReceiptReferenceMismatch));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn verifies_a_well_formed_payment_receipt() {
        let (signing_key, issuer_key) = issuer_keypair();
        let claims = json!({
            "status": "Success",
            "iss": "https://psp.example.com",
            "iat": 1700000000,
            "reference": "mandate-hash",
            "payment_id": "pay-1",
            "psp_confirmation_id": "psp-1",
            "network_confirmation_id": "net-1",
        });
        let receipt_jwt = encode(&Header::new(Algorithm::ES256), &claims, &signing_key).unwrap();

        let receipt = verify_payment_receipt(&receipt_jwt, &issuer_key, None)
            .expect("well-formed receipt must verify");

        assert_eq!(receipt.payment_id, "pay-1");
    }

    #[test]
    fn rejects_a_receipt_not_signed_by_the_claimed_issuer() {
        let (_signing_key, issuer_key) = issuer_keypair();
        let (impostor_key, _impostor_jwk) = issuer_keypair();
        let claims = json!({
            "status": "Error",
            "iss": "https://merchant.example.com",
            "iat": 1700000000,
            "reference": "mandate-hash",
            "error": "declined",
            "error_description": "card declined",
        });
        let receipt_jwt = encode(&Header::new(Algorithm::ES256), &claims, &impostor_key).unwrap();

        let err = verify_checkout_receipt(&receipt_jwt, &issuer_key, None).unwrap_err();

        assert!(matches!(
            err,
            VerifyError::Credential(ap2_credentials::CredentialError::SignatureInvalid(_))
        ));
    }
}
