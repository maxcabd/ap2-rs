use ap2_core::{MandateType, PaymentMandate};
use ap2_credentials::{
    sha256_base64url, verify_compact_jws, verify_sd_jwt, Jwk, ALLOWED_ALGORITHMS,
};
use serde_json::Value;

use crate::checkout::unwrap_delegate_payload;
use crate::error::VerifyError;

/// A Payment Mandate whose Issuer signature, hash binding to a Checkout
/// JWT, and (if present) expiry/freshness have all been verified.
#[derive(Debug, Clone)]
pub struct VerifiedPaymentMandate {
    pub transaction_id: String,
    pub iat: Option<i64>,
    pub exp: Option<i64>,
    pub payment_mandate: PaymentMandate,
}

/// Verifies a Payment Mandate SD-JWT presentation against the Checkout JWT
/// it authorizes payment for. Mirrors `verify_checkout_mandate`: binds via
/// `transaction_id = sha256_base64url(checkout_jwt)` instead of
/// `checkout_hash`.
pub fn verify_payment_mandate(
    mandate_presentation: &str,
    checkout_jwt: &str,
    user_key: &Jwk,
    merchant_key: &Jwk,
    now: i64,
    leeway_seconds: i64,
) -> Result<VerifiedPaymentMandate, VerifyError> {
    let verified_mandate = verify_sd_jwt(mandate_presentation, user_key)?;
    let claims = unwrap_delegate_payload(verified_mandate.claims)?;

    let mandate: PaymentMandate = serde_json::from_value(Value::Object(claims))?;

    match &mandate.vct {
        MandateType::PaymentV1 => {}
        MandateType::Unknown(vct) => {
            return Err(VerifyError::UnsupportedMandateType(vct.clone()));
        }
        other => return Err(VerifyError::WrongMandateType(other.clone())),
    }

    if let Some(exp) = mandate.exp {
        if now - leeway_seconds > exp {
            return Err(VerifyError::Expired {
                exp,
                now,
                leeway_seconds,
            });
        }
    }
    if let Some(iat) = mandate.iat {
        if iat - leeway_seconds > now {
            return Err(VerifyError::NotYetValid {
                iat,
                now,
                leeway_seconds,
            });
        }
    }

    verify_compact_jws::<Value>(checkout_jwt, merchant_key, ALLOWED_ALGORITHMS)?;

    let computed_hash = sha256_base64url(checkout_jwt);
    if computed_hash != mandate.transaction_id {
        return Err(VerifyError::TransactionIdMismatch);
    }

    Ok(VerifiedPaymentMandate {
        transaction_id: mandate.transaction_id.clone(),
        iat: mandate.iat,
        exp: mandate.exp,
        payment_mandate: mandate,
    })
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

    const NOW: i64 = 1_700_000_000;
    const LEEWAY: i64 = 60;

    struct KeyPair {
        encoding_key: EncodingKey,
        jwk: Jwk,
    }

    fn generate_es256_keypair() -> KeyPair {
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
        KeyPair { encoding_key, jwk }
    }

    fn sign(claims: &Value, key: &EncodingKey) -> String {
        encode(&Header::new(Algorithm::ES256), claims, key).unwrap()
    }

    fn present(claims: &Value, key: &EncodingKey) -> String {
        format!("{}~", sign(claims, key))
    }

    #[test]
    fn verifies_a_well_formed_payment_mandate() {
        let user = generate_es256_keypair();
        let merchant = generate_es256_keypair();

        let checkout_jwt = sign(&json!({"cart": "whatever"}), &merchant.encoding_key);
        let transaction_id = sha256_base64url(&checkout_jwt);

        let mandate_claims = json!({
            "vct": "mandate.payment.1",
            "transaction_id": transaction_id,
            "payee": {"id": "m-1", "name": "Store"},
            "payment_amount": {"amount": 2799, "currency": "USD"},
            "payment_instrument": {"id": "pi-1", "type": "credit"},
        });
        let mandate_presentation = present(&mandate_claims, &user.encoding_key);

        let verified = verify_payment_mandate(
            &mandate_presentation,
            &checkout_jwt,
            &user.jwk,
            &merchant.jwk,
            NOW,
            LEEWAY,
        )
        .expect("well-formed payment mandate must verify");

        assert_eq!(verified.transaction_id, transaction_id);
        assert_eq!(verified.payment_mandate.payee.name, "Store");
    }

    #[test]
    fn rejects_a_transaction_id_that_does_not_match_checkout() {
        let user = generate_es256_keypair();
        let merchant = generate_es256_keypair();

        let checkout_jwt = sign(&json!({"cart": "whatever"}), &merchant.encoding_key);
        let substituted = sign(&json!({"cart": "different"}), &merchant.encoding_key);

        let mandate_claims = json!({
            "vct": "mandate.payment.1",
            "transaction_id": sha256_base64url(&checkout_jwt),
            "payee": {"id": "m-1", "name": "Store"},
            "payment_amount": {"amount": 2799, "currency": "USD"},
            "payment_instrument": {"id": "pi-1", "type": "credit"},
        });
        let mandate_presentation = present(&mandate_claims, &user.encoding_key);

        let err = verify_payment_mandate(
            &mandate_presentation,
            &substituted,
            &user.jwk,
            &merchant.jwk,
            NOW,
            LEEWAY,
        )
        .unwrap_err();

        assert!(matches!(err, VerifyError::TransactionIdMismatch));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn rejects_the_wrong_mandate_type() {
        let user = generate_es256_keypair();
        let merchant = generate_es256_keypair();
        let checkout_jwt = sign(&json!({"cart": "whatever"}), &merchant.encoding_key);

        let mandate_claims = json!({
            "vct": "mandate.checkout.1",
            "transaction_id": sha256_base64url(&checkout_jwt),
            "payee": {"id": "m-1", "name": "Store"},
            "payment_amount": {"amount": 2799, "currency": "USD"},
            "payment_instrument": {"id": "pi-1", "type": "credit"},
        });
        let mandate_presentation = present(&mandate_claims, &user.encoding_key);

        let err = verify_payment_mandate(
            &mandate_presentation,
            &checkout_jwt,
            &user.jwk,
            &merchant.jwk,
            NOW,
            LEEWAY,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            VerifyError::WrongMandateType(MandateType::CheckoutV1)
        ));
    }
}
