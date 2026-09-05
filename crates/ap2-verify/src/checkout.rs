use ap2_core::{MandateType, UnverifiedCheckoutMandate};
use ap2_credentials::{
    sha256_base64url, verify_compact_jws, verify_sd_jwt, Jwk, ALLOWED_ALGORITHMS,
};
use serde_json::Value;

use crate::delegate::resolve_delegate_items;
use crate::error::VerifyError;

/// Unwraps `delegate_payload: [{...}]` if present, else treats claims as
/// flat (schema-literal shape).
fn unwrap_delegate_payload(
    claims: serde_json::Map<String, Value>,
) -> Result<serde_json::Map<String, Value>, VerifyError> {
    let mut items = resolve_delegate_items(&claims)?;
    match items.len() {
        0 => Ok(claims),
        1 => Ok(items.pop().unwrap()),
        _ => Err(VerifyError::InvalidDelegatePayload),
    }
}

/// A Checkout Mandate whose Issuer signature, hash binding to a Checkout
/// JWT, and (if present) expiry/freshness have all been verified.
#[derive(Debug, Clone)]
pub struct VerifiedCheckoutMandate {
    pub checkout_hash: String,
    pub iat: Option<i64>,
    pub exp: Option<i64>,
    pub checkout_claims: serde_json::Value, // opaque: AP2 doesn't pin a schema for the inner Checkout payload
}

pub fn verify_checkout_mandate(
    mandate_presentation: &str,
    checkout_jwt: &str,
    user_key: &Jwk,
    merchant_key: &Jwk,
    now: i64,
    leeway_seconds: i64,
) -> Result<VerifiedCheckoutMandate, VerifyError> {
    let verified_mandate = verify_sd_jwt(mandate_presentation, user_key)?;
    let claims = unwrap_delegate_payload(verified_mandate.claims)?;

    let mandate: UnverifiedCheckoutMandate = serde_json::from_value(Value::Object(claims))?;

    match &mandate.vct {
        MandateType::CheckoutV1 => {}
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

    let verified_checkout =
        verify_compact_jws::<Value>(checkout_jwt, merchant_key, ALLOWED_ALGORITHMS)?;

    let computed_hash = sha256_base64url(checkout_jwt);
    if computed_hash != mandate.checkout_hash {
        return Err(VerifyError::HashMismatch);
    }

    Ok(VerifiedCheckoutMandate {
        checkout_hash: mandate.checkout_hash,
        iat: mandate.iat,
        exp: mandate.exp,
        checkout_claims: verified_checkout.claims,
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

        let der = signing_key
            .to_pkcs8_der()
            .expect("PKCS8 DER encoding of a freshly generated key must succeed");
        let encoding_key = EncodingKey::from_ec_der(der.as_bytes());

        let point = signing_key.verifying_key().to_encoded_point(false);
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has x")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has y")),
        }))
        .unwrap();

        KeyPair { encoding_key, jwk }
    }

    fn sign(claims: &Value, key: &EncodingKey) -> String {
        encode(&Header::new(Algorithm::ES256), claims, key).unwrap()
    }

    /// A minimal, disclosure-free SD-JWT presentation of `claims`: just the
    /// Issuer-signed JWT with a trailing '~' and no disclosures/KB-JWT.
    fn present(claims: &Value, key: &EncodingKey) -> String {
        format!("{}~", sign(claims, key))
    }

    struct Fixture {
        user: KeyPair,
        merchant: KeyPair,
        checkout_jwt: String,
        mandate_presentation: String,
    }

    fn happy_path_fixture() -> Fixture {
        let user = generate_es256_keypair();
        let merchant = generate_es256_keypair();

        let checkout_claims = json!({
            "merchant": "Example Store",
            "amount": {"currency": "USD", "value": 2799},
        });
        let checkout_jwt = sign(&checkout_claims, &merchant.encoding_key);
        let checkout_hash = sha256_base64url(&checkout_jwt);

        let mandate_claims = json!({
            "vct": "mandate.checkout.1",
            "checkout_hash": checkout_hash,
            "iat": NOW - 10,
            "exp": NOW + 3600,
        });
        let mandate_presentation = present(&mandate_claims, &user.encoding_key);

        Fixture {
            user,
            merchant,
            checkout_jwt,
            mandate_presentation,
        }
    }

    #[test]
    fn verifies_a_well_formed_checkout_mandate() {
        let f = happy_path_fixture();

        let verified = verify_checkout_mandate(
            &f.mandate_presentation,
            &f.checkout_jwt,
            &f.user.jwk,
            &f.merchant.jwk,
            NOW,
            LEEWAY,
        )
        .expect("well-formed mandate must verify");

        assert_eq!(verified.iat, Some(NOW - 10));
        assert_eq!(verified.exp, Some(NOW + 3600));
        assert_eq!(verified.checkout_claims["merchant"], json!("Example Store"));
        assert_eq!(verified.checkout_hash, sha256_base64url(&f.checkout_jwt));
    }

    #[test]
    fn rejects_a_checkout_jwt_that_does_not_match_checkout_hash() {
        let f = happy_path_fixture();

        // A different, independently-valid Checkout JWT from the same
        // Merchant (e.g. a substituted lower price) -- its signature is
        // fine on its own, but it isn't the one this mandate was bound to.
        let substituted = sign(
            &json!({"amount": {"currency": "USD", "value": 100}}),
            &f.merchant.encoding_key,
        );

        let err = verify_checkout_mandate(
            &f.mandate_presentation,
            &substituted,
            &f.user.jwk,
            &f.merchant.jwk,
            NOW,
            LEEWAY,
        )
        .unwrap_err();

        assert!(matches!(err, VerifyError::HashMismatch));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn rejects_an_expired_mandate() {
        let user = generate_es256_keypair();
        let merchant = generate_es256_keypair();
        let checkout_jwt = sign(&json!({"amount": 100}), &merchant.encoding_key);
        let mandate_presentation = present(
            &json!({
                "vct": "mandate.checkout.1",
                "checkout_hash": sha256_base64url(&checkout_jwt),
                "exp": NOW - 3600,
            }),
            &user.encoding_key,
        );

        let err = verify_checkout_mandate(
            &mandate_presentation,
            &checkout_jwt,
            &user.jwk,
            &merchant.jwk,
            NOW,
            LEEWAY,
        )
        .unwrap_err();

        assert!(matches!(err, VerifyError::Expired { .. }));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn rejects_a_mandate_not_yet_valid() {
        let user = generate_es256_keypair();
        let merchant = generate_es256_keypair();
        let checkout_jwt = sign(&json!({"amount": 100}), &merchant.encoding_key);
        let mandate_presentation = present(
            &json!({
                "vct": "mandate.checkout.1",
                "checkout_hash": sha256_base64url(&checkout_jwt),
                "iat": NOW + 3600,
            }),
            &user.encoding_key,
        );

        let err = verify_checkout_mandate(
            &mandate_presentation,
            &checkout_jwt,
            &user.jwk,
            &merchant.jwk,
            NOW,
            LEEWAY,
        )
        .unwrap_err();

        assert!(matches!(err, VerifyError::NotYetValid { .. }));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn rejects_the_wrong_mandate_type() {
        let user = generate_es256_keypair();
        let merchant = generate_es256_keypair();
        let checkout_jwt = sign(&json!({"amount": 100}), &merchant.encoding_key);
        let mandate_presentation = present(
            &json!({
                "vct": "mandate.payment.1",
                "checkout_hash": sha256_base64url(&checkout_jwt),
            }),
            &user.encoding_key,
        );

        let err = verify_checkout_mandate(
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
            VerifyError::WrongMandateType(MandateType::PaymentV1)
        ));
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn rejects_an_unrecognized_mandate_type() {
        let user = generate_es256_keypair();
        let merchant = generate_es256_keypair();
        let checkout_jwt = sign(&json!({"amount": 100}), &merchant.encoding_key);
        let mandate_presentation = present(
            &json!({
                "vct": "mandate.checkout.2",
                "checkout_hash": sha256_base64url(&checkout_jwt),
            }),
            &user.encoding_key,
        );

        let err = verify_checkout_mandate(
            &mandate_presentation,
            &checkout_jwt,
            &user.jwk,
            &merchant.jwk,
            NOW,
            LEEWAY,
        )
        .unwrap_err();

        assert!(
            matches!(err, VerifyError::UnsupportedMandateType(ref v) if v == "mandate.checkout.2")
        );
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn rejects_a_checkout_jwt_not_signed_by_the_claimed_merchant() {
        let f = happy_path_fixture();
        let impostor = generate_es256_keypair();

        // Same content, hash would even match if we recomputed it -- but
        // it's signed by the wrong key, which is what actually matters.
        let forged_checkout = sign(
            &json!({"merchant": "Example Store", "amount": {"currency": "USD", "value": 2799}}),
            &impostor.encoding_key,
        );
        let forged_hash = sha256_base64url(&forged_checkout);
        let mandate_presentation = present(
            &json!({
                "vct": "mandate.checkout.1",
                "checkout_hash": forged_hash,
            }),
            &f.user.encoding_key,
        );

        let err = verify_checkout_mandate(
            &mandate_presentation,
            &forged_checkout,
            &f.user.jwk,
            &f.merchant.jwk,
            NOW,
            LEEWAY,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            VerifyError::Credential(ap2_credentials::CredentialError::SignatureInvalid(_))
        ));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn rejects_a_mandate_not_signed_by_the_claimed_user() {
        let f = happy_path_fixture();
        let impostor = generate_es256_keypair();

        let forged_mandate_presentation = present(
            &json!({
                "vct": "mandate.checkout.1",
                "checkout_hash": sha256_base64url(&f.checkout_jwt),
            }),
            &impostor.encoding_key,
        );

        let err = verify_checkout_mandate(
            &forged_mandate_presentation,
            &f.checkout_jwt,
            &f.user.jwk,
            &f.merchant.jwk,
            NOW,
            LEEWAY,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            VerifyError::Credential(ap2_credentials::CredentialError::SignatureInvalid(_))
        ));
        assert_eq!(err.exit_code(), 1);
    }

    // Real AP2 issuers (the upstream Python reference SDK) wrap mandate
    // fields as delegate_payload: [{...}], not flat at the top level.
    #[test]
    fn verifies_a_mandate_wrapped_in_delegate_payload() {
        let f = happy_path_fixture();

        let wrapped_presentation = present(
            &json!({
                "delegate_payload": [{
                    "vct": "mandate.checkout.1",
                    "checkout_hash": sha256_base64url(&f.checkout_jwt),
                }],
            }),
            &f.user.encoding_key,
        );

        let verified = verify_checkout_mandate(
            &wrapped_presentation,
            &f.checkout_jwt,
            &f.user.jwk,
            &f.merchant.jwk,
            NOW,
            LEEWAY,
        )
        .expect("delegate_payload-wrapped mandate must verify");

        assert_eq!(verified.checkout_hash, sha256_base64url(&f.checkout_jwt));
    }

    #[test]
    fn rejects_a_malformed_delegate_payload() {
        let f = happy_path_fixture();

        // Two items instead of exactly one.
        let malformed_presentation = present(
            &json!({
                "delegate_payload": [
                    {"vct": "mandate.checkout.1", "checkout_hash": sha256_base64url(&f.checkout_jwt)},
                    {"vct": "mandate.checkout.1", "checkout_hash": sha256_base64url(&f.checkout_jwt)},
                ],
            }),
            &f.user.encoding_key,
        );

        let err = verify_checkout_mandate(
            &malformed_presentation,
            &f.checkout_jwt,
            &f.user.jwk,
            &f.merchant.jwk,
            NOW,
            LEEWAY,
        )
        .unwrap_err();

        assert!(matches!(err, VerifyError::InvalidDelegatePayload));
        assert_eq!(err.exit_code(), 2);
    }
}
