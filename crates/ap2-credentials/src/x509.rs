use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use der::{Decode, Encode};
use ecdsa::signature::Verifier;
use jsonwebtoken::jwk::Jwk;
use p256::ecdsa::{Signature, VerifyingKey};
pub use x509_cert::Certificate;

use crate::error::CredentialError;

/// Verifies an `x5c` certificate chain (RFC 7515 SS4.1.6): each cert must be
/// signed by the next, the last must chain to one of `trusted_roots`, and
/// every cert must be within its validity window at `now`. Returns the
/// leaf's public key as a JWK.
///
/// Only ECDSA P-256 certs are supported, matching the ES256-only policy
/// enforced everywhere else in this crate. Does not check revocation, key
/// usage, or CA `basicConstraints` -- narrower than a full X.509 path
/// validator, but wider than the reference AP2 implementation's own
/// `X5cOrKidPublicKeyProvider`, which skips expiry too.
pub fn verify_x5c_chain(
    der_certs: &[Vec<u8>],
    trusted_roots: &[Certificate],
    now: i64,
) -> Result<Jwk, CredentialError> {
    if der_certs.is_empty() {
        return Err(CredentialError::MalformedJws("empty x5c chain".into()));
    }
    if trusted_roots.is_empty() {
        return Err(CredentialError::UntrustedCertificateRoot);
    }

    let certs: Vec<Certificate> = der_certs
        .iter()
        .map(|der| {
            Certificate::from_der(der)
                .map_err(|e| CredentialError::MalformedJws(format!("invalid x5c cert: {e}")))
        })
        .collect::<Result<_, _>>()?;

    for cert in &certs {
        check_validity(cert, now)?;
    }
    for pair in certs.windows(2) {
        verify_signed_by(&pair[0], &pair[1])?;
    }

    let last = certs.last().expect("checked non-empty above");
    let trusted = trusted_roots
        .iter()
        .any(|root| verify_signed_by(last, root).is_ok());
    if !trusted {
        return Err(CredentialError::UntrustedCertificateRoot);
    }

    extract_jwk(&certs[0])
}

fn check_validity(cert: &Certificate, now: i64) -> Result<(), CredentialError> {
    let validity = cert.tbs_certificate().validity();
    let not_before = validity.not_before.to_unix_duration().as_secs() as i64;
    let not_after = validity.not_after.to_unix_duration().as_secs() as i64;
    if now < not_before || now > not_after {
        return Err(CredentialError::CertificateExpired {
            not_before,
            not_after,
            now,
        });
    }
    Ok(())
}

fn verify_signed_by(subject: &Certificate, issuer: &Certificate) -> Result<(), CredentialError> {
    let issuer_key = extract_verifying_key(issuer)?;
    let tbs_der = subject
        .tbs_certificate()
        .to_der()
        .map_err(|e| CredentialError::MalformedJws(format!("cert re-encode failed: {e}")))?;
    let sig_bytes = subject
        .signature()
        .as_bytes()
        .ok_or_else(|| CredentialError::MalformedJws("cert signature not byte-aligned".into()))?;
    let sig = Signature::from_der(sig_bytes)
        .map_err(|e| CredentialError::MalformedJws(format!("bad cert signature: {e}")))?;
    issuer_key
        .verify(&tbs_der, &sig)
        .map_err(|_| CredentialError::CertificateChainInvalid)
}

fn extract_verifying_key(cert: &Certificate) -> Result<VerifyingKey, CredentialError> {
    let point = spki_point_bytes(cert)?;
    VerifyingKey::from_sec1_bytes(point).map_err(|e| {
        CredentialError::MalformedJws(format!("cert key is not a valid P-256 point: {e}"))
    })
}

fn spki_point_bytes(cert: &Certificate) -> Result<&[u8], CredentialError> {
    cert.tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| CredentialError::MalformedJws("cert public key not byte-aligned".into()))
}

fn extract_jwk(cert: &Certificate) -> Result<Jwk, CredentialError> {
    let point = spki_point_bytes(cert)?;
    if point.len() != 65 || point[0] != 0x04 {
        return Err(CredentialError::MalformedJws(
            "expected an uncompressed P-256 point".into(),
        ));
    }
    let x = URL_SAFE_NO_PAD.encode(&point[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&point[33..65]);
    serde_json::from_value(serde_json::json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}))
        .map_err(|e| CredentialError::MalformedJws(format!("failed to build JWK: {e}")))
}
