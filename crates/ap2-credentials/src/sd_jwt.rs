use jsonwebtoken::jwk::Jwk;
use sd_jwt_payload::{
    Hasher, JsonObject, KeyBindingJwt, KeyBindingJwtClaims, SdJwt, Sha256Hasher, KB_JWT_HEADER_TYP,
    SHA_ALG_NAME,
};

use crate::error::CredentialError;
use crate::jws::{verify_compact_jws, ALLOWED_ALGORITHMS};

/// SHA-256 + base64url digest of `input`.
///
/// Exposed for AP2 hash-binding checks outside the SD-JWT disclosure
/// mechanism itself (e.g. a Checkout Mandate's `checkout_hash` binding to
/// its `checkout_jwt`), which use the same digest SD-JWT disclosures do.
/// Centralizing it here keeps `sd-jwt-payload` an implementation detail of
/// this crate rather than a dependency callers reach past us for.
pub fn sha256_base64url(input: &str) -> String {
    Sha256Hasher::new().encoded_digest(input)
}

#[derive(Debug, Clone)]
pub struct VerifiedSdJwt {
    pub header: JsonObject,
    pub claims: JsonObject,
    pub key_binding_jwt: Option<KeyBindingJwt>,
}

pub fn verify_sd_jwt(
    presentation: &str,
    issuer_key: &Jwk,
) -> Result<VerifiedSdJwt, CredentialError> {
    let issuer_jwt_compact = presentation
        .split('~')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CredentialError::MalformedSdJwt("empty presentation".into()))?;

    verify_compact_jws::<serde_json::Value>(issuer_jwt_compact, issuer_key, ALLOWED_ALGORITHMS)?;

    let sd_jwt =
        SdJwt::parse(presentation).map_err(|e| CredentialError::MalformedSdJwt(e.to_string()))?;

    let sd_alg = sd_jwt.claims()._sd_alg.as_deref().unwrap_or(SHA_ALG_NAME);
    if sd_alg != SHA_ALG_NAME {
        return Err(CredentialError::Disclosure(format!(
            "unsupported _sd_alg {sd_alg:?}: only {SHA_ALG_NAME:?} is implemented"
        )));
    }

    let header = sd_jwt.headers().clone();
    let key_binding_jwt = sd_jwt.key_binding_jwt().cloned();

    let claims = sd_jwt
        .into_disclosed_object(&Sha256Hasher::new())
        .map_err(|e| CredentialError::Disclosure(e.to_string()))?;

    Ok(VerifiedSdJwt {
        header,
        claims,
        key_binding_jwt,
    })
}

/// The result of verifying a Key Binding JWT
#[derive(Debug, Clone)]
pub struct VerifiedKeyBinding {
    pub claims: KeyBindingJwtClaims,
}

pub fn verify_key_binding(
    presentation: &str,
    key_binding_jwt: &KeyBindingJwt,
    holder_key: &Jwk,
    expected_aud: &str,
    expected_nonce: &str,
) -> Result<VerifiedKeyBinding, CredentialError> {
    let kb_compact = key_binding_jwt.to_string();
    let verified =
        verify_compact_jws::<KeyBindingJwtClaims>(&kb_compact, holder_key, ALLOWED_ALGORITHMS)?;

    if verified.header.typ.as_deref() != Some(KB_JWT_HEADER_TYP) {
        return Err(CredentialError::KeyBinding(format!(
            "typ must be {KB_JWT_HEADER_TYP:?}"
        )));
    }
    if verified.claims.aud != expected_aud {
        return Err(CredentialError::KeyBinding("aud mismatch".into()));
    }
    if verified.claims.nonce != expected_nonce {
        return Err(CredentialError::KeyBinding("nonce mismatch".into()));
    }

    // RFC 9901 5.3.1: sd_hash covers the US-ASCII bytes preceding the
    // KB-JWT -- the Issuer-signed JWT, then each selected Disclosure, each
    // followed by '~'. That's everything up to (and including) the last
    // '~' in `presentation`.
    let (signed_prefix, _kb_segment) = presentation
        .rsplit_once('~')
        .ok_or_else(|| CredentialError::MalformedSdJwt("no KB-JWT separator".into()))?;
    let expected_sd_hash = Sha256Hasher::new().encoded_digest(&format!("{signed_prefix}~"));

    if verified.claims.sd_hash != expected_sd_hash {
        return Err(CredentialError::KeyBinding(
            "sd_hash does not match presentation".into(),
        ));
    }

    Ok(VerifiedKeyBinding {
        claims: verified.claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec_issuer_key() -> Jwk {
        serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
            "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
        }))
        .unwrap()
    }

    // RFC 9901 Appendix A.3: a presentation disclosing only `is_over_18`
    // and `nationalities`, with a Key Binding JWT signed by the holder key
    // published in the Issuer-signed JWT's `cnf` claim.
    const PRESENTATION_WITH_KB_JWT: &str = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogInZjK3NkLWp3dCJ9.eyJfc2QiOiBbIjBuOXl6RlNXdktfQlVIaWFNaG0xMmdockN0VmFockdKNl8ta1pQLXlTcTQiLCAiQ2gtREJjTDNrYjRWYkhJd3Rrbm5aZE5VSHRoRXE5TVpqb0ZkZzZpZGlobyIsICJEVzdnRlZaU3V5cjQyWVNZeDhwOHJWS0VrdEp6SjN1RkltZW5tSkJJbWRzIiwgIkkwMGZjRlVvRFhDdWNwNXl5MnVqcVBzc0RWR2FXTmlVbGlOel9hd0QwZ2MiLCAiWDlNYVBhRldtUVlwZkhFZHl0UmRhY2xuWW9FcnU4RXp0QkVVUXVXT2U0NCIsICJkOHFrZlBkb2UyUFlFOTNkNU1fZ0JMMWdabHBGUktDYzBkMWxhb2RfX3MwIiwgImxJM0wwaHNlQ1JXbVVQZzgyVkNVTl9hMTdzTUxfNjRRZ0E0SkZUWURGREUiLCAicHVNcEdMb0FHUmJjc0FnNTBVWjBoaFFMS0NMNnF6eFNLNDMwNGtCbjNfSSIsICJ6VTQ1MmxrR2JFS2g4WnVIXzhLeDNDVXZuMUY0eTFnWkxxbERUZ1hfOFBrIl0sICJpc3MiOiAiaHR0cHM6Ly9waWQtcHJvdmlkZXIubWVtYmVyc3RhdGUuZXhhbXBsZS5ldSIsICJpYXQiOiAxNTQxNDkzNzI0LCAiZXhwIjogMTg4MzAwMDAwMCwgInZjdCI6ICJQZXJzb25JZGVudGlmaWNhdGlvbkRhdGEiLCAiX3NkX2FsZyI6ICJzaGEtMjU2IiwgImNuZiI6IHsiandrIjogeyJrdHkiOiAiRUMiLCAiY3J2IjogIlAtMjU2IiwgIngiOiAiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsICJ5IjogIlp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEifX19.VStKGOA5TdLsrjahM4dRfDrbsy7BmrUNGw3jaBuxZnHYvmS2EnQ-ib7zSCUVBGGbcyORDFCMd_F6gr8CM9N3WQ~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImlzX292ZXJfMTgiLCB0cnVlXQ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm5hdGlvbmFsaXRpZXMiLCBbeyIuLi4iOiAiSnVMMzJRWER6aXpsLUw2Q0xyZnhmanBac1gzTzZ2c2ZwQ1ZkMWprd0pZZyJ9XV0~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgIkRFIl0~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3MDIzMTYwMTUsICJzZF9oYXNoIjogIk05cENKQ2t3dUZpbnZKQl9ZU280VVo3akdESUhmYWhwMEdzZ0pTZ2ZGUmMifQ.lg_PZwjyl7rPtR1sJXDx2e828npGOdQVQHRqA9Np7zJ4IfSf5foLpCsqAn40Z139sCOvitwV6jSSQKvd91nrRw";

    #[test]
    fn resolves_disclosures_from_the_spec_example() {
        let verified = verify_sd_jwt(PRESENTATION_WITH_KB_JWT, &spec_issuer_key())
            .expect("spec presentation must verify");

        assert_eq!(verified.claims["is_over_18"], json!(true));
        assert_eq!(verified.claims["nationalities"], json!(["DE"]));
        // Concealed in this presentation -- not just hidden, genuinely absent.
        assert!(!verified.claims.contains_key("first_name"));
        assert!(!verified.claims.contains_key("family_name"));
        assert!(verified.key_binding_jwt.is_some());
    }

    #[test]
    fn verifies_the_attached_key_binding_jwt() {
        let verified = verify_sd_jwt(PRESENTATION_WITH_KB_JWT, &spec_issuer_key()).unwrap();
        let holder_key: Jwk =
            serde_json::from_value(verified.claims["cnf"]["jwk"].clone()).unwrap();

        let kb = verify_key_binding(
            PRESENTATION_WITH_KB_JWT,
            verified.key_binding_jwt.as_ref().unwrap(),
            &holder_key,
            "https://verifier.example.org",
            "1234567890",
        )
        .expect("spec KB-JWT must verify");

        assert_eq!(
            kb.claims.sd_hash,
            "M9pCJCkwuFinvJB_YSo4UZ7jGDIHfahp0GsgJSgfFRc"
        );
    }

    #[test]
    fn rejects_key_binding_with_wrong_nonce() {
        let verified = verify_sd_jwt(PRESENTATION_WITH_KB_JWT, &spec_issuer_key()).unwrap();
        let holder_key: Jwk =
            serde_json::from_value(verified.claims["cnf"]["jwk"].clone()).unwrap();

        let err = verify_key_binding(
            PRESENTATION_WITH_KB_JWT,
            verified.key_binding_jwt.as_ref().unwrap(),
            &holder_key,
            "https://verifier.example.org",
            "wrong-nonce",
        )
        .unwrap_err();

        assert!(matches!(err, CredentialError::KeyBinding(_)));
    }
}
