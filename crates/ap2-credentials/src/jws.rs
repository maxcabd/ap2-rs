use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, Validation};
use serde::de::DeserializeOwned;

use crate::error::CredentialError;
/// Per ADR 0001, AP2 requires a randomized sig scheme
pub const ALLOWED_ALGORITHMS: &[Algorithm] = &[Algorithm::ES256];

/// A compact JWT/JWS whose signature has been verified against a known key,
/// using an algorithm drawn from an explicit allow-list rather than from
/// the token's own header.
#[derive(Debug, Clone)]
pub struct VerifiedJws<T> {
    pub header: Header,
    pub claims: T,
}

/// Decodes just the header of a compact JWT, or of the first (issuer-signed)
/// segment of an SD-JWT presentation, without verifying anything. Used to
/// resolve which key to verify with (e.g. via `kid`/`x5c`) before any
/// signature check happens.
pub fn peek_header(token_or_presentation: &str) -> Result<Header, CredentialError> {
    let segment = token_or_presentation
        .split('~')
        .next()
        .unwrap_or(token_or_presentation);
    decode_header(segment).map_err(|e| CredentialError::MalformedJws(e.to_string()))
}

/// Verifies a compact JWS (`header.payload.signature`) against `key`
pub fn verify_compact_jws<T>(
    compact: &str,
    key: &Jwk,
    allowed: &[Algorithm],
) -> Result<VerifiedJws<T>, CredentialError>
where
    T: DeserializeOwned,
{
    let header =
        decode_header(compact).map_err(|e| CredentialError::MalformedJws(e.to_string()))?;

    if !allowed.contains(&header.alg) {
        return Err(CredentialError::DisallowedAlgorithm(header.alg));
    }

    let decoding_key = DecodingKey::from_jwk(key)
        .map_err(|e| CredentialError::MalformedJws(format!("invalid JWK: {e}")))?;

    let mut validation = Validation::new(header.alg);
    validation.algorithms = allowed.to_vec();
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    // jsonwebtoken enforces its own `aud` policy by default: if the claims
    // carry an `aud` and `validation.aud` isn't set to match, it rejects the
    // token outright, before callers like `verify_key_binding` ever get to
    // apply their own expected-audience check. That's exactly the kind of
    // policy decision this crate defers to its callers.
    validation.validate_aud = false;

    let data = decode::<T>(compact, &decoding_key, &validation)?;

    Ok(VerifiedJws {
        header: data.header,
        claims: data.claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    // RFC 9901 (draft-ietf-oauth-selective-disclosure-jwt-07) Appendix A.5
    // the Issuer public key for the worked examples in Appendix A.3
    fn spec_issuer_key() -> Jwk {
        serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
            "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
        }))
        .unwrap()
    }

    #[derive(Debug, Deserialize)]
    struct PidClaims {
        iss: String,
        vct: String,
    }

    #[test]
    fn verifies_the_issuer_signed_segment_of_the_spec_example() {
        // Appendix A.3's Issuer-signed JWT (the segment before the first
        // '~' of the full SD-JWT).
        let compact = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogInZjK3NkLWp3dCJ9.eyJfc2QiOiBbIjBuOXl6RlNXdktfQlVIaWFNaG0xMmdockN0VmFockdKNl8ta1pQLXlTcTQiLCAiQ2gtREJjTDNrYjRWYkhJd3Rrbm5aZE5VSHRoRXE5TVpqb0ZkZzZpZGlobyIsICJEVzdnRlZaU3V5cjQyWVNZeDhwOHJWS0VrdEp6SjN1RkltZW5tSkJJbWRzIiwgIkkwMGZjRlVvRFhDdWNwNXl5MnVqcVBzc0RWR2FXTmlVbGlOel9hd0QwZ2MiLCAiWDlNYVBhRldtUVlwZkhFZHl0UmRhY2xuWW9FcnU4RXp0QkVVUXVXT2U0NCIsICJkOHFrZlBkb2UyUFlFOTNkNU1fZ0JMMWdabHBGUktDYzBkMWxhb2RfX3MwIiwgImxJM0wwaHNlQ1JXbVVQZzgyVkNVTl9hMTdzTUxfNjRRZ0E0SkZUWURGREUiLCAicHVNcEdMb0FHUmJjc0FnNTBVWjBoaFFMS0NMNnF6eFNLNDMwNGtCbjNfSSIsICJ6VTQ1MmxrR2JFS2g4WnVIXzhLeDNDVXZuMUY0eTFnWkxxbERUZ1hfOFBrIl0sICJpc3MiOiAiaHR0cHM6Ly9waWQtcHJvdmlkZXIubWVtYmVyc3RhdGUuZXhhbXBsZS5ldSIsICJpYXQiOiAxNTQxNDkzNzI0LCAiZXhwIjogMTg4MzAwMDAwMCwgInZjdCI6ICJQZXJzb25JZGVudGlmaWNhdGlvbkRhdGEiLCAiX3NkX2FsZyI6ICJzaGEtMjU2IiwgImNuZiI6IHsiandrIjogeyJrdHkiOiAiRUMiLCAiY3J2IjogIlAtMjU2IiwgIngiOiAiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsICJ5IjogIlp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEifX19.VStKGOA5TdLsrjahM4dRfDrbsy7BmrUNGw3jaBuxZnHYvmS2EnQ-ib7zSCUVBGGbcyORDFCMd_F6gr8CM9N3WQ";

        let verified =
            verify_compact_jws::<PidClaims>(compact, &spec_issuer_key(), ALLOWED_ALGORITHMS)
                .expect("spec vector must verify");

        assert_eq!(
            verified.claims.iss,
            "https://pid-provider.memberstate.example.eu"
        );
        assert_eq!(verified.claims.vct, "PersonIdentificationData");
        assert_eq!(verified.header.alg, Algorithm::ES256);
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let mut compact = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogInZjK3NkLWp3dCJ9.eyJfc2QiOiBbXX0.VStKGOA5TdLsrjahM4dRfDrbsy7BmrUNGw3jaBuxZnHYvmS2EnQ-ib7zSCUVBGGbcyORDFCMd_F6gr8CM9N3WQ".to_string();
        compact.push('x');

        let err = verify_compact_jws::<serde_json::Value>(
            &compact,
            &spec_issuer_key(),
            ALLOWED_ALGORITHMS,
        )
        .unwrap_err();

        // Header/payload still parse fine; only the signature itself is
        // wrong, so this fails inside jsonwebtoken's crypto check, not our
        // own structural checks.
        assert!(matches!(err, CredentialError::SignatureInvalid(_)));
    }

    #[test]
    fn rejects_a_disallowed_algorithm() {
        // A syntactically valid, well-signed HS256 token. It must be
        // rejected purely for using an algorithm outside our allow-list --
        // not because it fails to parse (that would prove nothing about
        // the allow-list check itself).
        let compact = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::HS256),
            &json!({"sub": "mallory"}),
            &jsonwebtoken::EncodingKey::from_secret(b"attacker-controlled-secret"),
        )
        .unwrap();

        let err = verify_compact_jws::<serde_json::Value>(
            &compact,
            &spec_issuer_key(),
            ALLOWED_ALGORITHMS,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            CredentialError::DisallowedAlgorithm(Algorithm::HS256)
        ));
    }
}
