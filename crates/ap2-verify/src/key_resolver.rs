use ap2_credentials::{verify_x5c_chain, Certificate, Header, Jwk};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::VerifyError;

/// Resolves the verifying key for a chain's root hop from its header.
/// Implemented for `Jwk` itself (always returns the same fixed key,
/// ignoring the header) so existing callers passing a plain `&Jwk` keep
/// working unchanged.
pub trait RootKeyResolver {
    fn resolve_root_key(&self, header: &Header) -> Result<Jwk, VerifyError>;
}

impl RootKeyResolver for Jwk {
    fn resolve_root_key(&self, _header: &Header) -> Result<Jwk, VerifyError> {
        Ok(self.clone())
    }
}

/// Resolves a root key from the header's `x5c` (certificate chain,
/// validated to a trusted root) or `kid` (looked up via a caller-supplied
/// callback), mirroring AP2's own `X5cOrKidPublicKeyProvider`.
pub struct X5cOrKidResolver<F> {
    pub kid_lookup: F,
    pub trusted_roots: Vec<Certificate>,
    /// Clock for certificate expiry checks (x5c only).
    pub now: i64,
}

impl<F> RootKeyResolver for X5cOrKidResolver<F>
where
    F: Fn(&str) -> Option<Jwk>,
{
    fn resolve_root_key(&self, header: &Header) -> Result<Jwk, VerifyError> {
        if let Some(x5c) = &header.x5c {
            // RFC 7515 SS4.1.6: x5c entries are plain base64 (padded), not
            // base64url, unlike everything else in a JOSE header.
            let der_certs = x5c
                .iter()
                .map(|c| {
                    base64::engine::general_purpose::STANDARD
                        .decode(c)
                        .or_else(|_| URL_SAFE_NO_PAD.decode(c))
                        .map_err(|e| {
                            VerifyError::UnresolvableRootKey(format!("bad x5c entry: {e}"))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(verify_x5c_chain(&der_certs, &self.trusted_roots, self.now)?);
        }
        if let Some(kid) = &header.kid {
            return (self.kid_lookup)(kid).ok_or_else(|| {
                VerifyError::UnresolvableRootKey(format!("no key for kid {kid:?}"))
            });
        }
        Err(VerifyError::UnresolvableRootKey(
            "header has neither x5c nor kid".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::verify_chain;
    use base64::engine::general_purpose::STANDARD;
    use der::Decode;
    use jsonwebtoken::{encode, Algorithm, EncodingKey};
    use serde_json::json;

    // A real EC P-256 cert chain (openssl-generated): `LEAF_CERT` signed by
    // `ROOT_CERT` (a self-signed CA). `LEAF_KEY` is the leaf's PKCS8
    // private key. Validity: 2026-09-05 .. 2036-09-02.
    const ROOT_CERT: &str = "MIIBnDCCAUGgAwIBAgIUDqMnuAtd5kGOBD8dNOVyqkBBR0owCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQYXAyLXJzIFRlc3QgUm9vdDAeFw0yNjA5MDUwNjM5MTdaFw0zNjA5MDIwNjM5MTdaMBsxGTAXBgNVBAMMEGFwMi1ycyBUZXN0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQW1E1Vjki3gWxungZ6b8TVR/dsDyyaoukMyqjjeSlLsM82Fx9q5mG4HlB/kqZoBpW8Xujag8XM4o6ZTKlUZ0Cbo2MwYTAdBgNVHQ4EFgQU7R2lWP7yXtatyxtTq0w19K4iXMAwHwYDVR0jBBgwFoAU7R2lWP7yXtatyxtTq0w19K4iXMAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDSQAwRgIhAOnk9DA+5GMcr7QdckoPbci8gM6CbFh8glRor99kof/eAiEA35EYLXK0mvH27sXdp27YshcYkUKfA4ucFbNNCzJb/w4=";
    const LEAF_CERT: &str = "MIIBMDCB1wIUA9o4ECeIXbTNs+qhkHHPQ4agrrAwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQYXAyLXJzIFRlc3QgUm9vdDAeFw0yNjA5MDUwNjM5MThaFw0zNjA5MDIwNjM5MThaMBsxGTAXBgNVBAMMEGFwMi1ycyBUZXN0IExlYWYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR7HQZ1ivN7si0XS7gqDgrWjZ14APe4JUJOKg3gYcpXL8M1nHz6PArfiasxqqogbnREAK4pxsBCCs7C9GPYoUh4MAoGCCqGSM49BAMCA0gAMEUCIQDcL5vZWAy4AKpyxQJRJcLE2dllvDvzly5BWx/Qz9aqGAIgMTpVP9craEKHgBrQRUNzKScAO8O5XLBfVteOZgvmzOA=";
    const UNTRUSTED_ROOT_CERT: &str = "MIIBlDCCATugAwIBAgIUZ086Az11HYFaWRGukG4oli/Cje8wCgYIKoZIzj0EAwIwIDEeMBwGA1UEAwwVYXAyLXJzIFVudHJ1c3RlZCBSb290MB4XDTI2MDkwNTA2MzkxOFoXDTM2MDkwMjA2MzkxOFowIDEeMBwGA1UEAwwVYXAyLXJzIFVudHJ1c3RlZCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE56B5uCH5O3W84CJ19wpGk681YkLjswceFmKeFAj1KjKzmrBNN5PaS6I2J+8RTxP2ihZsGNFK9/t9qQSMPjRJq6NTMFEwHQYDVR0OBBYEFDa7GYr5jRcwxMnN43o8HYyWYOLtMB8GA1UdIwQYMBaAFDa7GYr5jRcwxMnN43o8HYyWYOLtMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgB5x4bNQW3Hh0sQ8MPRq+3s+vkvBift4s8qMVreIiV3MCIDyz20i3kddm05jtIO6eo8cEEZP6fKEJ7n1obHusrZNh";
    const LEAF_KEY_PKCS8: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgXmlb6snBdGmNmuhLRyhYu6tiOTow3LtksrguxaiKAaOhRANCAAR7HQZ1ivN7si0XS7gqDgrWjZ14APe4JUJOKg3gYcpXL8M1nHz6PArfiasxqqogbnREAK4pxsBCCs7C9GPYoUh4";

    const VALID_NOW: i64 = 1_800_000_000; // within 2026-09-05 .. 2036-09-02
    const EXPIRED_NOW: i64 = 1_700_000_000; // before 2026-09-05

    fn der(b64: &str) -> Vec<u8> {
        STANDARD.decode(b64).unwrap()
    }

    fn root_cert() -> Certificate {
        Certificate::from_der(&der(ROOT_CERT)).unwrap()
    }

    fn untrusted_root_cert() -> Certificate {
        Certificate::from_der(&der(UNTRUSTED_ROOT_CERT)).unwrap()
    }

    fn leaf_encoding_key() -> EncodingKey {
        EncodingKey::from_ec_der(&der(LEAF_KEY_PKCS8))
    }

    /// A single-hop chain (no delegation needed) signed by the leaf key,
    /// with `x5c` naming the leaf + root cert chain.
    fn chain_with_x5c() -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
        header.x5c = Some(vec![LEAF_CERT.to_string(), ROOT_CERT.to_string()]);
        let jwt = encode(&header, &json!({"vct": "test.1"}), &leaf_encoding_key()).unwrap();
        format!("{jwt}~")
    }

    #[test]
    fn verifies_a_chain_via_x5c_to_a_trusted_root() {
        let resolver = X5cOrKidResolver {
            kid_lookup: |_: &str| None,
            trusted_roots: vec![root_cert()],
            now: VALID_NOW,
        };

        let payloads = verify_chain(
            &chain_with_x5c(),
            &resolver,
            VALID_NOW,
            60,
            "unused",
            "unused",
        )
        .expect("chain with a valid x5c trust path must verify");

        assert_eq!(payloads[0]["vct"], json!("test.1"));
    }

    #[test]
    fn rejects_x5c_chain_not_leading_to_a_trusted_root() {
        let resolver = X5cOrKidResolver {
            kid_lookup: |_: &str| None,
            trusted_roots: vec![untrusted_root_cert()],
            now: VALID_NOW,
        };

        let err = verify_chain(
            &chain_with_x5c(),
            &resolver,
            VALID_NOW,
            60,
            "unused",
            "unused",
        )
        .unwrap_err();

        assert!(matches!(
            err,
            VerifyError::Credential(ap2_credentials::CredentialError::UntrustedCertificateRoot)
        ));
    }

    #[test]
    fn rejects_an_expired_x5c_certificate() {
        let resolver = X5cOrKidResolver {
            kid_lookup: |_: &str| None,
            trusted_roots: vec![root_cert()],
            now: EXPIRED_NOW,
        };

        let err = verify_chain(
            &chain_with_x5c(),
            &resolver,
            VALID_NOW,
            60,
            "unused",
            "unused",
        )
        .unwrap_err();

        assert!(matches!(
            err,
            VerifyError::Credential(ap2_credentials::CredentialError::CertificateExpired { .. })
        ));
    }

    #[test]
    fn verifies_a_chain_via_kid_lookup() {
        let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
        header.kid = Some("test-key-1".to_string());
        let jwt = encode(&header, &json!({"vct": "test.1"}), &leaf_encoding_key()).unwrap();
        let chain = format!("{jwt}~");

        let leaf_jwk: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "ex0GdYrze7ItF0u4Kg4K1o2deAD3uCVCTioN4GHKVy8",
            "y": "wzWcfPo8Ct-JqzGqqiBudEQArinGwEIKzsL0Y9ihSHg",
        }))
        .unwrap();
        let resolver = X5cOrKidResolver {
            kid_lookup: move |kid: &str| (kid == "test-key-1").then(|| leaf_jwk.clone()),
            trusted_roots: vec![],
            now: VALID_NOW,
        };

        let payloads = verify_chain(&chain, &resolver, VALID_NOW, 60, "unused", "unused")
            .expect("chain with a resolvable kid must verify");

        assert_eq!(payloads[0]["vct"], json!("test.1"));
    }

    #[test]
    fn rejects_an_unknown_kid() {
        let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
        header.kid = Some("no-such-key".to_string());
        let jwt = encode(&header, &json!({"vct": "test.1"}), &leaf_encoding_key()).unwrap();
        let chain = format!("{jwt}~");

        let resolver = X5cOrKidResolver {
            kid_lookup: |_: &str| None,
            trusted_roots: vec![],
            now: VALID_NOW,
        };

        let err = verify_chain(&chain, &resolver, VALID_NOW, 60, "unused", "unused").unwrap_err();

        assert!(matches!(err, VerifyError::UnresolvableRootKey(_)));
        assert_eq!(err.exit_code(), 2);
    }
}
