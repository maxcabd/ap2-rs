use thiserror::Error;

/// Errors from JWT/JWS and SD-JWT credential mechanics
#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("malformed compact JWT: {0}")]
    MalformedJws(String),

    #[error(transparent)]
    SignatureInvalid(#[from] jsonwebtoken::errors::Error),

    #[error("alg {0:?} is not in the allowed set for this credential type")]
    DisallowedAlgorithm(jsonwebtoken::Algorithm),

    #[error("malformed SD-JWT: {0}")]
    MalformedSdJwt(String),

    #[error("SD-JWT disclosure error: {0}")]
    Disclosure(String),

    #[error("key binding JWT verification failed: {0}")]
    KeyBinding(String),

    #[error("certificate chain signature invalid")]
    CertificateChainInvalid,

    #[error("certificate not valid at {now}: window is {not_before}..={not_after}")]
    CertificateExpired {
        not_before: i64,
        not_after: i64,
        now: i64,
    },

    #[error("certificate chain does not lead to a trusted root")]
    UntrustedCertificateRoot,
}
