use ap2_core::MandateType;
use ap2_credentials::CredentialError;
use thiserror::Error;

/// Errors from AP2 verification policy: signature/disclosure mechanics
/// (`ap2-credentials`) plus AP2-specific rules (hash binding, freshness,
/// mandate type) this crate enforces on top of them.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error(transparent)]
    Credential(#[from] CredentialError),

    #[error("failed to parse disclosed mandate claims: {0}")]
    MalformedClaims(#[from] serde_json::Error),

    #[error("expected a Checkout Mandate (mandate.checkout.1), found {0:?}")]
    WrongMandateType(MandateType),

    #[error("unrecognized mandate type {0:?}: this build does not understand this protocol version/type")]
    UnsupportedMandateType(String),

    #[error("checkout_hash does not match the supplied Checkout JWT")]
    HashMismatch,

    #[error("mandate expired at {exp}, now is {now} (leeway {leeway_seconds}s)")]
    Expired {
        exp: i64,
        now: i64,
        leeway_seconds: i64,
    },

    #[error("mandate iat {iat} is in the future relative to now {now} (leeway {leeway_seconds}s)")]
    NotYetValid {
        iat: i64,
        now: i64,
        leeway_seconds: i64,
    },
}

impl VerifyError {
    /// Maps to `ap2-cli`'s documented exit codes: 1 verification failed,
    /// 2 malformed input / wrong artifact for this command, 3 unsupported
    /// protocol/version.
    pub fn exit_code(&self) -> u8 {
        match self {
            VerifyError::UnsupportedMandateType(_) => 3,

            VerifyError::WrongMandateType(_) | VerifyError::MalformedClaims(_) => 2,

            VerifyError::Credential(CredentialError::MalformedJws(_))
            | VerifyError::Credential(CredentialError::MalformedSdJwt(_))
            | VerifyError::Credential(CredentialError::Disclosure(_)) => 2,

            VerifyError::Credential(CredentialError::SignatureInvalid(_))
            | VerifyError::Credential(CredentialError::DisallowedAlgorithm(_))
            | VerifyError::Credential(CredentialError::KeyBinding(_))
            | VerifyError::HashMismatch
            | VerifyError::Expired { .. }
            | VerifyError::NotYetValid { .. } => 1,
        }
    }
}
