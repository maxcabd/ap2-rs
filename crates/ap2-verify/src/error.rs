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

    /// Real AP2 issuers wrap mandate fields as `delegate_payload: [{...}]`
    /// (draft-gco-oauth-delegate-sd-jwt); this is a malformed one.
    #[error("delegate_payload must be a one-item array of objects")]
    InvalidDelegatePayload,

    /// A `~~`-joined delegation chain hop that fails a structural check
    /// (bad/missing `typ`, missing `iat`, missing or wrong `cnf` for its
    /// position, more than one delegate item where exactly one is required).
    #[error("malformed delegation chain hop: {0}")]
    MalformedChainHop(&'static str),

    #[error("chain hop's confirmation key (cnf.jwk) is missing or invalid")]
    MissingConfirmationKey,

    #[error("chain hop binding (sd_hash/issuer_jwt_hash) does not match the preceding hop")]
    ChainBindingMismatch,

    #[error("chain terminal hop's aud/nonce does not match the expected values")]
    ChainAudienceMismatch,

    #[error("expected a Checkout Mandate (mandate.checkout.1), found {0:?}")]
    WrongMandateType(MandateType),

    #[error("unrecognized mandate type {0:?}: this build does not understand this protocol version/type")]
    UnsupportedMandateType(String),

    #[error("checkout_hash does not match the supplied Checkout JWT")]
    HashMismatch,

    #[error("transaction_id does not match the supplied Checkout JWT")]
    TransactionIdMismatch,

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

            VerifyError::WrongMandateType(_)
            | VerifyError::MalformedClaims(_)
            | VerifyError::InvalidDelegatePayload
            | VerifyError::MalformedChainHop(_)
            | VerifyError::MissingConfirmationKey => 2,

            VerifyError::Credential(CredentialError::MalformedJws(_))
            | VerifyError::Credential(CredentialError::MalformedSdJwt(_))
            | VerifyError::Credential(CredentialError::Disclosure(_)) => 2,

            VerifyError::Credential(CredentialError::SignatureInvalid(_))
            | VerifyError::Credential(CredentialError::DisallowedAlgorithm(_))
            | VerifyError::Credential(CredentialError::KeyBinding(_))
            | VerifyError::HashMismatch
            | VerifyError::TransactionIdMismatch
            | VerifyError::ChainBindingMismatch
            | VerifyError::ChainAudienceMismatch
            | VerifyError::Expired { .. }
            | VerifyError::NotYetValid { .. } => 1,
        }
    }
}
