//! AP2 credential mechanics: compact JWT/JWS parsing, SD-JWT selective
//! disclosure, and signature verification.
//!
//! This crate implements AP2 *semantics* on top of mature, audited
//! cryptographic/JWT crates. It MUST NOT contain custom implementations of
//! signature primitives, hashing, or encoding.

mod error;
mod jws;
mod sd_jwt;
mod x509;

pub use error::CredentialError;
pub use jws::{peek_header, verify_compact_jws, VerifiedJws, ALLOWED_ALGORITHMS};
pub use sd_jwt::{
    sha256_base64url, verify_key_binding, verify_sd_jwt, VerifiedKeyBinding, VerifiedSdJwt,
};
pub use x509::{verify_x5c_chain, Certificate};

pub use jsonwebtoken::jwk::Jwk;
pub use jsonwebtoken::{Algorithm, Header};
