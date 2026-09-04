//! AP2 credential mechanics: compact JWT/JWS parsing, SD-JWT selective
//! disclosure, and signature verification.
//!
//! This crate implements AP2 *semantics* on top of mature, audited
//! cryptographic/JWT crates. It MUST NOT contain custom implementations of
//! signature primitives, hashing, or encoding.

mod error;
mod jws;
mod sd_jwt;

pub use error::CredentialError;
pub use jws::{verify_compact_jws, VerifiedJws, ALLOWED_ALGORITHMS};
pub use sd_jwt::{verify_key_binding, verify_sd_jwt, VerifiedKeyBinding, VerifiedSdJwt};

pub use jsonwebtoken::jwk::Jwk;
pub use jsonwebtoken::Algorithm;
