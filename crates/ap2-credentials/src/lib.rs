//! AP2 credential mechanics: compact JWT/JWS parsing, SD-JWT selective
//! disclosure, and signature verification.
//!
//! This crate implements AP2 *semantics* on top of mature, audited
//! cryptographic/JWT crates. It MUST NOT contain custom implementations of
//! signature primitives, hashing, or encoding.
