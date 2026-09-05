//! Deterministic, role-aware AP2 verification.
//!
//! Verification is kept separate from parsing (`ap2-core`) and credential
//! mechanics (`ap2-credentials`): an object that has merely been parsed MUST
//! NOT be treated as trusted.

mod chain;
mod checkout;
mod checkout_chain;
mod constraints;
mod delegate;
mod error;

pub use chain::verify_chain;
pub use checkout::{verify_checkout_mandate, VerifiedCheckoutMandate};
pub use checkout_chain::CheckoutMandateChain;
pub use constraints::{check_checkout_constraints, CheckoutForConstraints, CheckoutLineItem};
pub use error::VerifyError;
