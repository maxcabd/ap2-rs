//! Pure protocol-domain types for the Agentic Payment Protocol (AP2).
//!
//! This crate performs no network I/O, no persistence, and no key management.
//! Types here are generated/derived from the pinned canonical AP2 schemas in
//! `spec/schemas/`, recorded in `spec/upstream.json`.

pub mod checkout_mandate;
pub mod mandate_type;
pub mod open_checkout_mandate;
pub mod types;

pub use checkout_mandate::UnverifiedCheckoutMandate;
pub use mandate_type::MandateType;
pub use open_checkout_mandate::{
    AcceptableItem, Constraint, LineItemRequirement, OpenCheckoutMandate,
};
pub use types::Merchant;

/// The AP2 protocol specification version this crate targets.
pub const AP2_SPEC_VERSION: &str = "0.2";

/// The exact upstream AP2 repository commit this crate was implemented and
/// tested against. See `spec/upstream.json` for the authoritative record.
pub const AP2_UPSTREAM_COMMIT: &str = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_version_is_pinned() {
        assert_eq!(AP2_SPEC_VERSION, "0.2");
        assert_eq!(AP2_UPSTREAM_COMMIT.len(), 40);
    }
}
