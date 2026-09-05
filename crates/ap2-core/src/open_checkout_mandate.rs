use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use crate::mandate_type::MandateType;
use crate::types::Merchant;

/// An item that may satisfy a [`LineItemRequirement`]. Distinct from the
/// pinned `types/item.json` (which also has `price`/`image_url`) --
/// `open_checkout_mandate.json` defines this narrower shape inline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptableItem {
    pub id: String,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineItemRequirement {
    pub id: String,
    pub acceptable_items: Vec<AcceptableItem>,
    pub quantity: NonZeroU32,
}

/// One constraint the future Checkout must satisfy. An unrecognized
/// `type` fails to parse rather than being silently dropped: an ignored
/// constraint an issuer meant to enforce is a security gap, not a
/// compatibility nicety.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Constraint {
    #[serde(rename = "checkout.allowed_merchants")]
    AllowedMerchants { allowed: Vec<Merchant> },
    #[serde(rename = "checkout.line_items")]
    LineItems { items: Vec<LineItemRequirement> },
}

/// `spec/schemas/ap2/open_checkout_mandate.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenCheckoutMandate {
    pub vct: MandateType,
    pub constraints: Vec<Constraint>,
    /// RFC 7800 `cnf`. Left as raw JSON: the schema doesn't pin its shape,
    /// and resolving it into a signing key is `ap2-verify`'s job.
    pub cnf: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> serde_json::Value {
        json!({
            "vct": "mandate.checkout.open.1",
            "constraints": [
                {"type": "checkout.allowed_merchants", "allowed": [{"id": "m-1", "name": "Store"}]},
                {"type": "checkout.line_items", "items": [
                    {"id": "req-1", "acceptable_items": [{"id": "SKU-A", "title": "Widget"}], "quantity": 2}
                ]},
            ],
            "cnf": {"jwk": {"kty": "EC"}},
        })
    }

    #[test]
    fn parses_constraints() {
        let mandate: OpenCheckoutMandate = serde_json::from_value(sample()).unwrap();
        assert_eq!(mandate.vct, MandateType::OpenCheckoutV1);
        assert_eq!(mandate.constraints.len(), 2);
        assert!(matches!(
            mandate.constraints[0],
            Constraint::AllowedMerchants { .. }
        ));
        assert!(matches!(
            mandate.constraints[1],
            Constraint::LineItems { .. }
        ));
    }

    #[test]
    fn rejects_an_unrecognized_constraint_type() {
        let mut value = sample();
        value["constraints"] = json!([{"type": "checkout.something_new"}]);
        let result: Result<OpenCheckoutMandate, _> = serde_json::from_value(value);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_zero_quantity() {
        let mut value = sample();
        value["constraints"][1]["items"][0]["quantity"] = json!(0);
        let result: Result<OpenCheckoutMandate, _> = serde_json::from_value(value);
        assert!(result.is_err());
    }
}
