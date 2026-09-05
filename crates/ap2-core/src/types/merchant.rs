use serde::{Deserialize, Serialize};

/// `spec/schemas/ap2/types/merchant.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Merchant {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_without_website() {
        let json = r#"{"id": "m-1", "name": "Example Store"}"#;
        let parsed: Merchant = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.website, None);

        let out = serde_json::to_string(&parsed).unwrap();
        assert_eq!(parsed, serde_json::from_str(&out).unwrap());
    }
}
