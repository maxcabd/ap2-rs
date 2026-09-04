use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MandateType {
    CheckoutV1,
    OpenCheckoutV1,
    PaymentV1,
    OpenPaymentV1,
    Unknown(String),
}

impl Serialize for MandateType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s: &str = match self {
            MandateType::CheckoutV1 => "mandate.checkout.1",
            MandateType::OpenCheckoutV1 => "mandate.checkout.open.1",
            MandateType::PaymentV1 => "mandate.payment.1",
            MandateType::OpenPaymentV1 => "mandate.payment.open.1",
            MandateType::Unknown(inner) => inner.as_str(),
        };

        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for MandateType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "mandate.checkout.1" => MandateType::CheckoutV1,
            "mandate.checkout.open.1" => MandateType::OpenCheckoutV1,
            "mandate.payment.1" => MandateType::PaymentV1,
            "mandate.payment.open.1" => MandateType::OpenPaymentV1,
            _ => MandateType::Unknown(s),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vct_round_trips() {
        let json = serde_json::to_string(&MandateType::CheckoutV1).unwrap();
        assert_eq!(json, "\"mandate.checkout.1\"");

        let back: MandateType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, MandateType::CheckoutV1);
    }

    #[test]
    fn unknown_vct_becomes_unknown_variant_not_an_error() {
        let json = "\"mandate.checkout.2\"";

        let parsed: MandateType = serde_json::from_str(json).unwrap();

        assert_eq!(
            parsed,
            MandateType::Unknown("mandate.checkout.2".to_string())
        );
    }
}
