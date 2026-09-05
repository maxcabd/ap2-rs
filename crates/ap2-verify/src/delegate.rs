use serde_json::Value;

use crate::error::VerifyError;

/// Resolves items from a `delegate_payload` claim. Real AP2 issuers wrap
/// mandate/model fields as `delegate_payload: [{...}]`
/// (draft-gco-oauth-delegate-sd-jwt-00 §5.1.4). Returns `[]` if absent.
pub(crate) fn resolve_delegate_items(
    claims: &serde_json::Map<String, Value>,
) -> Result<Vec<serde_json::Map<String, Value>>, VerifyError> {
    match claims.get("delegate_payload") {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Object(obj) => Ok(obj.clone()),
                _ => Err(VerifyError::InvalidDelegatePayload),
            })
            .collect(),
        Some(_) => Err(VerifyError::InvalidDelegatePayload),
    }
}
