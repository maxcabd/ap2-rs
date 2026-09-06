use ap2_credentials::{peek_header, sha256_base64url, verify_sd_jwt, Jwk};
use serde_json::Value;

use crate::delegate::resolve_delegate_items;
use crate::error::VerifyError;
use crate::key_resolver::RootKeyResolver;

const TYP_TERMINAL: &[&str] = &["kb+sd-jwt", "kb-sd-jwt"];
const TYP_INTERMEDIATE: &[&str] = &["kb+sd-jwt+kb", "kb-sd-jwt+kb"];

type Claims = serde_json::Map<String, Value>;

/// Verifies a `~~`-joined dSD-JWT delegation chain
/// (draft-gco-oauth-delegate-sd-jwt-00 §6): a root SD-JWT verified against
/// `root_key`, followed by zero or more KB-SD-JWT hops each signed by the
/// previous hop's disclosed `cnf.jwk`.
///
/// Only the terminal (last) hop's `aud`/`nonce` are checked against
/// `expected_aud`/`expected_nonce` -- intermediate hops are pure
/// delegation, not presentations to a specific verifier.
///
/// Returns one flattened list of effective payloads (root first). This
/// function doesn't know about specific AP2 mandate types: callers
/// deserialize/interpret each entry themselves.
pub fn verify_chain<K: RootKeyResolver>(
    chain: &str,
    root_key: &K,
    now: i64,
    leeway_seconds: i64,
    expected_aud: &str,
    expected_nonce: &str,
) -> Result<Vec<Claims>, VerifyError> {
    let hops: Vec<&str> = chain.split("~~").collect();

    let root_header = peek_header(hops[0])?;
    let resolved_root_key = root_key.resolve_root_key(&root_header)?;
    let root = verify_sd_jwt(&ensure_trailing_tilde(hops[0]), &resolved_root_key)?;
    let root_items = resolve_delegate_items(&root.claims)?;
    if root_items.len() > 1 {
        return Err(VerifyError::InvalidDelegatePayload);
    }
    check_freshness(&root.claims, now, leeway_seconds)?;
    for item in &root_items {
        check_freshness(item, now, leeway_seconds)?;
    }

    let mut all_payloads = effective_payloads(&root.claims, &root_items);
    let mut prev_hop = hops[0];
    let mut prev_claims = root.claims;
    let mut prev_items = root_items;

    for (i, hop) in hops.iter().enumerate().skip(1) {
        let is_last = i == hops.len() - 1;

        let signing_key = confirmation_key(&prev_claims, &prev_items)?;
        let verified = verify_sd_jwt(&ensure_trailing_tilde(hop), &signing_key)?;

        let typ = verified
            .header
            .get("typ")
            .and_then(Value::as_str)
            .ok_or(VerifyError::MalformedChainHop("missing typ header"))?;
        let is_terminal_typ = TYP_TERMINAL.contains(&typ);
        let is_intermediate_typ = TYP_INTERMEDIATE.contains(&typ);
        if !is_terminal_typ && !is_intermediate_typ {
            return Err(VerifyError::MalformedChainHop("unrecognized typ"));
        }

        verify_binding(&verified.claims, prev_hop)?;

        if !verified.claims.contains_key("iat") {
            return Err(VerifyError::MalformedChainHop("missing iat"));
        }
        if is_last {
            let aud = verified.claims.get("aud").and_then(Value::as_str);
            let nonce = verified.claims.get("nonce").and_then(Value::as_str);
            if aud != Some(expected_aud) || nonce != Some(expected_nonce) {
                return Err(VerifyError::ChainAudienceMismatch);
            }
        }

        let items = resolve_delegate_items(&verified.claims)?;
        if !is_last && items.len() != 1 {
            return Err(VerifyError::InvalidDelegatePayload);
        }
        let has_cnf = items.iter().any(|item| item.contains_key("cnf"));
        if is_terminal_typ && has_cnf {
            return Err(VerifyError::MalformedChainHop(
                "terminal hop must not carry cnf",
            ));
        }
        if is_intermediate_typ && !has_cnf {
            return Err(VerifyError::MalformedChainHop(
                "intermediate hop requires cnf",
            ));
        }

        check_freshness(&verified.claims, now, leeway_seconds)?;
        for item in &items {
            check_freshness(item, now, leeway_seconds)?;
        }

        all_payloads.extend(effective_payloads(&verified.claims, &items));
        prev_hop = hop;
        prev_claims = verified.claims;
        prev_items = items;
    }

    Ok(all_payloads)
}

/// `present()` strips one trailing `~` before joining hops with `~~`;
/// restore it so each hop parses as a standalone SD-JWT again.
fn ensure_trailing_tilde(hop: &str) -> String {
    if hop.ends_with('~') {
        hop.to_string()
    } else {
        format!("{hop}~")
    }
}

fn confirmation_key(claims: &Claims, items: &[Claims]) -> Result<Jwk, VerifyError> {
    let cnf = items
        .iter()
        .find_map(|item| item.get("cnf"))
        .or_else(|| claims.get("cnf"))
        .ok_or(VerifyError::MissingConfirmationKey)?;
    let jwk = cnf.get("jwk").ok_or(VerifyError::MissingConfirmationKey)?;
    serde_json::from_value(jwk.clone()).map_err(|_| VerifyError::MissingConfirmationKey)
}

/// Binding claim covers the US-ASCII bytes of the preceding hop: its full
/// canonical SD-JWT form (`sd_hash`), or just its issuer-signed JWT segment
/// (`issuer_jwt_hash`). Exactly one of the two claims must be present.
fn verify_binding(claims: &Claims, prev_hop: &str) -> Result<(), VerifyError> {
    let sd_hash = claims.get("sd_hash").and_then(Value::as_str);
    let issuer_jwt_hash = claims.get("issuer_jwt_hash").and_then(Value::as_str);
    match (sd_hash, issuer_jwt_hash) {
        (Some(actual), None) => {
            let expected = sha256_base64url(&ensure_trailing_tilde(prev_hop));
            (actual == expected)
                .then_some(())
                .ok_or(VerifyError::ChainBindingMismatch)
        }
        (None, Some(actual)) => {
            let issuer_jwt = prev_hop.split('~').next().unwrap_or(prev_hop);
            let expected = sha256_base64url(issuer_jwt);
            (actual == expected)
                .then_some(())
                .ok_or(VerifyError::ChainBindingMismatch)
        }
        _ => Err(VerifyError::MalformedChainHop(
            "exactly one of sd_hash/issuer_jwt_hash is required",
        )),
    }
}

fn check_freshness(claims: &Claims, now: i64, leeway_seconds: i64) -> Result<(), VerifyError> {
    if let Some(exp) = claims.get("exp").and_then(Value::as_i64) {
        if now - leeway_seconds > exp {
            return Err(VerifyError::Expired {
                exp,
                now,
                leeway_seconds,
            });
        }
    }
    if let Some(iat) = claims.get("iat").and_then(Value::as_i64) {
        if iat - leeway_seconds > now {
            return Err(VerifyError::NotYetValid {
                iat,
                now,
                leeway_seconds,
            });
        }
    }
    Ok(())
}

fn effective_payloads(claims: &Claims, items: &[Claims]) -> Vec<Claims> {
    if items.is_empty() {
        vec![claims.clone()]
    } else {
        items.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;
    use serde_json::json;

    const NOW: i64 = 1_700_000_000;
    const LEEWAY: i64 = 60;

    struct KeyPair {
        encoding_key: EncodingKey,
        jwk: Jwk,
    }

    fn generate_es256_keypair() -> KeyPair {
        let signing_key = SigningKey::random(&mut OsRng);
        let der = signing_key.to_pkcs8_der().unwrap();
        let encoding_key = EncodingKey::from_ec_der(der.as_bytes());
        let point = signing_key.verifying_key().to_encoded_point(false);
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }))
        .unwrap();
        KeyPair { encoding_key, jwk }
    }

    fn sign_typed(claims: &Value, key: &EncodingKey, typ: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = typ.map(str::to_string);
        encode(&header, claims, key).unwrap()
    }

    /// Builds a 2-hop chain: root (no typ) delegating to `agent`, then a
    /// terminal `kb+sd-jwt` hop signed by `agent` binding via `sd_hash`.
    struct TwoHopChain {
        chain: String,
        root: KeyPair,
    }

    fn two_hop_chain(hop2_extra: Value) -> TwoHopChain {
        let root = generate_es256_keypair();
        let agent = generate_es256_keypair();

        let root_claims = json!({
            "vct": "mandate.checkout.open.1",
            "constraints": [],
            "cnf": {"jwk": agent.jwk},
        });
        let root_jwt = sign_typed(&root_claims, &root.encoding_key, None);
        let root_sd_jwt = format!("{root_jwt}~");
        let sd_hash = sha256_base64url(&root_sd_jwt);

        let mut hop2_claims = json!({
            "vct": "mandate.checkout.1",
            "checkout_hash": "hash",
            "iat": NOW,
            "aud": "merchant",
            "nonce": "merchant-nonce",
            "sd_hash": sd_hash,
        });
        for (k, v) in hop2_extra.as_object().unwrap() {
            hop2_claims[k] = v.clone();
        }
        let hop2_jwt = sign_typed(&hop2_claims, &agent.encoding_key, Some("kb+sd-jwt"));
        let hop2_sd_jwt = format!("{hop2_jwt}~");

        TwoHopChain {
            chain: format!("{root_jwt}~~{hop2_sd_jwt}"),
            root,
        }
    }

    #[test]
    fn verifies_a_synthetic_two_hop_chain() {
        let c = two_hop_chain(json!({}));

        let payloads = verify_chain(
            &c.chain,
            &c.root.jwk,
            NOW,
            LEEWAY,
            "merchant",
            "merchant-nonce",
        )
        .expect("well-formed chain must verify");

        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0]["vct"], json!("mandate.checkout.open.1"));
        assert_eq!(payloads[1]["vct"], json!("mandate.checkout.1"));
    }

    #[test]
    fn verifies_a_single_hop_chain_with_no_delegation() {
        let root = generate_es256_keypair();
        let claims = json!({"vct": "mandate.checkout.1", "checkout_hash": "hash"});
        let chain = format!("{}~", sign_typed(&claims, &root.encoding_key, None));

        // No KB-SD-JWT hop exists, so aud/nonce are simply never checked.
        let payloads = verify_chain(&chain, &root.jwk, NOW, LEEWAY, "unused", "unused")
            .expect("single-hop chain must verify");

        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["checkout_hash"], json!("hash"));
    }

    #[test]
    fn rejects_wrong_expected_aud_or_nonce() {
        let c = two_hop_chain(json!({}));

        let err = verify_chain(
            &c.chain,
            &c.root.jwk,
            NOW,
            LEEWAY,
            "merchant",
            "wrong-nonce",
        )
        .unwrap_err();

        assert!(matches!(err, VerifyError::ChainAudienceMismatch));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn rejects_a_tampered_binding_hash() {
        let c = two_hop_chain(json!({"sd_hash": "not-the-real-hash"}));

        let err = verify_chain(
            &c.chain,
            &c.root.jwk,
            NOW,
            LEEWAY,
            "merchant",
            "merchant-nonce",
        )
        .unwrap_err();

        assert!(matches!(err, VerifyError::ChainBindingMismatch));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn rejects_an_unrecognized_hop_typ() {
        let root = generate_es256_keypair();
        let agent = generate_es256_keypair();
        let root_claims = json!({"cnf": {"jwk": agent.jwk}});
        let root_jwt = sign_typed(&root_claims, &root.encoding_key, None);
        let sd_hash = sha256_base64url(&format!("{root_jwt}~"));

        let hop2_claims = json!({
            "iat": NOW, "aud": "merchant", "nonce": "merchant-nonce", "sd_hash": sd_hash,
        });
        let hop2_jwt = sign_typed(&hop2_claims, &agent.encoding_key, Some("not-a-real-typ"));
        let chain = format!("{root_jwt}~~{hop2_jwt}~");

        let err =
            verify_chain(&chain, &root.jwk, NOW, LEEWAY, "merchant", "merchant-nonce").unwrap_err();

        assert!(matches!(err, VerifyError::MalformedChainHop(_)));
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn rejects_a_terminal_hop_that_carries_cnf() {
        let holder = generate_es256_keypair();
        let c = two_hop_chain(json!({
            "delegate_payload": [{"vct": "mandate.checkout.1", "cnf": {"jwk": holder.jwk}}],
        }));

        let err = verify_chain(
            &c.chain,
            &c.root.jwk,
            NOW,
            LEEWAY,
            "merchant",
            "merchant-nonce",
        )
        .unwrap_err();

        assert!(matches!(err, VerifyError::MalformedChainHop(_)));
    }

    #[test]
    fn rejects_an_intermediate_hop_missing_cnf() {
        // 3-hop chain: root -> intermediate (kb+sd-jwt+kb, no cnf: invalid) -> terminal.
        let root = generate_es256_keypair();
        let mid = generate_es256_keypair();
        let leaf = generate_es256_keypair();

        let root_claims = json!({"cnf": {"jwk": mid.jwk}});
        let root_jwt = sign_typed(&root_claims, &root.encoding_key, None);
        let root_sd_jwt = format!("{root_jwt}~");

        // Intermediate hop deliberately omits cnf for the next delegate.
        let mid_claims = json!({
            "iat": NOW, "sd_hash": sha256_base64url(&root_sd_jwt),
            "delegate_payload": [{"vct": "mandate.checkout.open.1"}],
        });
        let mid_jwt = sign_typed(&mid_claims, &mid.encoding_key, Some("kb+sd-jwt+kb"));
        let mid_sd_jwt = format!("{mid_jwt}~");

        let leaf_claims = json!({
            "iat": NOW, "aud": "merchant", "nonce": "n",
            "sd_hash": sha256_base64url(&mid_sd_jwt),
        });
        let leaf_jwt = sign_typed(&leaf_claims, &leaf.encoding_key, Some("kb+sd-jwt"));

        let chain = format!("{root_jwt}~~{mid_jwt}~~{leaf_jwt}~");

        let err = verify_chain(&chain, &root.jwk, NOW, LEEWAY, "merchant", "n").unwrap_err();

        assert!(matches!(err, VerifyError::MalformedChainHop(_)));
    }

    /// A correctly-formed 3-hop chain: root -> intermediate (has cnf,
    /// delegating onward) -> terminal. Mirrors the real-world
    /// DPC -> wallet -> agent delegation pattern (three tiers, not just
    /// the 2-hop Open+Closed case every other chain test here uses).
    #[test]
    fn verifies_a_well_formed_three_hop_chain() {
        let root = generate_es256_keypair();
        let mid = generate_es256_keypair();
        let leaf = generate_es256_keypair();

        let root_claims = json!({"vct": "dpc.credential.1", "cnf": {"jwk": mid.jwk}});
        let root_jwt = sign_typed(&root_claims, &root.encoding_key, None);
        let root_sd_jwt = format!("{root_jwt}~");

        let mid_claims = json!({
            "iat": NOW,
            "sd_hash": sha256_base64url(&root_sd_jwt),
            "delegate_payload": [{"vct": "wallet.delegation.1", "cnf": {"jwk": leaf.jwk}}],
        });
        let mid_jwt = sign_typed(&mid_claims, &mid.encoding_key, Some("kb+sd-jwt+kb"));
        let mid_sd_jwt = format!("{mid_jwt}~");

        let leaf_claims = json!({
            "iat": NOW,
            "aud": "merchant",
            "nonce": "merchant-nonce",
            "sd_hash": sha256_base64url(&mid_sd_jwt),
            "delegate_payload": [{"vct": "mandate.checkout.1", "checkout_hash": "hash"}],
        });
        let leaf_jwt = sign_typed(&leaf_claims, &leaf.encoding_key, Some("kb+sd-jwt"));

        let chain = format!("{root_jwt}~~{mid_jwt}~~{leaf_jwt}~");

        let payloads = verify_chain(&chain, &root.jwk, NOW, LEEWAY, "merchant", "merchant-nonce")
            .expect("well-formed 3-hop chain must verify");

        assert_eq!(payloads.len(), 3);
        assert_eq!(payloads[0]["vct"], json!("dpc.credential.1"));
        assert_eq!(payloads[1]["vct"], json!("wallet.delegation.1"));
        assert_eq!(payloads[2]["vct"], json!("mandate.checkout.1"));
    }

    #[test]
    fn rejects_an_expired_hop() {
        let c = two_hop_chain(json!({"exp": NOW - 3600}));

        let err = verify_chain(
            &c.chain,
            &c.root.jwk,
            NOW,
            LEEWAY,
            "merchant",
            "merchant-nonce",
        )
        .unwrap_err();

        assert!(matches!(err, VerifyError::Expired { .. }));
    }

    // A genuine 2-hop chain minted by AP2's own upstream Python reference
    // SDK (commit e1ea56db72a6385bce3e5c1112b3a56ce60acb43): an
    // OpenCheckoutMandate delegating to an agent key, then a CheckoutMandate
    // presented to "merchant" with nonce "merchant-nonce".
    const REAL_UPSTREAM_ROOT_KEY: &str = r#"{"crv":"P-256","kty":"EC","x":"j0vAm_Lf3h-gRRwlrxXyszxBCd4Wdwuq6M9kBzPulAs","y":"N8bS7vXe3RCSPmD34Pw0srb4120nt8xr2mu8C9rIDdg"}"#;
    const REAL_UPSTREAM_CHAIN: &str = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJkZWxlZ2F0ZV9wYXlsb2FkIjogW3siLi4uIjogInJ3TFVNZ1hXM3NNTjZ5bjVnM25qb0JIMVMzUFY0ajluRnhCcHFhMDJwNG8ifV0sICJfc2RfYWxnIjogInNoYS0yNTYifQ.Pj4SJi9BelCFns_TuxOTH2b-7psu2DA4SISLmqcikSn1GiqhqAjVYxXK_hhUBwp4ofslSGauCrBiKn_VXSCwBg~WyJKUU5ES2xEZGxKRUgwYlY5RUFweDRBIiwgeyJ2Y3QiOiAibWFuZGF0ZS5jaGVja291dC5vcGVuLjEiLCAiY29uc3RyYWludHMiOiBbXSwgImNuZiI6IHsiandrIjogeyJrdHkiOiAiRUMiLCAiY3J2IjogIlAtMjU2IiwgIngiOiAibWtYNUJNNW1LbmhTMzZjMHVLZWNHNW16M0VvU1VyYnA3bjF5bmdNdWJBTSIsICJ5IjogIlRCRkRfdkRTdWdBZmluMVdIZnlBUHNndmhSQjVKNFQyTWhtVVZ4cFJRN1kiLCAiYWxnIjogIkVTMjU2In19fV0~~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK3NkLWp3dCJ9.eyJkZWxlZ2F0ZV9wYXlsb2FkIjogW3siLi4uIjogIjU2UmpJZk8weVBGRm9mVHhMZVBUejNJX3pKaFM1bjJQY3ZqWTg1Nk9vbFEifV0sICJpYXQiOiAxNzg4NTY4Nzg4LCAiYXVkIjogIm1lcmNoYW50IiwgIm5vbmNlIjogIm1lcmNoYW50LW5vbmNlIiwgInNkX2hhc2giOiAiVFVTUWlmd2U1OFpxRjJSVWtHLVVwZTh1TjQtSkxUZU5ELXRrbmpBdmtRTSIsICJfc2RfYWxnIjogInNoYS0yNTYifQ.a7LvlGynBP_zAVbA_HZjqWSALfiH_HuVuP9A8_ApgxyKGx1PXTx4_U4-5PWkLC0ZRXFr_tKIQAhoBUXdCIISEg~WyJnbGVTN0l5bG9NREJsbExxZ1lsRUxBIiwgeyJfc2QiOiBbIjVoR0ctNVhOdmVuQTFyaURLczRIazJtTmtWZElabGZJU2dObjByV0d3LU0iXSwgInZjdCI6ICJtYW5kYXRlLmNoZWNrb3V0LjEiLCAiY2hlY2tvdXRfaGFzaCI6ICJoYXNoIn1d~WyJQUlR5em5CZ05PNWE5UnR4T1BEa1lBIiwgImNoZWNrb3V0X2p3dCIsICJoZHIuYm9keS5zaWciXQ~";
    const REAL_UPSTREAM_IAT: i64 = 1_788_568_788;

    fn real_root_key() -> Jwk {
        serde_json::from_str(REAL_UPSTREAM_ROOT_KEY).unwrap()
    }

    #[test]
    fn verifies_a_real_upstream_two_hop_chain() {
        let payloads = verify_chain(
            REAL_UPSTREAM_CHAIN,
            &real_root_key(),
            REAL_UPSTREAM_IAT,
            LEEWAY,
            "merchant",
            "merchant-nonce",
        )
        .expect("genuine upstream-signed chain must verify");

        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0]["vct"], json!("mandate.checkout.open.1"));
        assert_eq!(payloads[1]["vct"], json!("mandate.checkout.1"));
        assert_eq!(payloads[1]["checkout_hash"], json!("hash"));
    }

    #[test]
    fn rejects_wrong_nonce_on_real_upstream_chain() {
        let err = verify_chain(
            REAL_UPSTREAM_CHAIN,
            &real_root_key(),
            REAL_UPSTREAM_IAT,
            LEEWAY,
            "merchant",
            "wrong-nonce",
        )
        .unwrap_err();

        assert!(matches!(err, VerifyError::ChainAudienceMismatch));
    }
}
