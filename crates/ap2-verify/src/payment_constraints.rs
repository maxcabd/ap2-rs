use ap2_core::{OpenPaymentMandate, PaymentConstraint, PaymentMandate};

use crate::constraints::merchant_matches;

/// Aggregated usage context for a recurring mandate, supplied by the
/// caller: this crate has no persistence of its own.
#[derive(Debug, Clone, Default)]
pub struct MandateContext {
    pub total_amount: i64,
    pub total_uses: u32,
}

fn check_preset_payment_claims(open: &OpenPaymentMandate, closed: &PaymentMandate) -> Vec<String> {
    let mut violations = Vec::new();

    if let Some(payee) = &open.payee {
        if !merchant_matches(payee, &closed.payee) {
            violations.push(format!(
                "Pre-set payee mismatch: expected {}, got {}",
                payee.name, closed.payee.name
            ));
        }
    }
    if let Some(amount) = &open.payment_amount {
        if *amount != closed.payment_amount {
            violations.push(format!(
                "Pre-set amount mismatch: expected {amount:?}, got {:?}",
                closed.payment_amount
            ));
        }
    }
    if let Some(instrument) = &open.payment_instrument {
        if *instrument != closed.payment_instrument {
            violations.push("Pre-set payment_instrument mismatch".to_string());
        }
    }
    if let Some(execution_date) = &open.execution_date {
        if Some(execution_date) != closed.execution_date.as_ref() {
            violations.push(format!(
                "Pre-set execution_date mismatch: expected {execution_date}, got {:?}",
                closed.execution_date
            ));
        }
    }

    violations
}

fn evaluate_constraint(
    constraint: &PaymentConstraint,
    closed: &PaymentMandate,
    open_checkout_hash: Option<&str>,
    mandate_context: Option<&MandateContext>,
) -> Vec<String> {
    match constraint {
        PaymentConstraint::AmountRange { currency, max, min } => {
            let amount = &closed.payment_amount;
            let mut violations = Vec::new();
            if amount.currency != *currency {
                violations.push(format!(
                    "Currency mismatch: expected {currency}, got {}",
                    amount.currency
                ));
            }
            if let Some(min) = min {
                if amount.amount < *min {
                    violations.push(format!("Amount {} below minimum {min}", amount.amount));
                }
            }
            if amount.amount > *max {
                violations.push(format!("Amount {} exceeds maximum {max}", amount.amount));
            }
            violations
        }
        PaymentConstraint::AllowedPayees { allowed } => {
            if allowed.iter().any(|a| merchant_matches(a, &closed.payee)) {
                vec![]
            } else {
                vec![format!("Payee {} not in allowed list", closed.payee.name)]
            }
        }
        PaymentConstraint::PaymentReference {
            conditional_transaction_id,
        } => {
            let Some(open_checkout_hash) = open_checkout_hash else {
                return vec![
                    "open_checkout_hash is required to evaluate PaymentReference constraints"
                        .to_string(),
                ];
            };
            if open_checkout_hash == conditional_transaction_id {
                vec![]
            } else {
                vec![format!(
                    "PaymentReference mismatch: expected open checkout hash {conditional_transaction_id}, got {open_checkout_hash}"
                )]
            }
        }
        PaymentConstraint::AgentRecurrence {
            max_occurrences, ..
        } => {
            let Some(limit) = max_occurrences else {
                return vec![];
            };
            let Some(context) = mandate_context else {
                return vec!["Missing mandate context required to evaluate recurrence".to_string()];
            };
            if context.total_uses >= *limit {
                vec![format!(
                    "Maximum occurrences exceeded: {} >= {limit}",
                    context.total_uses
                )]
            } else {
                vec![]
            }
        }
        PaymentConstraint::AllowedPaymentInstruments { allowed } => {
            if allowed.iter().any(|a| a.id == closed.payment_instrument.id) {
                vec![]
            } else {
                vec![format!(
                    "Payment instrument {} not in allowed list",
                    closed.payment_instrument.id
                )]
            }
        }
        PaymentConstraint::AllowedPisps { allowed } => {
            let Some(pisp) = &closed.pisp else {
                return vec!["Missing PISP in closed mandate".to_string()];
            };
            if allowed.contains(pisp) {
                vec![]
            } else {
                vec![format!("PISP {pisp:?} not in allowed list")]
            }
        }
        PaymentConstraint::Budget { max, currency } => {
            if closed.payment_amount.currency != *currency {
                return vec![format!(
                    "Budget currency mismatch: expected {currency}, got {}",
                    closed.payment_amount.currency
                )];
            }
            let Some(context) = mandate_context else {
                return vec!["Missing mandate context required to evaluate budget".to_string()];
            };
            let total_spend = context.total_amount + closed.payment_amount.amount;
            let budget_max_cents = (*max * 100.0) as i64;
            if total_spend > budget_max_cents {
                vec![format!(
                    "Cumulative spend {total_spend} exceeds budget limit {budget_max_cents} \
                     (past spend: {})",
                    context.total_amount
                )]
            } else {
                vec![]
            }
        }
        PaymentConstraint::ExecutionDate {
            not_before,
            not_after,
        } => {
            let Some(exec_date) = &closed.execution_date else {
                return vec![];
            };
            let mut violations = Vec::new();
            if let Some(not_before) = not_before {
                if exec_date < not_before {
                    violations.push(format!(
                        "Execution date {exec_date} is before allowed window {not_before}"
                    ));
                }
            }
            if let Some(not_after) = not_after {
                if exec_date > not_after {
                    violations.push(format!(
                        "Execution date {exec_date} is after allowed window {not_after}"
                    ));
                }
            }
            violations
        }
    }
}

/// Verifies a closed Payment Mandate satisfies an Open Payment Mandate's
/// constraints and pre-set claims. Returns violation messages; empty
/// means compliant.
pub fn check_payment_constraints(
    open_mandate: &OpenPaymentMandate,
    closed_payment: &PaymentMandate,
    open_checkout_hash: Option<&str>,
    mandate_context: Option<&MandateContext>,
) -> Vec<String> {
    let mut violations = check_preset_payment_claims(open_mandate, closed_payment);

    let has_recurrence = open_mandate
        .constraints
        .iter()
        .any(|c| matches!(c, PaymentConstraint::AgentRecurrence { .. }));
    if has_recurrence {
        let has_amount = open_mandate
            .constraints
            .iter()
            .any(|c| matches!(c, PaymentConstraint::AmountRange { .. }));
        let has_budget = open_mandate
            .constraints
            .iter()
            .any(|c| matches!(c, PaymentConstraint::Budget { .. }));
        if !has_amount {
            violations.push(
                "payment.agent_recurrence requires payment.amount_range constraint".to_string(),
            );
        }
        if !has_budget {
            violations
                .push("payment.agent_recurrence requires payment.budget constraint".to_string());
        }
    }

    for constraint in &open_mandate.constraints {
        violations.extend(evaluate_constraint(
            constraint,
            closed_payment,
            open_checkout_hash,
            mandate_context,
        ));
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn open_mandate(constraints: serde_json::Value) -> OpenPaymentMandate {
        serde_json::from_value(json!({
            "vct": "mandate.payment.open.1",
            "constraints": constraints,
            "cnf": {},
        }))
        .unwrap()
    }

    fn closed_mandate(overrides: serde_json::Value) -> PaymentMandate {
        let mut value = json!({
            "vct": "mandate.payment.1",
            "transaction_id": "tx-1",
            "payee": {"id": "m-1", "name": "Store"},
            "payment_amount": {"amount": 1000, "currency": "USD"},
            "payment_instrument": {"id": "pi-1", "type": "credit"},
        });
        for (k, v) in overrides.as_object().unwrap() {
            value[k] = v.clone();
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn amount_range_rejects_over_max() {
        let open = open_mandate(json!([
            {"type": "payment.amount_range", "currency": "USD", "max": 500},
        ]));
        let closed = closed_mandate(json!({}));
        let violations = check_payment_constraints(&open, &closed, None, None);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("exceeds maximum"));
    }

    #[test]
    fn amount_range_rejects_under_min() {
        let open = open_mandate(json!([
            {"type": "payment.amount_range", "currency": "USD", "max": 5000, "min": 2000},
        ]));
        let closed = closed_mandate(json!({}));
        let violations = check_payment_constraints(&open, &closed, None, None);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("below minimum"));
    }

    #[test]
    fn amount_range_accepts_in_range() {
        let open = open_mandate(json!([
            {"type": "payment.amount_range", "currency": "USD", "max": 5000, "min": 100},
        ]));
        let closed = closed_mandate(json!({}));
        assert!(check_payment_constraints(&open, &closed, None, None).is_empty());
    }

    #[test]
    fn budget_rejects_over_limit() {
        let open = open_mandate(json!([
            {"type": "payment.budget", "max": 5.00, "currency": "USD"},
        ]));
        let closed = closed_mandate(json!({}));
        let context = MandateContext {
            total_amount: 0,
            total_uses: 0,
        };
        let violations = check_payment_constraints(&open, &closed, None, Some(&context));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("exceeds"));
    }

    #[test]
    fn budget_accepts_within_limit() {
        let open = open_mandate(json!([
            {"type": "payment.budget", "max": 100.0, "currency": "USD"},
        ]));
        let closed = closed_mandate(json!({}));
        let context = MandateContext {
            total_amount: 5000,
            total_uses: 0,
        };
        assert!(check_payment_constraints(&open, &closed, None, Some(&context)).is_empty());
    }

    #[test]
    fn agent_recurrence_requires_amount_range_and_budget() {
        let open = open_mandate(json!([
            {"type": "payment.agent_recurrence", "frequency": "MONTHLY"},
        ]));
        let closed = closed_mandate(json!({}));
        let violations = check_payment_constraints(&open, &closed, None, None);
        assert_eq!(violations.len(), 2);
        assert!(violations.iter().any(|v| v.contains("amount_range")));
        assert!(violations.iter().any(|v| v.contains("budget")));
    }

    #[test]
    fn agent_recurrence_rejects_at_limit() {
        let open = open_mandate(json!([
            {"type": "payment.agent_recurrence", "frequency": "MONTHLY", "max_occurrences": 3},
            {"type": "payment.amount_range", "currency": "USD", "max": 5000},
            {"type": "payment.budget", "max": 100.0, "currency": "USD"},
        ]));
        let closed = closed_mandate(json!({}));
        let context = MandateContext {
            total_amount: 0,
            total_uses: 3,
        };
        let violations = check_payment_constraints(&open, &closed, None, Some(&context));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("Maximum occurrences exceeded"));
    }

    #[test]
    fn payment_reference_matches_open_checkout_hash() {
        let open = open_mandate(json!([
            {"type": "payment.reference", "conditional_transaction_id": "open-hash"},
        ]));
        let closed = closed_mandate(json!({}));
        assert!(check_payment_constraints(&open, &closed, Some("open-hash"), None).is_empty());
        let violations = check_payment_constraints(&open, &closed, Some("wrong-hash"), None);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn execution_date_rejects_outside_window() {
        let open = open_mandate(json!([
            {"type": "payment.execution_date", "not_before": "2026-01-01", "not_after": "2026-01-31"},
        ]));
        let closed = closed_mandate(json!({"execution_date": "2026-02-15"}));
        let violations = check_payment_constraints(&open, &closed, None, None);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("after allowed window"));
    }

    #[test]
    fn preset_payee_mismatch_is_a_violation() {
        let open: OpenPaymentMandate = serde_json::from_value(json!({
            "vct": "mandate.payment.open.1",
            "constraints": [],
            "cnf": {},
            "payee": {"id": "m-1", "name": "Store"},
        }))
        .unwrap();
        let closed = closed_mandate(json!({"payee": {"id": "m-2", "name": "Other"}}));
        let violations = check_payment_constraints(&open, &closed, None, None);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("Pre-set payee mismatch"));
    }
}
