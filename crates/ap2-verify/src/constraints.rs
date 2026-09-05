use std::collections::{HashMap, HashSet, VecDeque};

use ap2_core::{Constraint, Merchant, OpenCheckoutMandate};
use serde::Deserialize;

/// The slice of a Checkout JWT's payload constraint-checking needs. AP2
/// doesn't pin a schema for this payload (it's UCP's, an external spec);
/// unknown fields (status, totals, links, ...) are simply ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct CheckoutForConstraints {
    #[serde(default)]
    pub merchant: Option<Merchant>,
    #[serde(default)]
    pub line_items: Vec<CheckoutLineItem>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckoutLineItem {
    pub item: CheckoutItemRef,
    pub quantity: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckoutItemRef {
    pub id: String,
}

/// Matches merchants by `id` (preferred), else by non-empty `name` +
/// `website` both matching.
fn merchant_matches(candidate: &Merchant, target: &Merchant) -> bool {
    if !candidate.id.is_empty() && !target.id.is_empty() {
        return candidate.id == target.id;
    }
    let name_matches = !candidate.name.is_empty() && candidate.name == target.name;
    let website_matches = candidate.website.as_deref().is_some_and(|w| !w.is_empty())
        && candidate.website == target.website;
    name_matches && website_matches
}

/// Verifies a Checkout satisfies an Open Checkout Mandate's constraints.
/// Returns violation messages; empty means the checkout is compliant.
pub fn check_checkout_constraints(
    open_mandate: &OpenCheckoutMandate,
    checkout: &CheckoutForConstraints,
) -> Vec<String> {
    let mut violations = Vec::new();

    for constraint in &open_mandate.constraints {
        match constraint {
            Constraint::AllowedMerchants { allowed } => match &checkout.merchant {
                None => violations.push("Missing merchant in checkout".to_string()),
                Some(merchant) => {
                    if !allowed.iter().any(|a| merchant_matches(a, merchant)) {
                        violations.push(format!("Merchant {} not in allowed list", merchant.name));
                    }
                }
            },
            Constraint::LineItems { items } => {
                if checkout.line_items.is_empty() {
                    violations
                        .push("Empty cart does not satisfy line_items constraint".to_string());
                } else {
                    violations.extend(evaluate_line_items(&checkout.line_items, items));
                }
            }
        }
    }

    violations
}

const INF: i64 = 1_000_000_000_000_000;

/// Matches cart line items against requirements, where a requirement may
/// accept several SKUs and a SKU may satisfy several requirements. Most
/// carts resolve via simple greedy elimination; ambiguous overlaps fall
/// back to max-flow (mirrors AP2's own `max_flow_helper.py`, whose
/// `dinic` mode this ports).
fn evaluate_line_items(
    checkout_items: &[CheckoutLineItem],
    requirements: &[ap2_core::LineItemRequirement],
) -> Vec<String> {
    let mut cart_qty: HashMap<&str, i64> = HashMap::new();
    let mut sku_order: Vec<&str> = Vec::new();
    for li in checkout_items {
        let sku = li.item.id.as_str();
        if !cart_qty.contains_key(sku) {
            sku_order.push(sku);
        }
        *cart_qty.entry(sku).or_insert(0) += li.quantity as i64;
    }

    let req_acceptable: Vec<HashSet<&str>> = requirements
        .iter()
        .map(|r| r.acceptable_items.iter().map(|i| i.id.as_str()).collect())
        .collect();
    // An empty acceptable_items list means "any SKU accepted".
    let req_is_wildcard: Vec<bool> = requirements
        .iter()
        .map(|r| r.acceptable_items.is_empty())
        .collect();

    let has_wildcard = req_is_wildcard.iter().any(|&w| w);
    let mut all_acceptable: HashSet<&str> = HashSet::new();
    if !has_wildcard {
        for acc in &req_acceptable {
            all_acceptable.extend(acc.iter());
        }
    }

    let mut violations = Vec::new();
    for &sku in &sku_order {
        if cart_qty[sku] <= 0 {
            continue;
        }
        if !has_wildcard && !all_acceptable.contains(sku) {
            violations.push(format!(
                "Item {sku} not in any requirement's acceptable items"
            ));
        }
    }
    if !violations.is_empty() {
        return violations;
    }

    let mut req_remaining: Vec<i64> = requirements
        .iter()
        .map(|r| r.quantity.get() as i64)
        .collect();
    let mut complex_skus: Vec<&str> = Vec::new();
    let mut unassigned_items: Vec<String> = Vec::new();

    for &sku in &sku_order {
        let qty = cart_qty[sku];
        if qty <= 0 {
            continue;
        }
        let mut match_idx: Option<usize> = None;
        let mut is_complex = false;
        for j in 0..requirements.len() {
            if req_is_wildcard[j] || req_acceptable[j].contains(sku) {
                if match_idx.is_none() {
                    match_idx = Some(j);
                } else {
                    is_complex = true;
                    break;
                }
            }
        }
        match match_idx {
            Some(j) if !is_complex => {
                let assigned = qty.min(req_remaining[j]);
                req_remaining[j] -= assigned;
                let leftover = qty - assigned;
                if leftover > 0 {
                    unassigned_items.push(format!("{sku} ({leftover})"));
                }
            }
            _ => complex_skus.push(sku),
        }
    }

    if !complex_skus.is_empty() {
        let (max_flow, source_residual) = line_items_max_flow(
            &complex_skus,
            &cart_qty,
            requirements.len(),
            &req_acceptable,
            &req_is_wildcard,
            &req_remaining,
        );
        let total_complex_cart: i64 = complex_skus.iter().map(|s| cart_qty[s]).sum();
        if max_flow < total_complex_cart {
            for (i, &sku) in complex_skus.iter().enumerate() {
                let remaining = *source_residual.get(&(1 + i)).unwrap_or(&0);
                if remaining > 0 {
                    unassigned_items.push(format!("{sku} ({remaining})"));
                }
            }
        }
    }

    if !unassigned_items.is_empty() {
        violations.push(format!(
            "Cannot satisfy line item constraints: {} could not be assigned to any requirement slot",
            unassigned_items.join(", ")
        ));
    }

    violations
}

/// Builds a sparse bipartite flow network (source -> SKUs -> requirements
/// -> sink) and runs it. Returns (max flow, source node's residual caps),
/// which is all the caller needs to see which SKUs stayed unassigned.
fn line_items_max_flow(
    sku_list: &[&str],
    cart_qty: &HashMap<&str, i64>,
    req_count: usize,
    req_acceptable: &[HashSet<&str>],
    req_is_wildcard: &[bool],
    req_remaining_capacity: &[i64],
) -> (i64, HashMap<usize, i64>) {
    let s_count = sku_list.len();
    let n = 1 + s_count + req_count + 1;
    let source = 0;
    let sink = n - 1;
    let sku_offset = 1;
    let req_offset = sku_offset + s_count;

    let mut graph: Vec<HashMap<usize, i64>> = vec![HashMap::new(); n];
    for (i, &sku) in sku_list.iter().enumerate() {
        graph[source].insert(sku_offset + i, cart_qty[sku]);
        graph[sku_offset + i].insert(source, 0);
    }
    for (i, &sku) in sku_list.iter().enumerate() {
        for j in 0..req_count {
            if req_is_wildcard[j] || req_acceptable[j].contains(sku) {
                graph[sku_offset + i].insert(req_offset + j, INF);
                graph[req_offset + j].insert(sku_offset + i, 0);
            }
        }
    }
    for j in 0..req_count {
        graph[req_offset + j].insert(sink, req_remaining_capacity[j]);
        graph[sink].insert(req_offset + j, 0);
    }

    let flow = dinic(&mut graph, source, sink, n);
    (flow, graph[source].clone())
}

fn dinic(graph: &mut [HashMap<usize, i64>], source: usize, sink: usize, n: usize) -> i64 {
    let adj: Vec<Vec<usize>> = graph.iter().map(|m| m.keys().copied().collect()).collect();
    let mut total = 0i64;
    while let Some(level) = bfs_level(graph, &adj, source, sink, n) {
        let mut it = vec![0usize; n];
        loop {
            let pushed = dfs_block(graph, &adj, source, sink, INF, &level, &mut it);
            if pushed == 0 {
                break;
            }
            total += pushed;
        }
    }
    total
}

fn bfs_level(
    graph: &[HashMap<usize, i64>],
    adj: &[Vec<usize>],
    source: usize,
    sink: usize,
    n: usize,
) -> Option<Vec<i64>> {
    let mut level = vec![-1i64; n];
    level[source] = 0;
    let mut queue = VecDeque::from([source]);
    while let Some(u) = queue.pop_front() {
        for &v in &adj[u] {
            if level[v] == -1 && graph[u][&v] > 0 {
                level[v] = level[u] + 1;
                queue.push_back(v);
            }
        }
    }
    (level[sink] != -1).then_some(level)
}

fn dfs_block(
    graph: &mut [HashMap<usize, i64>],
    adj: &[Vec<usize>],
    u: usize,
    sink: usize,
    pushed: i64,
    level: &[i64],
    it: &mut [usize],
) -> i64 {
    if u == sink || pushed == 0 {
        return pushed;
    }
    let mut total_pushed = 0i64;
    let mut pushed = pushed;
    while it[u] < adj[u].len() {
        let v = adj[u][it[u]];
        let cap = graph[u][&v];
        if level[v] == level[u] + 1 && cap > 0 {
            let d = dfs_block(graph, adj, v, sink, pushed.min(cap), level, it);
            if d > 0 {
                *graph[u].get_mut(&v).unwrap() -= d;
                *graph[v].get_mut(&u).unwrap() += d;
                total_pushed += d;
                pushed -= d;
                if pushed == 0 {
                    break;
                }
            }
        }
        it[u] += 1;
    }
    total_pushed
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap2_core::AcceptableItem;
    use std::num::NonZeroU32;

    fn item(sku: &str, qty: u32) -> CheckoutLineItem {
        CheckoutLineItem {
            item: CheckoutItemRef { id: sku.into() },
            quantity: qty,
        }
    }

    fn requirement(id: &str, acceptable: &[&str], qty: u32) -> ap2_core::LineItemRequirement {
        ap2_core::LineItemRequirement {
            id: id.into(),
            acceptable_items: acceptable
                .iter()
                .map(|sku| AcceptableItem {
                    id: (*sku).into(),
                    title: (*sku).into(),
                })
                .collect(),
            quantity: NonZeroU32::new(qty).unwrap(),
        }
    }

    #[test]
    fn satisfies_a_simple_unambiguous_requirement() {
        let cart = [item("SKU-A", 2)];
        let reqs = [requirement("r1", &["SKU-A"], 2)];
        assert!(evaluate_line_items(&cart, &reqs).is_empty());
    }

    #[test]
    fn rejects_an_item_not_in_any_requirement() {
        let cart = [item("SKU-Z", 1)];
        let reqs = [requirement("r1", &["SKU-A"], 1)];
        let violations = evaluate_line_items(&cart, &reqs);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("not in any requirement's acceptable items"));
    }

    // This checks that every cart item can be *placed* into some
    // requirement's capacity -- it does not check a requirement's minimum
    // is met. A cart with less than the requirement's quantity is fine.
    #[test]
    fn under_quantity_cart_is_not_a_violation() {
        let cart = [item("SKU-A", 1)];
        let reqs = [requirement("r1", &["SKU-A"], 2)];
        assert!(evaluate_line_items(&cart, &reqs).is_empty());
    }

    #[test]
    fn rejects_excess_quantity_in_the_simple_case() {
        let cart = [item("SKU-A", 3)];
        let reqs = [requirement("r1", &["SKU-A"], 2)];
        let violations = evaluate_line_items(&cart, &reqs);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("SKU-A (1)"));
    }

    #[test]
    fn wildcard_requirement_accepts_any_sku() {
        let cart = [item("SKU-ANYTHING", 3)];
        let reqs = [requirement("r1", &[], 3)];
        assert!(evaluate_line_items(&cart, &reqs).is_empty());
    }

    /// Two requirements both accept SKU-2: satisfying both needs real
    /// max-flow, not the greedy single-match fast path.
    #[test]
    fn satisfies_an_ambiguous_overlap_via_max_flow() {
        let cart = [item("SKU-2", 2)];
        let reqs = [
            requirement("r1", &["SKU-1", "SKU-2"], 1),
            requirement("r2", &["SKU-2"], 1),
        ];
        assert!(evaluate_line_items(&cart, &reqs).is_empty());
    }

    #[test]
    fn rejects_an_ambiguous_overlap_that_exceeds_total_capacity() {
        let cart = [item("SKU-2", 3)];
        let reqs = [
            requirement("r1", &["SKU-1", "SKU-2"], 1),
            requirement("r2", &["SKU-2"], 1),
        ];
        let violations = evaluate_line_items(&cart, &reqs);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("SKU-2 (1)"));
    }

    #[test]
    fn allowed_merchants_rejects_a_merchant_not_in_the_list() {
        let mandate: OpenCheckoutMandate = serde_json::from_value(serde_json::json!({
            "vct": "mandate.checkout.open.1",
            "constraints": [
                {"type": "checkout.allowed_merchants", "allowed": [{"id": "m-1", "name": "Good"}]},
            ],
            "cnf": {},
        }))
        .unwrap();
        let checkout = CheckoutForConstraints {
            merchant: Some(Merchant {
                id: "m-evil".into(),
                name: "Evil".into(),
                website: None,
            }),
            line_items: vec![],
        };

        let violations = check_checkout_constraints(&mandate, &checkout);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("not in allowed list"));
    }
}
