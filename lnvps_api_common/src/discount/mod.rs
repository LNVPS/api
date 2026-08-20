//! Discount rule evaluation.
//!
//! A discount's eligibility **and** effect are a single CEL expression that
//! returns a decision map:
//!
//! ```text
//! {'percent': 10}
//! order.amount >= 5000 ? {'percent': 10} : {}
//! order.intervals >= 12 ? {'percent': 15} : order.intervals >= 6 ? {'percent': 10} : {}
//! order.amount >= 10000 ? {'amount': 500, 'currency': 'EUR'} : {}
//! ```
//!
//! CEL is not Turing-complete and performs no I/O, so evaluation always
//! terminates and cannot reach the network or the database. What a rule can
//! *see* is limited to [`DiscountContext`], and what it can *do* is limited to
//! [`DiscountDecision`], which is clamped in Rust — see
//! [`DiscountDecision::amount_off`].

mod context;
mod decision;
mod engine;
mod items;

pub use context::{DiscountContext, HistoryContext, OrderContext, UserContext};
pub use decision::DiscountDecision;
pub use engine::{
    AppliedDiscount, DiscountError, DiscountOrder, allocate_discount, discount_tax_lines,
};
pub use items::{OrderLineItem, OrderProduct};

use anyhow::{Context as _, Result, bail};
use cel::{Context, Program};
use log::warn;

/// Maximum accepted rule length, in bytes.
///
/// CEL always terminates, so this is not a runaway-execution guard; it stops a
/// pathological expression from being stored and re-parsed on every order.
pub const MAX_RULE_LEN: usize = 4096;

/// Compile a rule without executing it, for validation at the admin API
/// boundary. Returns the parse error so the admin UI can show it.
pub fn validate_rule(rule: &str) -> Result<()> {
    compile_rule(rule).map(|_| ())
}

/// Bounds-check and compile a rule into an executable program.
fn compile_rule(rule: &str) -> Result<Program> {
    if rule.len() > MAX_RULE_LEN {
        bail!("rule is too long ({} > {} bytes)", rule.len(), MAX_RULE_LEN);
    }
    if rule.trim().is_empty() {
        bail!("rule is empty");
    }
    Program::compile(rule).map_err(|e| anyhow::anyhow!("invalid CEL expression: {e}"))
}

/// Evaluate `rule` against `ctx` and return the clamped decision.
///
/// Errors on an invalid expression, a failed evaluation, or a result that is
/// not a decision map. Callers that price real orders should use
/// [`evaluate_rule_or_none`] so a broken rule cannot fail an order.
pub fn evaluate_rule(rule: &str, ctx: &DiscountContext) -> Result<DiscountDecision> {
    let program = compile_rule(rule)?;

    let mut cel_ctx = Context::default();
    cel_ctx
        .add_variable("order", &ctx.order)
        .context("failed to bind 'order'")?;
    cel_ctx
        .add_variable("user", &ctx.user)
        .context("failed to bind 'user'")?;
    cel_ctx
        .add_variable("history", &ctx.history)
        .context("failed to bind 'history'")?;
    cel_ctx.add_variable_from_value("now", ctx.now);

    let value = program
        .execute(&cel_ctx)
        .map_err(|e| anyhow::anyhow!("rule evaluation failed: {e}"))?;

    DiscountDecision::from_cel_value(&value)
}

/// Evaluate `rule`, treating any failure as "this discount does not apply".
///
/// Used on the pricing path: a discount that cannot be evaluated must never
/// stop a customer from paying, and must never be applied by accident either.
pub fn evaluate_rule_or_none(rule: &str, ctx: &DiscountContext) -> DiscountDecision {
    match evaluate_rule(rule, ctx) {
        Ok(d) => d,
        Err(e) => {
            warn!("Discount rule failed to evaluate, ignoring discount: {e}");
            DiscountDecision::none()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> DiscountContext {
        DiscountContext::sample()
    }

    #[test]
    fn flat_percent_rule() {
        let d = evaluate_rule("{'percent': 10}", &ctx()).unwrap();
        assert_eq!(d.percent, Some(10));
        assert_eq!(d.amount_off(10_000, "EUR").unwrap(), 1_000);
    }

    #[test]
    fn threshold_rule_applies_above_and_declines_below() {
        let rule = "order.amount >= 5000 ? {'percent': 10} : {}";
        let mut c = ctx();
        assert_eq!(evaluate_rule(rule, &c).unwrap().percent, Some(10));

        c.order.amount = 4_999;
        assert!(evaluate_rule(rule, &c).unwrap().is_empty());
    }

    #[test]
    fn tiered_rule_by_interval_count() {
        let rule =
            "order.intervals >= 12 ? {'percent': 15} : order.intervals >= 6 ? {'percent': 10} : {}";
        let mut c = ctx();
        c.order.intervals = 12;
        assert_eq!(evaluate_rule(rule, &c).unwrap().percent, Some(15));
        c.order.intervals = 6;
        assert_eq!(evaluate_rule(rule, &c).unwrap().percent, Some(10));
        c.order.intervals = 1;
        assert!(evaluate_rule(rule, &c).unwrap().is_empty());
    }

    #[test]
    fn fixed_amount_rule() {
        let d = evaluate_rule(
            "order.amount >= 10000 ? {'amount': 500, 'currency': 'EUR'} : {}",
            &ctx(),
        )
        .unwrap();
        assert_eq!(d.amount, Some(500));
        assert_eq!(d.amount_off(10_000, "EUR").unwrap(), 500);
    }

    #[test]
    fn rules_can_read_every_context_variable() {
        let c = ctx();
        for rule in [
            "user.country == 'IRL' ? {'percent': 5} : {}",
            "user.id == 42 ? {'percent': 5} : {}",
            "order.is_new ? {'percent': 5} : {}",
            "order.currency == 'EUR' ? {'percent': 5} : {}",
            "order.interval_type == 'month' ? {'percent': 5} : {}",
            "order.items[0].type == 'vm' ? {'percent': 5} : {}",
            "order.items.exists(i, i.template_id == 1) ? {'percent': 5} : {}",
            "order.items.all(i, i.type == 'vm' && i.cpu >= 2) ? {'percent': 5} : {}",
            "size(order.items) == 1 ? {'percent': 5} : {}",
            "order.items[0].name == 'VPS' ? {'percent': 5} : {}",
            "order.items.exists(i, i.region_id == 1) ? {'percent': 5} : {}",
            "history.orders == 0 ? {'percent': 5} : {}",
            "now > 0 ? {'percent': 5} : {}",
        ] {
            assert_eq!(
                evaluate_rule(rule, &c).unwrap().percent,
                Some(5),
                "rule did not apply: {rule}"
            );
        }
    }

    #[test]
    fn a_custom_build_is_told_apart_by_a_null_template() {
        let mut c = ctx();
        c.order.items = vec![OrderLineItem {
            product: match OrderLineItem::sample_vm().product {
                crate::OrderProduct::Vm {
                    vm_id,
                    cpu,
                    memory,
                    disk_size,
                    disk_type,
                    ip4_count,
                    ip6_count,
                    region_id,
                    ..
                } => crate::OrderProduct::Vm {
                    vm_id,
                    template_id: None,
                    region_id,
                    cpu,
                    memory,
                    disk_size,
                    disk_type,
                    ip4_count,
                    ip6_count,
                },
                other => other,
            },
            ..OrderLineItem::sample_vm()
        }];
        assert_eq!(
            evaluate_rule(
                "order.items.exists(i, i.type == 'vm' && i.template_id == null) ? {'percent': 5} : {}",
                &c
            )
            .unwrap()
            .percent,
            Some(5)
        );
    }

    #[test]
    fn over_percent_rule_is_clamped_not_honoured() {
        let d = evaluate_rule("{'percent': 900}", &ctx()).unwrap();
        assert_eq!(d.percent, Some(100));
        assert_eq!(d.amount_off(10_000, "EUR").unwrap(), 10_000);
    }

    #[test]
    fn rejects_syntax_errors_and_unknown_variables() {
        assert!(evaluate_rule("{'percent': ", &ctx()).is_err());
        assert!(evaluate_rule("secrets.api_key", &ctx()).is_err());
        assert!(evaluate_rule("order.password", &ctx()).is_err());
    }

    #[test]
    fn rejects_runtime_errors() {
        assert!(evaluate_rule("{'percent': 1 / 0}", &ctx()).is_err());
    }

    #[test]
    fn rejects_non_decision_results() {
        assert!(evaluate_rule("10", &ctx()).is_err());
        assert!(evaluate_rule("'10%'", &ctx()).is_err());
        assert!(evaluate_rule("true", &ctx()).is_err());
        // an explicit false is the documented "does not apply" result
        assert!(evaluate_rule("false", &ctx()).unwrap().is_empty());
    }

    #[test]
    fn validate_rule_bounds_input() {
        assert!(validate_rule("{'percent': 10}").is_ok());
        assert!(validate_rule("").is_err());
        assert!(validate_rule("   ").is_err());
        assert!(validate_rule(&"a".repeat(MAX_RULE_LEN + 1)).is_err());
        assert!(evaluate_rule(&"1".repeat(MAX_RULE_LEN + 1), &ctx()).is_err());
    }

    #[test]
    fn deeply_nested_expression_terminates() {
        let rule = format!(
            "{}{{'percent': 1}}{}",
            "true ? ".repeat(200),
            " : {}".repeat(200)
        );
        let d = evaluate_rule(&rule, &ctx());
        // Either it evaluates or the parser rejects it; what matters is that it
        // returns rather than hanging.
        assert!(d.is_ok() || d.is_err());
    }

    #[test]
    fn evaluate_rule_or_none_swallows_failures() {
        assert!(evaluate_rule_or_none("not valid cel {{", &ctx()).is_empty());
        assert!(evaluate_rule_or_none("10", &ctx()).is_empty());
        assert_eq!(
            evaluate_rule_or_none("{'percent': 10}", &ctx()).percent,
            Some(10)
        );
    }
}
