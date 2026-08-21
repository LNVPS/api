//! Tools for the two partner programmes: referrals and marketplace node
//! operators.
//!
//! Both are opt-in enrolments, so the common answer is "not enrolled" — which
//! the executor returns as data rather than an error, so the model can say so
//! rather than reporting a failure it cannot explain.

use async_openai::types::FunctionObject;

use super::nullary;

pub fn get_my_referral() -> FunctionObject {
    nullary(
        "get_my_referral",
        "Get the current user's referral enrolment: their referral code, payout mode and address, payout threshold, and commission rate. A null commission rate means the company default applies — say that rather than quoting a number. Returns enrolled=false when the account has no referral code.",
    )
}

pub fn list_referral_usage() -> FunctionObject {
    nullary(
        "list_referral_usage",
        "List what the current user's referral code has earned: each referred VM's first paid invoice with the commission rate applied, totals per currency, how many referred VMs never paid, and the payout history. Amounts are in minor units (cents / millisats).",
    )
}

pub fn get_my_marketplace_operator() -> FunctionObject {
    nullary(
        "get_my_marketplace_operator",
        "Get the current user's marketplace node-operator enrolment and their nodes: each node's approval status, trust tier, when it was last seen, and its most recent health check. Use this for operators asking why a node is not receiving VMs — a node that is not 'approved', or that failed its last health check, will not be placed on. Returns enrolled=false for a normal customer.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partner_tools_take_no_arguments() {
        for spec in [
            get_my_referral(),
            list_referral_usage(),
            get_my_marketplace_operator(),
        ] {
            let params = spec.parameters.expect("parameters");
            assert!(params["properties"].as_object().unwrap().is_empty());
        }
    }

    /// The "no enrolment" case is the common one, so the specs must tell the
    /// model that a false is an answer and not a fault.
    #[test]
    fn enrolment_tools_document_the_not_enrolled_case() {
        for spec in [get_my_referral(), get_my_marketplace_operator()] {
            assert!(spec.description.unwrap().contains("enrolled=false"));
        }
    }
}
