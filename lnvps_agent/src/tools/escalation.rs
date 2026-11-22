use async_openai::types::FunctionObject;
use serde_json::json;

use super::tool;

pub fn escalate_to_support() -> FunctionObject {
    tool(
        "escalate_to_support",
        "Email this customer's problem to the LNVPS support team on their behalf, so staff can follow up by email and the customer does not have to retell it. Use it for what only a human can do: platform faults, a VM disabled by staff, payments you cannot see, refunds, anything that moves money or destroys data, or when diagnostics cannot find the cause. Ask the customer first if they want it sent. The email goes to the account email on file. At most one email per conversation per 24 hours unless a new VM is involved. Never put passwords, keys or seed phrases in any field.",
        json!({
            "type": "object",
            "properties": {
                "reason": { "type": "string", "description": "Short reason, under 60 characters, used in the subject" },
                "summary": { "type": "string", "description": "What the customer needs and what is going wrong, in a few sentences" },
                "vm_ids": {
                    "type": "array",
                    "items": { "type": "integer" },
                    "description": "Ids of the customer's VMs involved, if any"
                },
                "checked": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "One short line per check already done and what it showed"
                }
            },
            "required": ["reason", "summary"]
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_no_user_or_address_arguments() {
        let params = escalate_to_support().parameters.expect("parameters");
        let properties = params["properties"].as_object().unwrap();
        for forbidden in ["user_id", "email", "to", "address", "reply_to"] {
            assert!(!properties.contains_key(forbidden), "{forbidden}");
        }
    }
}
