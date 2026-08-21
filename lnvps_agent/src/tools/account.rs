//! Tools that read the requesting customer's own account.
//!
//! None takes an identifier: the executor is already bound to one user, so
//! there is nothing for the model to name — and therefore nothing for it to
//! get wrong or be talked into.

use async_openai::types::FunctionObject;

use super::nullary;

pub fn get_my_account() -> FunctionObject {
    nullary(
        "get_my_account",
        "Get the current user's account information: billing details, contact preferences, email verification status, and NWC auto-renewal status.",
    )
}

pub fn list_my_ssh_keys() -> FunctionObject {
    nullary(
        "list_my_ssh_keys",
        "List the SSH keys saved on the current user's account, by name and date added. Use this when a customer cannot log into a VM and needs to know which key was installed on it — the key material itself is never returned.",
    )
}

pub fn list_my_payment_methods() -> FunctionObject {
    nullary(
        "list_my_payment_methods",
        "List the payment methods saved on the current user's account: provider, card brand, last four digits, expiry and which is the default. Use this for questions about automatic renewal failing or an expired card. Full card and processor details are never returned.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Account tools must stay argument-free: an identifier here would be a
    /// value the model invents.
    #[test]
    fn account_tools_take_no_arguments() {
        for spec in [
            get_my_account(),
            list_my_ssh_keys(),
            list_my_payment_methods(),
        ] {
            let params = spec.parameters.expect("parameters");
            assert!(params["properties"].as_object().unwrap().is_empty());
            assert!(params.get("required").is_none());
        }
    }
}
