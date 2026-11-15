const HUMAN_CONFIRMATION_PREFIXES: &[&str] = &[
    "refund",
    "delete",
    "purge",
    "destroy",
    "reinstall",
    "extend",
    "grant",
    "assign",
    "revoke",
    "credit",
    "adjust",
    "transfer",
    "create_token",
    "rotate",
    "set_role",
    "ban",
    "suspend",
];

pub const WORKLOAD_CONTROL_TOOLS: &[&str] = &[
    "start_vm",
    "stop_vm",
    "restart_vm",
    "start_app_deployment",
    "stop_app_deployment",
];

pub fn requires_human_confirmation(tool: &str) -> bool {
    HUMAN_CONFIRMATION_PREFIXES
        .iter()
        .any(|p| tool.starts_with(p) || tool.contains(&format!("_{p}")))
}

pub fn refuse_if_human_only(tool: &str) -> anyhow::Result<()> {
    if requires_human_confirmation(tool) {
        anyhow::bail!(
            "{tool} changes money, access or data, so it has to be done by a human and is never run by the agent"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{live_chat_tools, public_tools, support_tools};

    #[test]
    fn destructive_and_financial_names_need_a_human() {
        for t in [
            "refund_vm",
            "delete_vm",
            "extend_vm",
            "purge_vm",
            "grant_role",
            "adjust_credit",
        ] {
            assert!(requires_human_confirmation(t), "{t}");
            assert!(refuse_if_human_only(t).is_err());
        }
    }

    #[test]
    fn read_and_workload_tools_do_not() {
        for t in ["get_my_account", "list_my_vms", "start_vm", "restart_vm"] {
            assert!(!requires_human_confirmation(t), "{t}");
        }
    }

    #[test]
    fn no_tool_set_offers_a_human_only_tool() {
        for set in [public_tools(), support_tools(), live_chat_tools()] {
            for tool in set {
                assert!(
                    !requires_human_confirmation(&tool.name),
                    "{} must not be offered to the model",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn untrusted_text_channels_cannot_change_anything() {
        for set in [public_tools(), support_tools()] {
            for tool in set {
                assert!(
                    !WORKLOAD_CONTROL_TOOLS.contains(&tool.name.as_str()),
                    "{} must not be offered on a channel driven by third-party text",
                    tool.name
                );
            }
        }
    }
}
