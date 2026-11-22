use std::collections::{HashMap, HashSet};

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use lnvps_db::AgentMessageRole;

use super::DbToolExecutor;
use crate::escalation::{EscalationRequest, recent_messages_limit, within_window};

const MAX_VM_IDS: usize = 10;
const MAX_CHECKED_ARGS: usize = 12;
const MAX_TOOL_RESULTS: usize = 8;
const TOOL_RESULT_CHARS: usize = 160;

fn text_arg(args: &HashMap<String, Value>, key: &str) -> Result<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("{} required", key))
}

fn parse_vm_ids(args: &HashMap<String, Value>) -> Vec<u64> {
    let mut ids: Vec<u64> = args
        .get("vm_ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
        .unwrap_or_default();
    ids.sort_unstable();
    ids.dedup();
    ids.truncate(MAX_VM_IDS);
    ids
}

fn parse_stored_ids(stored: Option<&str>) -> HashSet<u64> {
    stored
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

struct Transcript {
    customer_messages: Vec<String>,
    tool_results: Vec<String>,
}

impl DbToolExecutor {
    pub(super) async fn escalate_to_support(&self, args: &HashMap<String, Value>) -> Result<Value> {
        let user_id = self.require_user()?;
        let Some(escalation) = self.escalation.as_ref() else {
            bail!(
                "Handing a chat to support by email is not enabled here. Point the customer at support@lnvps.net."
            );
        };
        let reason = text_arg(args, "reason")?;
        let summary = text_arg(args, "summary")?;
        let vm_ids = parse_vm_ids(args);
        for vm_id in &vm_ids {
            let vm = self.db.get_vm(*vm_id).await?;
            if vm.user_id != user_id {
                bail!("VM {} does not belong to you", vm_id);
            }
        }

        let user = self.db.get_user(user_id).await?;
        if user.email.is_empty() {
            bail!(
                "This account has no email on file, so support could not reply. Ask the customer to add an email address to their account, or to write to support@lnvps.net themselves."
            );
        }

        let conversation = self
            .db
            .upsert_agent_conversation(&format!("user:{user_id}"), Some(user_id))
            .await?;
        let previous_ids = parse_stored_ids(conversation.escalation_vm_ids.as_deref());
        let something_new = vm_ids.iter().any(|id| !previous_ids.contains(id));
        if within_window(conversation.escalated_at, chrono::Utc::now()) && !something_new {
            return Ok(json!({
                "sent": false,
                "already_escalated": true,
                "reference": escalation.reference(conversation.id),
                "message": "This conversation was already emailed to support in the last 24 hours and nothing new has come up. Do not send it again. Tell the customer the reference and that the reply will come to their account email."
            }));
        }

        let transcript = self.escalation_transcript(conversation.id).await?;
        let mut checked: Vec<String> = args
            .get("checked")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .take(MAX_CHECKED_ARGS)
                    .collect()
            })
            .unwrap_or_default();
        checked.extend(transcript.tool_results);

        let request = EscalationRequest {
            conversation_id: conversation.id,
            previous_count: conversation.escalation_count,
            user_id,
            customer_email: user.email.as_str().to_string(),
            email_verified: user.email_verified,
            vm_ids: vm_ids.clone(),
            reason: reason.clone(),
            summary,
            checked,
            recent_customer_messages: transcript.customer_messages,
        };
        let mail = escalation.build(&request);
        escalation.sink.send(mail).await.map_err(|e| {
            log::error!("Escalation email for user {} failed: {}", user_id, e);
            anyhow!(
                "The email to support could not be sent. Say it was not sent and point the customer at support@lnvps.net."
            )
        })?;

        let vm_list = vm_ids
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        if let Err(e) = self
            .db
            .record_agent_escalation(conversation.id, &reason, &vm_list)
            .await
        {
            log::error!("Could not record escalation for user {}: {}", user_id, e);
        }

        Ok(json!({
            "sent": true,
            "reference": escalation.reference(conversation.id),
            "message": "Support has been emailed. Tell the customer the reference and that the reply will come to their account email. Do not state a response time."
        }))
    }

    async fn escalation_transcript(&self, conversation_id: u64) -> Result<Transcript> {
        let rows = self
            .db
            .list_agent_messages_after_watermark(conversation_id)
            .await?;
        let mut names: HashMap<String, String> = HashMap::new();
        for row in &rows {
            if row.role != AgentMessageRole::Assistant {
                continue;
            }
            let Some(raw) = row.tool_calls.as_deref() else {
                continue;
            };
            let calls: Vec<crate::conversation::StoredToolCall> =
                serde_json::from_slice(raw).unwrap_or_default();
            for call in calls {
                names.insert(call.id, call.name);
            }
        }
        let mut customer_messages: Vec<String> = rows
            .iter()
            .filter(|r| r.role == AgentMessageRole::User)
            .filter_map(|r| r.content.as_ref().map(|c| c.as_str().to_string()))
            .collect();
        let skip = customer_messages
            .len()
            .saturating_sub(recent_messages_limit());
        customer_messages.drain(..skip);

        let mut tool_results: Vec<String> = rows
            .iter()
            .filter(|r| r.role == AgentMessageRole::Tool)
            .filter_map(|r| {
                let name = names.get(r.tool_call_id.as_deref()?)?;
                let content = r.content.as_ref()?.as_str();
                let flat: String = content.split_whitespace().collect::<Vec<_>>().join(" ");
                let short: String = flat.chars().take(TOOL_RESULT_CHARS).collect();
                Some(format!("{name}: {short}"))
            })
            .collect();
        let skip = tool_results.len().saturating_sub(MAX_TOOL_RESULTS);
        tool_results.drain(..skip);
        Ok(Transcript {
            customer_messages,
            tool_results,
        })
    }
}
