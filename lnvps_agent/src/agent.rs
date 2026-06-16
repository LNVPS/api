use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;

use crate::api_client::ApiClient;
use crate::conversation::{ConversationEntry, ConversationStore, SenderConversation};
use crate::settings::Settings;

/// Executes tool calls by invoking the LNVPS APIs.
/// Each instance is scoped to a single user — all tools operate
/// within that user's context without taking user identifiers.
#[async_trait]
pub trait ToolExecutor: Send + Sync {
    async fn execute(&self, name: &str, arguments: &str) -> Result<String>;
}

/// The actual tool executor backed by the API client, scoped to one user.
pub struct LnvpsToolExecutor {
    api: Arc<ApiClient>,
    user_id: u64,
}

impl LnvpsToolExecutor {
    pub fn new(api: Arc<ApiClient>, user_id: u64) -> Self {
        Self { api, user_id }
    }

    async fn check_vm_ownership(&self, vm_id: u64) -> Result<()> {
        let vm = self.api.admin_get_vm(vm_id).await?;
        let owner = vm["user_id"]
            .as_u64()
            .ok_or_else(|| anyhow!("VM {} has no user_id field", vm_id))?;
        if owner != self.user_id {
            bail!(
                "VM {} does not belong to the current user (owner is {})",
                vm_id,
                owner
            );
        }
        Ok(())
    }
}

#[async_trait]
impl ToolExecutor for LnvpsToolExecutor {
    async fn execute(&self, name: &str, arguments: &str) -> Result<String> {
        let args: HashMap<String, serde_json::Value> =
            serde_json::from_str(arguments).unwrap_or_default();

        let uid = self.user_id;

        match name {
            "get_my_account" => {
                let user = self.api.admin_get_user(uid).await?;
                Ok(serde_json::to_string_pretty(&user)?)
            }

            "list_my_vms" => {
                let vms = self.api.admin_list_vms(Some(uid), None).await?;
                Ok(serde_json::to_string_pretty(&vms)?)
            }

            "get_vm_details" => {
                let vm_id = args
                    .get("vm_id")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow!("vm_id required"))?;
                self.check_vm_ownership(vm_id).await?;
                let vm = self.api.admin_get_vm(vm_id).await?;
                Ok(serde_json::to_string_pretty(&vm)?)
            }

            "list_vm_payments" => {
                let vm_id = args
                    .get("vm_id")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow!("vm_id required"))?;
                self.check_vm_ownership(vm_id).await?;
                let payments = self.api.admin_list_vm_payments(vm_id).await?;
                Ok(serde_json::to_string_pretty(&payments)?)
            }

            "list_vm_history" => {
                let vm_id = args
                    .get("vm_id")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow!("vm_id required"))?;
                self.check_vm_ownership(vm_id).await?;
                let history = self.api.admin_list_vm_history(vm_id).await?;
                Ok(serde_json::to_string_pretty(&history)?)
            }

            "extend_vm" => {
                let vm_id = args
                    .get("vm_id")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow!("vm_id required"))?;
                self.check_vm_ownership(vm_id).await?;
                let days = args
                    .get("days")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow!("days required"))?;
                let rsp = self.api.admin_extend_vm(vm_id, days).await?;
                Ok(serde_json::to_string_pretty(&rsp)?)
            }

            "refund_vm" => {
                let vm_id = args
                    .get("vm_id")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow!("vm_id required"))?;
                self.check_vm_ownership(vm_id).await?;
                let rsp = self.api.admin_refund_vm(vm_id).await?;
                Ok(serde_json::to_string_pretty(&rsp)?)
            }

            "delete_vm" => {
                let vm_id = args
                    .get("vm_id")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow!("vm_id required"))?;
                self.check_vm_ownership(vm_id).await?;
                let rsp = self.api.admin_delete_vm(vm_id).await?;
                Ok(serde_json::to_string_pretty(&rsp)?)
            }

            "list_regions" => {
                let regions = self.api.admin_list_regions().await?;
                Ok(serde_json::to_string_pretty(&regions)?)
            }

            _ => bail!("Unknown tool: {}", name),
        }
    }
}

/// Public tool executor for non-customer requests.
/// Only exposes read-only endpoints that don't require authentication.
pub struct PublicToolExecutor {
    api: Arc<ApiClient>,
}

impl PublicToolExecutor {
    pub fn new(api: Arc<ApiClient>) -> Self {
        Self { api }
    }
}

#[async_trait]
impl ToolExecutor for PublicToolExecutor {
    async fn execute(&self, name: &str, _arguments: &str) -> Result<String> {
        match name {
            "list_regions" => {
                let regions = self.api.admin_list_regions().await?;
                Ok(serde_json::to_string_pretty(&regions)?)
            }
            "list_templates" => {
                let templates = self.api.admin_list_templates().await?;
                Ok(serde_json::to_string_pretty(&templates)?)
            }
            "list_os_images" => {
                let images = self.api.admin_list_os_images().await?;
                Ok(serde_json::to_string_pretty(&images)?)
            }
            _ => bail!("Unknown tool: {}", name),
        }
    }
}

fn general_system_message() -> String {
    r#"You are the LNVPS support agent, helping potential customers and the general public with
questions about LNVPS VPS hosting services.

The sender has not been identified as an existing LNVPS customer, but you have access to
the following tools to help answer their questions:
- list_regions — see all available hosting regions
- list_templates — see all available VM plans with specs and pricing
- list_os_images — see all available operating system images

Use these tools to give accurate, up-to-date answers about pricing, available plans,
regions, and OS options. Never guess or fabricate data.

If the person is an existing customer and needs account-specific help, ask them to
send their support request from the email address registered on their LNVPS account,
or include their nostr pubkey (64 hex characters) in the email so you can look up
their account.

Be friendly, professional, and concise."#
    .to_string()
}

/// The AI support agent that handles a support conversation
pub struct SupportAgent {
    api: Arc<ApiClient>,
    settings: Settings,
    store: Arc<dyn ConversationStore>,
    /// Maximum conversation exchanges to retain per sender (before compaction).
    max_history: usize,
}

impl SupportAgent {
    pub fn new(api: Arc<ApiClient>, settings: Settings, store: Arc<dyn ConversationStore>) -> Self {
        Self {
            api,
            settings,
            store,
            max_history: 10,
        }
    }

    fn openai_client(&self) -> async_openai::Client<async_openai::config::OpenAIConfig> {
        use async_openai::Client;
        use async_openai::config::OpenAIConfig;
        let mut config = OpenAIConfig::new().with_api_base(&self.settings.openai.base_url);
        if let Some(ref key) = self.settings.openai.api_key {
            config = config.with_api_key(key);
        }
        Client::with_config(config)
    }

    fn system_message(&self, user_pubkey: &str, account: &serde_json::Value) -> String {
        let account_pretty = serde_json::to_string_pretty(account).unwrap_or_default();

        self.settings.system_prompt.clone().unwrap_or_else(|| {
            format!(
                r#"You are the LNVPS support agent. You help customers with their VPS hosting
accounts, virtual machines, payments, and billing.

Current user context:
- Nostr pubkey: {user_pubkey}
- Account info: {account_pretty}

All your tools are automatically scoped to this user — you do NOT need to pass
pubkey or user_id. Just call get_my_account or list_my_vms directly to see
their data. You can manage only this user's VMs and account.

Guidelines:
1. Be friendly and professional. The user may be frustrated — be empathetic.
2. Use list_my_vms first to see what VMs the user has, then get_vm_details
   for specifics.
3. Check list_vm_payments to understand billing issues, and list_vm_history
   for activity logs.
4. Be VERY careful with destructive actions (refund, delete, extend_vm).
   Always confirm verbally with the user before executing them — tell them
   exactly what will happen and ask for explicit confirmation.
5. If you don't have enough info, ask the customer for more details.
6. When presenting payment data, always include amounts, currencies, dates,
   and paid/unpaid status.
7. If a VM is expired, check payment history to see what happened.
8. For connectivity issues, check VM details for IP assignments.
9. NEVER fabricate data. Only report what your tools actually return.
10. If a tool call fails, explain the error honestly and suggest next steps.

LNVPS product info:
- VMs are provisioned on Proxmox and LibVirt hypervisors
- Payments via Lightning Network (Bitcoin) or fiat (Revolut, Stripe, PayPal)
- VMs auto-expire if not renewed
- Customers can manage SSH keys, upgrade specs, reinstall OS images, and
  access console via WebSocket
- Custom VM templates are available in regions that support them"#
            )
        })
    }

    /// Build the messages vec with system prompt, summary block, and history entries.
    async fn build_messages_with_history(
        &self,
        messages: &mut Vec<async_openai::types::ChatCompletionRequestMessage>,
        sender_id: &str,
        system_prompt: String,
    ) {
        use async_openai::types::{
            ChatCompletionRequestAssistantMessage,
            ChatCompletionRequestUserMessageArgs,
            ChatCompletionRequestSystemMessageArgs,
        };

        let conv = self.store.load(sender_id).await;

        // Inject the summary as a memory block before the main system prompt
        let full_system = if let Some(ref summary) = conv.summary {
            format!(
                r#"{system_prompt}

<MEMORY>
{summary}
</MEMORY>

The above is your accumulated knowledge from all prior conversations with this sender.
Use it to provide continuity — reference past issues, remember what was tried, and
avoid repeating yourself."#
            )
        } else {
            system_prompt
        };

        messages.push(
            ChatCompletionRequestSystemMessageArgs::default()
                .content(full_system)
                .build()
                .unwrap()
                .into(),
        );

        // Inject recent raw exchanges after the system prompt
        for entry in &conv.entries {
            messages.push(
                ChatCompletionRequestUserMessageArgs::default()
                    .content(entry.user_message.clone())
                    .build()
                    .unwrap()
                    .into(),
            );
            messages.push(
                ChatCompletionRequestAssistantMessage {
                    content: Some(
                        async_openai::types::ChatCompletionRequestAssistantMessageContent::Text(
                            entry.agent_response.clone(),
                        ),
                    ),
                    ..Default::default()
                }
                .into(),
            );
        }
    }

    /// Record a conversation exchange for a sender.
    async fn record_exchange(&self, sender_id: &str, user_msg: &str, agent_resp: &str) {
        let entry = ConversationEntry {
            user_message: user_msg.to_string(),
            agent_response: agent_resp.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
        };
        if let Err(e) = self.store.append(sender_id, entry).await {
            log::error!("Failed to record conversation for {}: {}", sender_id, e);
            return;
        }

        // Auto-compact when entries exceed max_history
        let conv = self.store.load(sender_id).await;
        if conv.entries.len() > self.max_history {
            log::info!(
                "Conversation for {} has {} entries, triggering compaction",
                sender_id,
                conv.entries.len()
            );
            if let Err(e) = self.compact(sender_id).await {
                log::error!("Failed to compact conversation for {}: {}", sender_id, e);
            }
        }
    }

    /// Compact the conversation history for a sender using the LLM.
    ///
    /// Summarises all raw entries into a persistent `<MEMORY>` block that
    /// is injected into the system prompt on future requests. Clears the
    /// raw entries after compaction so only the summary carries forward.
    pub async fn compact(&self, sender_id: &str) -> Result<()> {
        use async_openai::types::{
            ChatCompletionRequestMessage,
            ChatCompletionRequestSystemMessageArgs,
            ChatCompletionRequestUserMessageArgs,
            CreateChatCompletionRequestArgs,
        };

        let conv = self.store.load(sender_id).await;

        if conv.entries.is_empty() {
            log::info!("No entries to compact for {}", sender_id);
            return Ok(());
        }

        // Build the conversation transcript for summarisation
        let mut transcript = String::new();
        if let Some(ref existing) = conv.summary {
            transcript.push_str("Existing summary (incorporate into your updated summary):\n");
            transcript.push_str(existing);
            transcript.push_str("\n\nNew exchanges to fold in:\n");
        }
        for entry in &conv.entries {
            transcript.push_str(&format!("User: {}\nAgent: {}\n\n", entry.user_message, entry.agent_response));
        }

        let client = self.openai_client();

        let messages: Vec<ChatCompletionRequestMessage> = vec![
            ChatCompletionRequestSystemMessageArgs::default()
                .content(
                    r#"You are a conversation summariser for a support agent.
Your job is to produce a concise but complete memory block that will be injected
into the agent's system prompt so it remembers everything important about this
sender's support history.

When writing the summary:
- Preserve ALL concrete facts: VM IDs, IPs, hostnames, region names, dates,
  error messages, what was tried and whether it worked, outstanding issues,
  payment amounts and statuses, refund decisions, and any explicit user
  preferences.
- Note anything the agent should remember to do or NOT do with this sender
  (e.g. "always explain pricing before extending", "user is non-technical").
- If a prior issue was resolved, say so briefly so the agent doesn't re-open it.
- If an issue is still open, make that very clear.
- Write in third person ("The customer", "The user").
- Keep it under 800 words.
- Output ONLY the summary text — no markdown fences, no preamble."#
                )
                .build()
                .unwrap()
                .into(),
            ChatCompletionRequestUserMessageArgs::default()
                .content(transcript)
                .build()
                .unwrap()
                .into(),
        ];

        let request = CreateChatCompletionRequestArgs::default()
            .model(&self.settings.openai.model)
            .max_completion_tokens(1024u32)
            .messages(messages)
            .build()?;

        let response = client.chat().create(request).await?;
        let summary = response.choices[0]
            .message
            .content
            .clone()
            .ok_or_else(|| anyhow!("LLM returned empty summary"))?;

        log::info!(
            "Compacted conversation for {}: {} entries -> {} chars summary",
            sender_id,
            conv.entries.len(),
            summary.len()
        );

        // Save summary and clear raw entries
        self.store.save(
            sender_id,
            SenderConversation {
                summary: Some(summary),
                entries: vec![],
            },
        )
        .await
    }

    pub async fn process_request(
        &self,
        sender_id: &str,
        user_pubkey: Option<&str>,
        user_message: &str,
        channel_prompt: &str,
    ) -> Result<String> {
        use async_openai::types::{
            ChatCompletionRequestAssistantMessage, ChatCompletionRequestMessage,
            ChatCompletionRequestToolMessageArgs,
            ChatCompletionRequestUserMessageArgs, ChatCompletionTool, ChatCompletionToolType,
            CreateChatCompletionRequestArgs,
        };

        let client = self.openai_client();

        // --- General question (no known user) ---
        let Some(pubkey) = user_pubkey else {
            let system = if channel_prompt.is_empty() {
                general_system_message()
            } else {
                format!("{}\n\n{}", general_system_message(), channel_prompt)
            };

            let tools: Vec<ChatCompletionTool> = super::tools::public_tools()
                .into_iter()
                .map(|f| ChatCompletionTool {
                    function: f,
                    r#type: ChatCompletionToolType::Function,
                })
                .collect();

            let mut messages: Vec<ChatCompletionRequestMessage> = Vec::new();
            self.build_messages_with_history(
                &mut messages,
                sender_id,
                system,
            )
            .await;

            messages.push(
                ChatCompletionRequestUserMessageArgs::default()
                    .content(user_message.to_string())
                    .build()
                    .unwrap()
                    .into(),
            );

            let executor = Arc::new(PublicToolExecutor::new(self.api.clone()));
            let max_iterations = 5;

            for _ in 0..max_iterations {
                let request = CreateChatCompletionRequestArgs::default()
                    .model(&self.settings.openai.model)
                    .max_completion_tokens(self.settings.openai.max_tokens.unwrap_or(2048))
                    .messages(messages.clone())
                    .tools(tools.clone())
                    .build()?;

                let response = client.chat().create(request).await?;
                let choice = &response.choices[0];

                if let Some(ref tool_calls) = choice.message.tool_calls
                    && !tool_calls.is_empty()
                {
                    let assistant_tool_calls: Vec<
                        async_openai::types::ChatCompletionMessageToolCall,
                    > = tool_calls.to_vec();

                    messages.push(
                        ChatCompletionRequestAssistantMessage {
                            content: None,
                            tool_calls: Some(assistant_tool_calls.clone()),
                            ..Default::default()
                        }
                        .into(),
                    );

                    for tc in tool_calls {
                        let name = tc.function.name.clone();
                        let args = tc.function.arguments.clone();
                        let call_id = tc.id.clone();

                        log::info!("Executing public tool: {} with args: {}", name, args);

                        let result = match executor.execute(&name, &args).await {
                            Ok(content) => content,
                            Err(e) => format!("Error: {}", e),
                        };

                        log::info!("Tool {} result: {}", name, &result[..result.len().min(200)]);

                        messages.push(
                            ChatCompletionRequestToolMessageArgs::default()
                                .tool_call_id(call_id)
                                .content(result)
                                .build()
                                .unwrap()
                                .into(),
                        );
                    }
                    continue;
                }

                let content = choice
                    .message
                    .content
                    .clone()
                    .unwrap_or_else(|| "I'm sorry, I couldn't generate a response.".to_string());

                self.record_exchange(sender_id, user_message, &content).await;
                return Ok(content);
            }

            let fallback = "I wasn't able to generate a complete response. Could you try rephrasing your question?".to_string();
            self.record_exchange(sender_id, user_message, &fallback).await;
            return Ok(fallback);
        };

        // --- Known user: resolve, create scoped executor with tools ---
        let user = self
            .api
            .admin_find_user_by_pubkey(pubkey)
            .await?
            .ok_or_else(|| anyhow!("No user found with pubkey: {}", pubkey))?;

        let user_id = user["id"]
            .as_u64()
            .ok_or_else(|| anyhow!("User record missing 'id' field"))?;

        let account = self.api.admin_get_user(user_id).await?;
        let executor = Arc::new(LnvpsToolExecutor::new(self.api.clone(), user_id));

        let tools: Vec<ChatCompletionTool> = super::tools::support_tools()
            .into_iter()
            .map(|f| ChatCompletionTool {
                function: f,
                r#type: ChatCompletionToolType::Function,
            })
            .collect();

        let mut messages: Vec<ChatCompletionRequestMessage> = Vec::new();
        let sys = if channel_prompt.is_empty() {
            self.system_message(pubkey, &account)
        } else {
            format!("{}\n\n{}", self.system_message(pubkey, &account), channel_prompt)
        };
        self.build_messages_with_history(
            &mut messages,
            sender_id,
            sys,
        )
        .await;

        messages.push(
            ChatCompletionRequestUserMessageArgs::default()
                .content(user_message.to_string())
                .build()
                .unwrap()
                .into(),
        );

        let max_iterations = 10;

        for _ in 0..max_iterations {
            let request = CreateChatCompletionRequestArgs::default()
                .model(&self.settings.openai.model)
                .max_completion_tokens(self.settings.openai.max_tokens.unwrap_or(2048))
                .messages(messages.clone())
                .tools(tools.clone())
                .build()?;

            let response = client.chat().create(request).await?;
            let choice = &response.choices[0];

            if let Some(ref tool_calls) = choice.message.tool_calls
                && !tool_calls.is_empty()
            {
                let assistant_tool_calls: Vec<
                    async_openai::types::ChatCompletionMessageToolCall,
                > = tool_calls.to_vec();

                messages.push(
                    ChatCompletionRequestAssistantMessage {
                        content: None,
                        tool_calls: Some(assistant_tool_calls.clone()),
                        ..Default::default()
                    }
                    .into(),
                );

                for tc in tool_calls {
                    let name = tc.function.name.clone();
                    let args = tc.function.arguments.clone();
                    let call_id = tc.id.clone();

                    log::info!("Executing tool: {} with args: {}", name, args);

                    let result = match executor.execute(&name, &args).await {
                        Ok(content) => content,
                        Err(e) => format!("Error: {}", e),
                    };

                    log::info!("Tool {} result: {}", name, &result[..result.len().min(200)]);

                    messages.push(
                        ChatCompletionRequestToolMessageArgs::default()
                            .tool_call_id(call_id)
                            .content(result)
                            .build()
                            .unwrap()
                            .into(),
                    );
                }
                continue;
            }

            let content = choice
                .message
                .content
                .clone()
                .unwrap_or_else(|| "I processed your request but have no further response.".to_string());

            self.record_exchange(sender_id, user_message, &content).await;
            return Ok(content);
        }

        Ok("I've checked everything I can but the issue may need more investigation. Please open a manual support ticket.".to_string())
    }

    pub async fn run_loop(&self, channel: Box<dyn crate::channel::SupportChannel>) {
        use crate::channel::SupportReply;

        let channel_prompt = channel.channel_prompt().to_string();

        while let Some(req) = channel.next_request().await {
            let pubkey_display = req.pubkey.as_deref().unwrap_or("(general)");
            log::info!(
                "Processing request from {} (sender={}): {}",
                pubkey_display,
                req.sender_id,
                &req.message[..req.message.len().min(100)]
            );

            let reply_ctx = req.channel_context.clone();
            let response = match self
                .process_request(&req.sender_id, req.pubkey.as_deref(), &req.message, &channel_prompt)
                .await
            {
                Ok(text) => text,
                Err(e) => {
                    log::error!("Agent error: {}", e);
                    format!(
                        "I encountered an error processing your request. Please try again later. ({})",
                        e
                    )
                }
            };

            log::info!("Response: {}", &response[..response.len().min(200)]);

            if let Err(e) = channel
                .send_reply(SupportReply {
                    response,
                    channel_context: reply_ctx,
                })
                .await
            {
                log::error!("Failed to send reply: {}", e);
            }
        }

        log::info!("Support channel closed, agent exiting.");
    }
}
