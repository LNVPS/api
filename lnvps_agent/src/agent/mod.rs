mod executor;
mod prompts;

use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_openai::Client;
use async_openai::config::OpenAIConfig;
use async_openai::types::{
    ChatCompletionMessageToolCall, ChatCompletionRequestAssistantMessage,
    ChatCompletionRequestMessage, ChatCompletionRequestSystemMessageArgs,
    ChatCompletionRequestToolMessageArgs, ChatCompletionRequestUserMessageArgs, ChatCompletionTool,
    ChatCompletionToolType, CreateChatCompletionRequestArgs, FunctionCall,
};

use crate::api_client::ApiClient;
use crate::conversation::{ChatMessage, ConversationStore, SenderConversation, StoredToolCall};
use crate::settings::Settings;

pub use executor::{LnvpsToolExecutor, PublicToolExecutor, ToolExecutor};

/// Number of stored chat messages that triggers a compaction pass.
const COMPACTION_THRESHOLD: usize = 30;

/// Maximum tool-calling iterations for a general (public) request.
const PUBLIC_MAX_ITERATIONS: usize = 5;

/// Maximum tool-calling iterations for a known-customer request.
const USER_MAX_ITERATIONS: usize = 10;

/// Tuning for a single tool-calling loop.
struct LoopConfig {
    /// Maximum model round-trips before giving up.
    max_iterations: usize,
    /// Returned when the model produces an empty (no-content) reply.
    empty_reply_fallback: &'static str,
    /// Returned when `max_iterations` is exhausted without a final reply.
    exhausted_fallback: &'static str,
}

/// Convert a persisted chat message into an async-openai request message.
fn to_request_message(message: &ChatMessage) -> ChatCompletionRequestMessage {
    match message {
        ChatMessage::User { content, .. } => ChatCompletionRequestUserMessageArgs::default()
            .content(content.clone())
            .build()
            .expect("valid user message")
            .into(),
        ChatMessage::Assistant {
            content,
            tool_calls,
            ..
        } => ChatCompletionRequestAssistantMessage {
            content: content.clone().map(Into::into),
            tool_calls: (!tool_calls.is_empty()).then(|| {
                tool_calls
                    .iter()
                    .map(|tc| ChatCompletionMessageToolCall {
                        id: tc.id.clone(),
                        r#type: ChatCompletionToolType::Function,
                        function: FunctionCall {
                            name: tc.name.clone(),
                            arguments: tc.arguments.clone(),
                        },
                    })
                    .collect()
            }),
            ..Default::default()
        }
        .into(),
        ChatMessage::Tool {
            tool_call_id,
            content,
            ..
        } => ChatCompletionRequestToolMessageArgs::default()
            .tool_call_id(tool_call_id.clone())
            .content(content.clone())
            .build()
            .expect("valid tool message")
            .into(),
    }
}

/// Map a provider tool call into the persisted representation.
fn stored_tool_call(tc: &ChatCompletionMessageToolCall) -> StoredToolCall {
    StoredToolCall {
        id: tc.id.clone(),
        name: tc.function.name.clone(),
        arguments: tc.function.arguments.clone(),
    }
}

/// Build the function tool specs the model is offered for a request.
fn tool_specs(functions: Vec<async_openai::types::FunctionObject>) -> Vec<ChatCompletionTool> {
    functions
        .into_iter()
        .map(|function| ChatCompletionTool {
            function,
            r#type: ChatCompletionToolType::Function,
        })
        .collect()
}

/// The AI support agent that handles a support conversation.
pub struct SupportAgent {
    api: Arc<ApiClient>,
    settings: Settings,
    store: Arc<dyn ConversationStore>,
    /// Maximum stored messages to retain per sender before compaction.
    compaction_threshold: usize,
}

impl SupportAgent {
    pub fn new(api: Arc<ApiClient>, settings: Settings, store: Arc<dyn ConversationStore>) -> Self {
        Self {
            api,
            settings,
            store,
            compaction_threshold: COMPACTION_THRESHOLD,
        }
    }

    fn openai_client(&self) -> Client<OpenAIConfig> {
        let mut config = OpenAIConfig::new().with_api_base(&self.settings.openai.base_url);
        if let Some(ref key) = self.settings.openai.api_key {
            config = config.with_api_key(key);
        }
        Client::with_config(config)
    }

    fn max_tokens(&self) -> u32 {
        self.settings.openai.max_tokens.unwrap_or(2048)
    }

    /// Build the base request messages: system prompt (+ memory block) followed
    /// by the replayed chat log for this sender.
    async fn base_messages(
        &self,
        sender_id: &str,
        system_prompt: String,
    ) -> Vec<ChatCompletionRequestMessage> {
        let conv = self.store.load(sender_id).await;
        let full_system = prompts::with_memory(&system_prompt, conv.summary.as_deref());

        let mut messages: Vec<ChatCompletionRequestMessage> = vec![
            ChatCompletionRequestSystemMessageArgs::default()
                .content(full_system)
                .build()
                .expect("valid system message")
                .into(),
        ];
        messages.extend(conv.messages.iter().map(to_request_message));
        messages
    }

    /// Run the tool-calling loop until the model returns a plain text reply,
    /// tools are exhausted, or `max_iterations` is hit.
    ///
    /// Returns the final reply text plus the new chat messages produced this
    /// turn (the user message, any assistant/tool turns, and the final reply),
    /// ready to be persisted.
    async fn run_chat_loop(
        &self,
        executor: Arc<dyn ToolExecutor>,
        tools: Vec<ChatCompletionTool>,
        mut request_messages: Vec<ChatCompletionRequestMessage>,
        user_message: &str,
        config: LoopConfig,
    ) -> Result<(String, Vec<ChatMessage>)> {
        let client = self.openai_client();

        request_messages.push(
            ChatCompletionRequestUserMessageArgs::default()
                .content(user_message.to_string())
                .build()
                .expect("valid user message")
                .into(),
        );
        let mut new_messages = vec![ChatMessage::user(user_message)];

        for _ in 0..config.max_iterations {
            let request = CreateChatCompletionRequestArgs::default()
                .model(&self.settings.openai.model)
                .max_completion_tokens(self.max_tokens())
                .messages(request_messages.clone())
                .tools(tools.clone())
                .build()?;

            let response = client.chat().create(request).await?;
            let choice = &response.choices[0];

            if let Some(ref tool_calls) = choice.message.tool_calls
                && !tool_calls.is_empty()
            {
                let stored_calls = tool_calls.iter().map(stored_tool_call).collect::<Vec<_>>();

                request_messages.push(
                    ChatCompletionRequestAssistantMessage {
                        content: None,
                        tool_calls: Some(tool_calls.clone()),
                        ..Default::default()
                    }
                    .into(),
                );
                new_messages.push(ChatMessage::assistant(
                    choice.message.content.clone(),
                    stored_calls,
                ));

                for tc in tool_calls {
                    let name = tc.function.name.clone();
                    let args = tc.function.arguments.clone();
                    log::info!("Executing tool: {} with args: {}", name, args);

                    let result = match executor.execute(&name, &args).await {
                        Ok(content) => content,
                        Err(e) => format!("Error: {}", e),
                    };
                    log::info!("Tool {} result: {}", name, &result[..result.len().min(200)]);

                    request_messages.push(
                        ChatCompletionRequestToolMessageArgs::default()
                            .tool_call_id(tc.id.clone())
                            .content(result.clone())
                            .build()
                            .expect("valid tool message")
                            .into(),
                    );
                    new_messages.push(ChatMessage::tool(tc.id.clone(), result));
                }
                continue;
            }

            let content = choice
                .message
                .content
                .clone()
                .unwrap_or_else(|| config.empty_reply_fallback.to_string());
            new_messages.push(ChatMessage::assistant(Some(content.clone()), vec![]));
            return Ok((content, new_messages));
        }

        new_messages.push(ChatMessage::assistant(
            Some(config.exhausted_fallback.to_string()),
            vec![],
        ));
        Ok((config.exhausted_fallback.to_string(), new_messages))
    }

    /// Persist a completed turn and compact if the log has grown too large.
    async fn record_turn(&self, sender_id: &str, messages: Vec<ChatMessage>) {
        if let Err(e) = self.store.append(sender_id, messages).await {
            log::error!("Failed to record conversation for {}: {}", sender_id, e);
            return;
        }

        let conv = self.store.load(sender_id).await;
        if conv.messages.len() > self.compaction_threshold {
            log::info!(
                "Conversation for {} has {} messages, triggering compaction",
                sender_id,
                conv.messages.len()
            );
            if let Err(e) = self.compact(sender_id).await {
                log::error!("Failed to compact conversation for {}: {}", sender_id, e);
            }
        }
    }

    /// Compact the conversation log for a sender using the LLM.
    ///
    /// Summarises the chat log into a persistent `<MEMORY>` block that is
    /// injected into the system prompt on future requests, then clears the
    /// raw log so only the summary carries forward.
    pub async fn compact(&self, sender_id: &str) -> Result<()> {
        let conv = self.store.load(sender_id).await;
        if conv.messages.is_empty() {
            log::info!("No messages to compact for {}", sender_id);
            return Ok(());
        }

        let mut transcript = String::new();
        if let Some(ref existing) = conv.summary {
            transcript.push_str("Existing summary (incorporate into your updated summary):\n");
            transcript.push_str(existing);
            transcript.push_str("\n\nNew exchanges to fold in:\n");
        }
        for message in &conv.messages {
            transcript.push_str(&message.transcript_line());
            transcript.push('\n');
        }

        let client = self.openai_client();
        let messages: Vec<ChatCompletionRequestMessage> = vec![
            ChatCompletionRequestSystemMessageArgs::default()
                .content(prompts::compaction_system_message())
                .build()
                .expect("valid system message")
                .into(),
            ChatCompletionRequestUserMessageArgs::default()
                .content(transcript)
                .build()
                .expect("valid user message")
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
            "Compacted conversation for {}: {} messages -> {} chars summary",
            sender_id,
            conv.messages.len(),
            summary.len()
        );

        self.store
            .save(
                sender_id,
                SenderConversation {
                    summary: Some(summary),
                    messages: vec![],
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
        let (response, new_messages) = match user_pubkey {
            None => {
                self.process_general(sender_id, user_message, channel_prompt)
                    .await?
            }
            Some(pubkey) => {
                self.process_known_user(sender_id, pubkey, user_message, channel_prompt)
                    .await?
            }
        };

        self.record_turn(sender_id, new_messages).await;
        Ok(response)
    }

    /// Handle a request from a sender not identified as a customer.
    async fn process_general(
        &self,
        sender_id: &str,
        user_message: &str,
        channel_prompt: &str,
    ) -> Result<(String, Vec<ChatMessage>)> {
        let system =
            prompts::with_channel_prompt(prompts::general_system_message(), channel_prompt);
        let base = self.base_messages(sender_id, system).await;
        let tools = tool_specs(super::tools::public_tools());
        let executor = Arc::new(PublicToolExecutor::new(self.api.clone()));

        self.run_chat_loop(
            executor,
            tools,
            base,
            user_message,
            LoopConfig {
                max_iterations: PUBLIC_MAX_ITERATIONS,
                empty_reply_fallback: "I'm sorry, I couldn't generate a response.",
                exhausted_fallback:
                    "I wasn't able to generate a complete response. Could you try rephrasing your question?",
            },
        )
        .await
    }

    /// Handle a request from a known customer (resolved via their pubkey).
    async fn process_known_user(
        &self,
        sender_id: &str,
        pubkey: &str,
        user_message: &str,
        channel_prompt: &str,
    ) -> Result<(String, Vec<ChatMessage>)> {
        let user = self
            .api
            .admin_find_user_by_pubkey(pubkey)
            .await?
            .ok_or_else(|| anyhow!("No user found with pubkey: {}", pubkey))?;
        let user_id = user["id"]
            .as_u64()
            .ok_or_else(|| anyhow!("User record missing 'id' field"))?;
        let account = self.api.admin_get_user(user_id).await?;

        let system = prompts::with_channel_prompt(
            prompts::user_system_message(pubkey, &account),
            channel_prompt,
        );
        let base = self.base_messages(sender_id, system).await;
        let tools = tool_specs(super::tools::support_tools());
        let executor = Arc::new(LnvpsToolExecutor::new(self.api.clone(), user_id));

        self.run_chat_loop(
            executor,
            tools,
            base,
            user_message,
            LoopConfig {
                max_iterations: USER_MAX_ITERATIONS,
                empty_reply_fallback: "I processed your request but have no further response.",
                exhausted_fallback:
                    "I've checked everything I can but the issue may need more investigation. Please open a manual support ticket.",
            },
        )
        .await
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
                .process_request(
                    &req.sender_id,
                    req.pubkey.as_deref(),
                    &req.message,
                    &channel_prompt,
                )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_request_message_maps_roles() {
        let user = to_request_message(&ChatMessage::user("hi"));
        assert!(matches!(user, ChatCompletionRequestMessage::User(_)));

        let assistant = to_request_message(&ChatMessage::assistant(
            None,
            vec![StoredToolCall {
                id: "1".to_string(),
                name: "list_my_vms".to_string(),
                arguments: "{}".to_string(),
            }],
        ));
        match assistant {
            ChatCompletionRequestMessage::Assistant(a) => {
                assert!(a.content.is_none());
                assert_eq!(a.tool_calls.unwrap().len(), 1);
            }
            _ => panic!("expected assistant message"),
        }

        let tool = to_request_message(&ChatMessage::tool("1", "result"));
        assert!(matches!(tool, ChatCompletionRequestMessage::Tool(_)));
    }

    #[test]
    fn stored_tool_call_maps_fields() {
        let tc = ChatCompletionMessageToolCall {
            id: "abc".to_string(),
            r#type: ChatCompletionToolType::Function,
            function: FunctionCall {
                name: "extend_vm".to_string(),
                arguments: r#"{"vm_id":1}"#.to_string(),
            },
        };
        let stored = stored_tool_call(&tc);
        assert_eq!(stored.id, "abc");
        assert_eq!(stored.name, "extend_vm");
        assert_eq!(stored.arguments, r#"{"vm_id":1}"#);
    }

    #[test]
    fn tool_specs_wraps_functions() {
        let specs = tool_specs(super::super::tools::public_tools());
        assert!(!specs.is_empty());
        assert!(
            specs
                .iter()
                .all(|s| matches!(s.r#type, ChatCompletionToolType::Function))
        );
    }
}
