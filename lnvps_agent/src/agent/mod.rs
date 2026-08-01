#[cfg(feature = "db")]
mod db_executor;
mod executor;
mod prompts;

use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_openai::Client;
use async_openai::config::OpenAIConfig;
use async_openai::types::{
    ChatCompletionMessageToolCall, ChatCompletionMessageToolCallChunk,
    ChatCompletionRequestAssistantMessage, ChatCompletionRequestMessage,
    ChatCompletionRequestSystemMessageArgs, ChatCompletionRequestToolMessageArgs,
    ChatCompletionRequestUserMessageArgs, ChatCompletionTool, ChatCompletionToolType,
    CreateChatCompletionRequestArgs, FunctionCall,
};
use futures::StreamExt;
use tokio::sync::mpsc;

use crate::session::ChatEvent;

use crate::api_client::ApiClient;
use crate::channel::IncomingSupportRequest;
use crate::conversation::{ChatMessage, ConversationStore, StoredToolCall};
use crate::identity::{Requester, SupportChannelKind, conversation_key};
use crate::settings::{OpenAiConfig, Settings};

#[cfg(feature = "db")]
pub use db_executor::DbToolExecutor;
pub use executor::{LnvpsToolExecutor, PublicToolExecutor, ToolExecutor};

/// Truncate a string to at most `max` characters for logging, without panicking
/// on multi-byte UTF-8 boundaries (byte-index slicing would panic).
fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

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

/// Whether a stream error just means the provider closed the connection.
///
/// `async-openai` only ends a stream cleanly on a `data: [DONE]` sentinel and
/// surfaces anything else — including an ordinary EOF — as a `StreamError`.
/// Plenty of OpenAI-compatible servers (vLLM among them) never send `[DONE]`
/// and simply close after the chunk carrying `finish_reason`, so treating that
/// as a failure would break every conversation against those providers.
fn is_stream_end(error: &async_openai::error::OpenAIError) -> bool {
    matches!(
        error,
        async_openai::error::OpenAIError::StreamError(message)
            if message.contains("Stream ended")
    )
}

/// Partial tool call assembled from streamed deltas.
#[derive(Default, Clone)]
struct PartialToolCall {
    id: String,
    name: String,
    arguments: String,
}

/// Reassembles streamed tool-call deltas into complete tool calls.
///
/// A streaming provider splits one tool call across many chunks: the first
/// carries the id and function name, and the rest carry successive slices of the
/// JSON arguments. Chunks are correlated by `index`, and several tool calls can
/// be interleaved in the same response, so they are accumulated into a map keyed
/// by that index (ordered, so the calls come back in the order the model emitted
/// them).
///
/// Every field is *appended* rather than overwritten: the wire format sends each
/// piece exactly once, and appending is what makes a name or id split across two
/// chunks reassemble correctly.
#[derive(Default)]
struct ToolCallAccumulator {
    calls: std::collections::BTreeMap<u32, PartialToolCall>,
}

impl ToolCallAccumulator {
    /// Fold one delta's worth of tool-call chunks into the accumulator.
    fn ingest(&mut self, chunks: &[ChatCompletionMessageToolCallChunk]) {
        for chunk in chunks {
            let entry = self.calls.entry(chunk.index).or_default();
            if let Some(id) = chunk.id.as_deref() {
                entry.id.push_str(id);
            }
            if let Some(function) = chunk.function.as_ref() {
                if let Some(name) = function.name.as_deref() {
                    entry.name.push_str(name);
                }
                if let Some(arguments) = function.arguments.as_deref() {
                    entry.arguments.push_str(arguments);
                }
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }

    /// Produce the completed tool calls, in emission order.
    ///
    /// Calls that never received a name are dropped — they cannot be dispatched,
    /// and forwarding one would make the model's next turn reference a tool
    /// result that can never arrive.
    fn finish(self) -> Vec<ChatCompletionMessageToolCall> {
        self.calls
            .into_values()
            .filter(|c| !c.name.is_empty())
            .map(|c| ChatCompletionMessageToolCall {
                id: c.id,
                r#type: ChatCompletionToolType::Function,
                function: FunctionCall {
                    name: c.name,
                    // An argument-less call streams no argument deltas at all;
                    // the API requires valid JSON here.
                    arguments: if c.arguments.is_empty() {
                        "{}".to_string()
                    } else {
                        c.arguments
                    },
                },
            })
            .collect()
    }
}

/// Build the function tool specs the model is offered for a request.
pub(crate) fn tool_specs(
    functions: Vec<async_openai::types::FunctionObject>,
) -> Vec<ChatCompletionTool> {
    functions
        .into_iter()
        .map(|function| ChatCompletionTool {
            function,
            r#type: ChatCompletionToolType::Function,
        })
        .collect()
}

/// Append operator-supplied instructions to a channel prompt.
///
/// Kept separate from the built-in prompts so config can only ever add to them.
fn channel_prompt_with_extra(channel_prompt: &str, extra: Option<&str>) -> String {
    match extra {
        Some(extra) if !extra.trim().is_empty() => {
            if channel_prompt.is_empty() {
                extra.trim().to_string()
            } else {
                format!("{}\n\n{}", channel_prompt, extra.trim())
            }
        }
        _ => channel_prompt.to_string(),
    }
}

/// The AI support agent that handles a support conversation.
#[derive(Clone)]
pub struct SupportAgent {
    /// HTTP client for the LNVPS APIs.
    ///
    /// `None` when the agent is hosted inside `lnvps_api`, where sender
    /// resolution and tool execution are done against the database directly and
    /// there is no admin nsec to sign with. Only the pull-based channel paths
    /// ([`Self::process_request`], [`Self::run_loop`]) require it; the streaming
    /// session path takes its executor from the caller.
    api: Option<Arc<ApiClient>>,
    openai: OpenAiConfig,
    store: Arc<dyn ConversationStore>,
    /// Maximum stored messages to retain per sender before compaction.
    compaction_threshold: usize,
    /// Operator-supplied instructions appended after the built-in prompts.
    ///
    /// Additive, never a replacement: the compiled prompts in [`prompts`] are
    /// always used, so a deployment can adjust tone or house rules without
    /// having to restate the whole support prompt.
    extra_prompt: Option<String>,
}

impl SupportAgent {
    pub fn new(api: Arc<ApiClient>, settings: Settings, store: Arc<dyn ConversationStore>) -> Self {
        let extra_prompt = settings
            .system_prompt
            .filter(|p| !p.trim().is_empty())
            .map(|p| p.trim().to_string());
        Self {
            api: Some(api),
            openai: settings.openai,
            store,
            compaction_threshold: COMPACTION_THRESHOLD,
            extra_prompt,
        }
    }

    /// Build an agent with no HTTP API client, for in-process hosting.
    ///
    /// Suitable for [`crate::session::ChatSession`], which supplies its own tool
    /// executor. Calling [`Self::process_request`] or [`Self::run_loop`] on such
    /// an agent is an error, since neither can resolve a sender.
    pub fn detached(openai: OpenAiConfig, store: Arc<dyn ConversationStore>) -> Self {
        Self {
            api: None,
            openai,
            store,
            compaction_threshold: COMPACTION_THRESHOLD,
            extra_prompt: None,
        }
    }

    /// The HTTP API client, or a clear error when running detached.
    fn api(&self) -> Result<Arc<ApiClient>> {
        self.api
            .clone()
            .ok_or_else(|| anyhow!("this agent has no API client; use a ChatSession instead"))
    }

    fn openai_client(&self) -> Client<OpenAIConfig> {
        let mut config = OpenAIConfig::new().with_api_base(&self.openai.base_url);
        if let Some(ref key) = self.openai.api_key {
            config = config.with_api_key(key);
        }
        Client::with_config(config)
    }

    fn max_tokens(&self) -> u32 {
        self.openai.max_tokens.unwrap_or(2048)
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
                .model(&self.openai.model)
                .max_completion_tokens(self.max_tokens())
                .messages(request_messages.clone())
                .tools(tools.clone())
                .build()?;

            let response = client.chat().create(request).await?;
            let choice = response
                .choices
                .first()
                .ok_or_else(|| anyhow!("LLM returned no choices"))?;

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
                    log::info!("Tool {} result: {}", name, truncate_chars(&result, 200));

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

    /// Streaming counterpart to [`Self::run_chat_loop`].
    ///
    /// Identical control flow, but the assistant's prose is forwarded to
    /// `events` token by token as it arrives, and each tool invocation is
    /// announced so a UI can show progress instead of a silent pause.
    async fn stream_chat_loop(
        &self,
        executor: Arc<dyn ToolExecutor>,
        tools: Vec<ChatCompletionTool>,
        mut request_messages: Vec<ChatCompletionRequestMessage>,
        user_message: &str,
        config: LoopConfig,
        emit_tool_activity: bool,
        events: &mpsc::Sender<ChatEvent>,
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

        // Everything streamed to the client across all iterations of this turn.
        //
        // A model often narrates before calling a tool ("Let me check that..."),
        // and that prose is streamed as it arrives. The `Final` event must
        // therefore carry the whole visible reply, not just the last
        // iteration's text, or a client rendering tokens progressively would
        // end up displaying something different from the final value.
        let mut visible = String::new();

        for _ in 0..config.max_iterations {
            let request = CreateChatCompletionRequestArgs::default()
                .model(&self.openai.model)
                .max_completion_tokens(self.max_tokens())
                .messages(request_messages.clone())
                .tools(tools.clone())
                .build()?;

            let mut stream = client.chat().create_stream(request).await?;
            let mut content = String::new();
            let mut accumulator = ToolCallAccumulator::default();
            // Set once the provider reports why generation stopped, which marks
            // the response as complete even if no `[DONE]` sentinel follows.
            let mut finished = false;

            while let Some(chunk) = stream.next().await {
                let chunk = match chunk {
                    Ok(chunk) => chunk,
                    Err(e) if is_stream_end(&e) && finished => break,
                    Err(e) if is_stream_end(&e) && !content.is_empty() => {
                        // Truncated mid-generation: keep the partial reply
                        // rather than losing the turn, but say so.
                        log::warn!("LLM stream ended before completion; using partial reply");
                        break;
                    }
                    Err(e) => return Err(e.into()),
                };

                let Some(choice) = chunk.choices.first() else {
                    continue;
                };
                if choice.finish_reason.is_some() {
                    finished = true;
                }

                if let Some(delta) = choice.delta.content.as_deref()
                    && !delta.is_empty()
                {
                    content.push_str(delta);
                    visible.push_str(delta);
                    // A closed receiver means the client hung up; keep draining
                    // so the turn still gets persisted.
                    let _ = events
                        .send(ChatEvent::Token {
                            text: delta.to_string(),
                        })
                        .await;
                }

                if let Some(chunks) = choice.delta.tool_calls.as_deref() {
                    accumulator.ingest(chunks);
                }
            }

            if !accumulator.is_empty() {
                let tool_calls = accumulator.finish();
                if tool_calls.is_empty() {
                    // Every accumulated call was unusable (no name); treating
                    // this as a plain reply avoids a pointless extra round trip.
                    log::warn!("Model streamed tool calls with no dispatchable name");
                } else {
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
                        (!content.is_empty()).then(|| content.clone()),
                        stored_calls,
                    ));

                    for tc in &tool_calls {
                        let name = tc.function.name.clone();
                        let args = tc.function.arguments.clone();
                        log::info!("Executing tool: {} with args: {}", name, args);
                        if emit_tool_activity {
                            let _ = events
                                .send(ChatEvent::ToolStart { name: name.clone() })
                                .await;
                        }

                        let result = match executor.execute(&name, &args).await {
                            Ok(content) => content,
                            Err(e) => format!("Error: {}", e),
                        };
                        log::info!("Tool {} result: {}", name, truncate_chars(&result, 200));
                        if emit_tool_activity {
                            let _ = events
                                .send(ChatEvent::ToolDone { name: name.clone() })
                                .await;
                        }

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
            }

            // Persist only this iteration's text as the assistant message: any
            // pre-tool narration was already stored on the tool-calling turn.
            if !content.is_empty() {
                new_messages.push(ChatMessage::assistant(Some(content), vec![]));
            }

            let reply = if visible.is_empty() {
                let fallback = config.empty_reply_fallback.to_string();
                new_messages.push(ChatMessage::assistant(Some(fallback.clone()), vec![]));
                fallback
            } else {
                visible
            };
            return Ok((reply, new_messages));
        }

        new_messages.push(ChatMessage::assistant(
            Some(config.exhausted_fallback.to_string()),
            vec![],
        ));
        Ok((config.exhausted_fallback.to_string(), new_messages))
    }

    /// Run one streamed conversational turn for an already-resolved sender.
    ///
    /// This is the entry point used by [`crate::session::ChatSession`]; the
    /// caller supplies the executor so the session can be backed by either the
    /// HTTP API client or a direct database executor.
    pub(crate) async fn stream_turn(
        &self,
        sender_id: &str,
        channel: SupportChannelKind,
        requester: &Requester,
        executor: Arc<dyn ToolExecutor>,
        tools: Vec<ChatCompletionTool>,
        user_message: &str,
        channel_prompt: &str,
        emit_tool_activity: bool,
        events: &mpsc::Sender<ChatEvent>,
    ) -> Result<String> {
        let (system, config) = match requester {
            Requester::Customer { account, .. } => (
                prompts::with_channel_prompt(prompts::user_system_message(account), channel_prompt),
                LoopConfig {
                    max_iterations: USER_MAX_ITERATIONS,
                    empty_reply_fallback: "I processed your request but have no further response.",
                    exhausted_fallback: "I've checked everything I can but the issue may need more investigation. Please open a manual support ticket.",
                },
            ),
            Requester::Anonymous => (
                prompts::with_channel_prompt(prompts::general_system_message(), channel_prompt),
                LoopConfig {
                    max_iterations: PUBLIC_MAX_ITERATIONS,
                    empty_reply_fallback: "I'm sorry, I couldn't generate a response.",
                    exhausted_fallback: "I wasn't able to generate a complete response. Could you try rephrasing your question?",
                },
            ),
        };

        let base = self.base_messages(sender_id, system).await;
        let (response, new_messages) = self
            .stream_chat_loop(
                executor,
                tools,
                base,
                user_message,
                config,
                emit_tool_activity,
                events,
            )
            .await?;

        self.record_turn(sender_id, channel, new_messages).await;
        Ok(response)
    }

    /// Persist a completed turn and compact if the log has grown too large.
    async fn record_turn(
        &self,
        sender_id: &str,
        channel: SupportChannelKind,
        messages: Vec<ChatMessage>,
    ) {
        if let Err(e) = self.store.append(sender_id, channel, messages).await {
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
    /// injected into the system prompt on future requests, then advances the
    /// store's high-water mark so those messages stop being replayed. Whether
    /// the underlying messages are retained is up to the store — the database
    /// store keeps them as a training corpus.
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
            .model(&self.openai.model)
            .max_completion_tokens(1024u32)
            .messages(messages)
            .build()?;

        let response = client.chat().create(request).await?;
        let summary = response
            .choices
            .first()
            .ok_or_else(|| anyhow!("LLM returned no choices"))?
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

        // Pass back the cursor from the snapshot we actually summarised, so a
        // message that arrived mid-summarisation stays in the replay window.
        self.store.compact(sender_id, summary, conv.cursor).await
    }

    pub async fn process_request(
        &self,
        req: &IncomingSupportRequest,
        channel: SupportChannelKind,
        channel_prompt: &str,
    ) -> Result<String> {
        let requester = self.api()?.resolve(&req.sender).await?;
        let key = conversation_key(&req.sender, &requester, channel);

        let (response, new_messages) = match requester {
            Requester::Customer { user_id, account } => {
                self.process_known_user(&key, user_id, &account, &req.message, channel_prompt)
                    .await?
            }
            Requester::Anonymous => {
                self.process_general(&key, &req.message, channel_prompt)
                    .await?
            }
        };

        self.record_turn(&key, channel, new_messages).await;
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
        let executor = Arc::new(PublicToolExecutor::new(self.api()?));

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

    /// Handle a request from a known customer. The channel already resolved the
    /// user and returned their full account record, so no further lookup is
    /// needed here.
    async fn process_known_user(
        &self,
        sender_id: &str,
        user_id: u64,
        account: &serde_json::Value,
        user_message: &str,
        channel_prompt: &str,
    ) -> Result<(String, Vec<ChatMessage>)> {
        let system =
            prompts::with_channel_prompt(prompts::user_system_message(account), channel_prompt);
        let base = self.base_messages(sender_id, system).await;
        let tools = tool_specs(super::tools::support_tools());
        let executor = Arc::new(LnvpsToolExecutor::new(self.api()?, user_id));

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

        let channel_prompt =
            channel_prompt_with_extra(channel.channel_prompt(), self.extra_prompt.as_deref());
        let kind = channel.kind();

        while let Some(req) = channel.next_request().await {
            log::info!(
                "Processing request from {}: {}",
                req.sender.as_str(),
                truncate_chars(&req.message, 100)
            );

            let reply_ctx = req.channel_context.clone();
            let response = match self.process_request(&req, kind, &channel_prompt).await {
                Ok(text) => text,
                Err(e) => {
                    log::error!("Agent error: {}", e);
                    format!(
                        "I encountered an error processing your request. Please try again later. ({})",
                        e
                    )
                }
            };

            log::info!("Response: {}", truncate_chars(&response, 200));

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

    /// Config may only add to the built-in prompts, never replace them.
    #[test]
    fn channel_prompt_with_extra_is_additive() {
        assert_eq!(channel_prompt_with_extra("BASE", None), "BASE");
        assert_eq!(channel_prompt_with_extra("BASE", Some("   ")), "BASE");
        assert_eq!(
            channel_prompt_with_extra("BASE", Some("be brief\n")),
            "BASE\n\nbe brief"
        );
        // A channel with no prompt of its own still gets the extra text.
        assert_eq!(channel_prompt_with_extra("", Some("be brief")), "be brief");
    }

    /// Regression: truncating for logging must not panic on multi-byte UTF-8
    /// input (byte-index slicing previously panicked mid-character).
    #[test]
    fn truncate_chars_handles_multibyte() {
        // 100th byte lands inside a multi-byte char in the original bug.
        let s = "é".repeat(200);
        let out = truncate_chars(&s, 100);
        assert_eq!(out.chars().count(), 100);
        // Emoji (4-byte) input must also be safe.
        let emoji = "🚀".repeat(50);
        let out = truncate_chars(&emoji, 10);
        assert_eq!(out.chars().count(), 10);
        // Shorter-than-limit input is returned whole.
        assert_eq!(truncate_chars("hi", 100), "hi");
    }

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

    /// Build a streamed chunk the way a provider sends them.
    fn chunk(
        index: u32,
        id: Option<&str>,
        name: Option<&str>,
        arguments: Option<&str>,
    ) -> ChatCompletionMessageToolCallChunk {
        ChatCompletionMessageToolCallChunk {
            index,
            id: id.map(String::from),
            r#type: Some(ChatCompletionToolType::Function),
            function: Some(async_openai::types::FunctionCallStream {
                name: name.map(String::from),
                arguments: arguments.map(String::from),
            }),
        }
    }

    /// The wire format sends a tool call's id and name once, then the JSON
    /// arguments in successive slices; reassembly must concatenate them in
    /// order.
    #[test]
    fn accumulator_reassembles_a_split_tool_call() {
        let mut acc = ToolCallAccumulator::default();
        assert!(acc.is_empty());

        acc.ingest(&[chunk(0, Some("call_1"), Some("get_vm_details"), Some(""))]);
        acc.ingest(&[chunk(0, None, None, Some("{\"vm"))]);
        acc.ingest(&[chunk(0, None, None, Some("_id\":"))]);
        acc.ingest(&[chunk(0, None, None, Some("5}"))]);

        assert!(!acc.is_empty());
        let calls = acc.finish();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_1");
        assert_eq!(calls[0].function.name, "get_vm_details");
        assert_eq!(calls[0].function.arguments, r#"{"vm_id":5}"#);
    }

    /// Several tool calls can be interleaved in one response; they are
    /// correlated by index and must come back in emission order.
    #[test]
    fn accumulator_separates_interleaved_calls() {
        let mut acc = ToolCallAccumulator::default();
        acc.ingest(&[
            chunk(0, Some("a"), Some("start_vm"), Some("{\"vm_id\":")),
            chunk(1, Some("b"), Some("stop_vm"), Some("{\"vm_id\":")),
        ]);
        acc.ingest(&[
            chunk(1, None, None, Some("2}")),
            chunk(0, None, None, Some("1}")),
        ]);

        let calls = acc.finish();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].id, "a");
        assert_eq!(calls[0].function.name, "start_vm");
        assert_eq!(calls[0].function.arguments, r#"{"vm_id":1}"#);
        assert_eq!(calls[1].id, "b");
        assert_eq!(calls[1].function.name, "stop_vm");
        assert_eq!(calls[1].function.arguments, r#"{"vm_id":2}"#);
    }

    /// A no-argument tool streams no argument deltas, but the API requires
    /// valid JSON — an empty string would be rejected.
    #[test]
    fn accumulator_defaults_missing_arguments_to_empty_object() {
        let mut acc = ToolCallAccumulator::default();
        acc.ingest(&[chunk(0, Some("c"), Some("list_my_vms"), None)]);
        let calls = acc.finish();
        assert_eq!(calls[0].function.arguments, "{}");
    }

    /// A call with no name can't be dispatched; forwarding it would leave the
    /// model waiting on a tool result that can never arrive.
    #[test]
    fn accumulator_drops_nameless_calls() {
        let mut acc = ToolCallAccumulator::default();
        acc.ingest(&[chunk(0, Some("orphan"), None, Some("{}"))]);
        acc.ingest(&[chunk(1, Some("ok"), Some("list_regions"), None)]);

        let calls = acc.finish();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "list_regions");
    }

    /// Chunks carrying no function payload at all must not create phantom calls
    /// or panic.
    #[test]
    fn accumulator_tolerates_empty_chunks() {
        let mut acc = ToolCallAccumulator::default();
        acc.ingest(&[]);
        assert!(acc.is_empty());

        acc.ingest(&[ChatCompletionMessageToolCallChunk {
            index: 0,
            id: None,
            r#type: None,
            function: None,
        }]);
        // An entry exists but has no name, so nothing dispatchable comes out.
        assert!(acc.finish().is_empty());
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
