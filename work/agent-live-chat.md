# Live-chat WebSocket for the LNVPS support agent

**Status:** complete
**Started:** 2026-07-30
**Last updated:** 2026-07-31 (all increments complete; e2e suite green against a
real LLM)

## Goal

Expose `lnvps_agent` as an interactive, token-streaming live-chat agent over a
WebSocket served by `lnvps_api`, and move conversation history from per-sender
JSON files into the database so that (a) the transcript survives restarts and is
consistent between email and web chat for the same customer, and (b) the full
message log is retained as a training corpus.

## Design decisions (confirmed with user 2026-07-30)

- **Session API:** new `lnvps_agent::session::ChatSession`, one per WebSocket
  connection. `send(msg) -> impl Stream<Item = ChatEvent>` emitting
  `Token`/`ToolStart`/`ToolDone`/`Final`/`Error`. The existing pull-based
  `SupportChannel` + `run_loop` stay exactly as they are for email and Nostr.
- **Data access:** direct DB. `lnvps_agent` gains an optional `db` feature
  pulling in `lnvps_db`, so the in-API agent makes no loopback HTTP calls and
  needs no admin nsec. The HTTP `ApiClient` remains for the standalone binary.
- **Shared infrastructure:** the hypervisor host client lives in
  `lnvps_api_common` (moved in increment 0), alongside the `WorkCommander` and
  `VmHistoryLogger` that were already there. `lnvps_agent` can therefore drive
  VM power actions directly and the planned `VmPowerControl` trait seam is
  **no longer required**.
- **Live-chat tool scope:** read-only tools + `start_vm`/`stop_vm`/`restart_vm`.
  `extend_vm`, `refund_vm` and `delete_vm` are **excluded** — they grant paid
  time, move money or destroy data, and a model-issued "please confirm" is not
  an authorisation control on a public, prompt-injectable surface. Those remain
  available to the slower, auditable email/Nostr channels.
- **History storage:** MariaDB, append-only, encrypted at rest.
- **Thread identity:** unified per LNVPS user across the *private* channels
  (email + web chat) via a `user:<id>` conversation key. Anonymous senders fall
  back to `email:<addr>` / `pubkey:<hex>`.
- **Public Nostr is deliberately NOT in the shared thread.** kind-1 replies are
  world-readable; sharing a thread with email would let the agent quote a
  privately-reported billing detail into a public post. kind-1 keeps its own
  `nostr:<pubkey>` key namespace.
- **Compaction becomes non-destructive.** Messages are never deleted;
  `agent_conversation.compacted_upto` is a watermark and only messages above it
  are replayed as LLM context. Everything below stays for training/audit.
- **Content encryption:** message content uses the existing `EncryptedString`
  sqlx type, same as `user.email`. Transcripts contain PII (IPs, hostnames,
  addresses, whatever a user pastes) and must not sit in plaintext in backups.

## Findings

Assessment of `lnvps_agent` as it stands (~3.2k lines) — the agent core is
sound; the gaps are all in shape rather than substance:

- `src/lib.rs` **already exists** and exports all 8 modules, so "make a lib.rs"
  is already done. The real blocker is the channel abstraction.
- `SupportAgent::run_loop` (`src/agent/mod.rs`) is **strictly serial**: a single
  `while let Some(req) = channel.next_request()` loop that awaits
  `process_request` before taking the next request. Fine for email; for
  WebSockets one user's slow LLM call would block every other session. This is
  the main reason a separate session API is needed rather than a
  `WebSocketChannel` implementing `SupportChannel`.
- No streaming anywhere — `process_request` returns a complete `String`.
- `JsonFileStore` is a file-per-sender `RwLock<HashMap>` cache; not
  multi-replica safe and compaction **deletes** raw messages.
- `SenderIdentity::conversation_key()` returns the bare email/pubkey, so the
  same customer already has two disjoint histories across email and Nostr.
- `ApiClient` calls the admin API over HTTP signed with an admin nsec — inside
  `lnvps_api` that would be a loopback call with god-mode credentials.
- Ownership *is* enforced server-side (`LnvpsToolExecutor::owned_vm_id`), not
  merely by prompt. Good.
- Missing support capabilities generally: no VM power actions, no SSH key
  tools, no docs/KB retrieval, no human escalation/ticket handoff, and no
  per-sender rate/cost limiting. Power actions land in increment 4; the rest is
  explicitly out of scope for this task (see Notes).

Codebase facts that constrain the work:

- `LNVpsDbBase` has **two** implementations to keep in sync: `lnvps_db/src/mysql.rs`
  and `lnvps_api_common/src/mock.rs`.
- VM power actions need `get_host_client` + `work_sender` + `VmHistoryLogger`.
  `WorkCommander` and `VmHistoryLogger` were **already** in `lnvps_api_common`;
  the host client was moved there in increment 0. Since `lnvps_api` depends on
  `lnvps_agent`, the agent could never depend on `lnvps_api` — the move removes
  that constraint entirely rather than working around it with a trait.
- `lnvps_db::User` carries secrets (`email_verify_token`, `whatsapp_verify_code`,
  `telegram_link_token`). The `get_my_account` tool must return a hand-built
  sanitized projection, never the struct as-is.
- Existing WebSocket precedent to copy: `v1_terminal_proxy` in
  `lnvps_api/src/api/routes.rs` (`?auth=` query param carrying a base64 NIP-98
  event, checked with `Nip98Auth::from_base64` + `.check(path, method)`).
- async-openai 0.28 streams tool calls as `ChatCompletionMessageToolCallChunk`
  (`index`, optional `id`, optional `function.name`/`function.arguments`), so
  the streaming loop must accumulate chunks by `index`.
- Workspace has no `async-stream`/`tokio-stream`; use `futures::stream::unfold`
  over an mpsc receiver to return `impl Stream` without a new dependency.

## Tasks

### Increment 0 — move the host client into `lnvps_api_common` — **COMPLETE**

- [x] `git mv lnvps_api/src/host/ -> lnvps_api_common/src/host/` (4 files, 5,675
      lines; tracked by git as renames)
- [x] `git mv lnvps_api/src/ssh_client.rs -> lnvps_api_common/src/ssh_client.rs`
- [x] Extract `ProvisionerConfig`/`ProxmoxConfig`/`LibVirtConfig`/`QemuConfig`/
      `SshConfig`/`FirewallConfig`/`FirewallPolicy` out of
      `lnvps_api/src/settings.rs` into `lnvps_api_common/src/host/config.rs`,
      re-exported from `lnvps_api::settings` so `Settings` still deserializes
- [x] Move `extract_host_from_url` out of `lnvps_api::worker` into
      `lnvps_api_common::host` (both the Proxmox client and the worker need it)
- [x] Move `proxmox`/`libvirt`/`linux-ssh` features + their optional deps
      (`russh`, `russh-sftp`, `tokio-tungstenite`, `virt`, `uuid`, `quick-xml`)
      to `lnvps_api_common`; `lnvps_api`'s features now forward to them
- [x] Add `urlencoding` + `serde_yml` to `lnvps_api_common` (used by the Proxmox
      client)
- [x] Re-export `lnvps_api::host` / `lnvps_api::ssh_client` from the common crate
      so all existing `crate::host::*` call sites keep working
- [x] Move `tests/ssh_client.rs` to `lnvps_api_common/tests/`
- [x] Silence the now-reachable `unused_variables` on `get_host_client(cfg)` when
      built with neither hypervisor feature
- [x] Verified: `cargo test --workspace --exclude lnvps_e2e --exclude lnvps_health`
      → 925 passed, 0 failed; clippy clean; `--features proxmox` host tests run
      in their new home

### Increment 1 — conversation persistence in `lnvps_db` — **COMPLETE**

- [x] Migration `lnvps_db/migrations/20260730215133_agent_conversation.sql`
      creating `agent_conversation` (unique `conversation_key`, nullable
      `user_id` FK with `ON DELETE CASCADE`, `summary`, `compacted_upto`) and
      `agent_message` (append-only, `role`, `channel`, encrypted `content`,
      `tool_calls` JSON, `tool_call_id`)
- [x] Models + `#[repr(u16)]` enums `AgentMessageRole` (User/Assistant/Tool) and
      `AgentChannel` (Email/Nostr/WebChat), plus `AgentConversation`,
      `AgentMessage`, `NewAgentMessage` in `lnvps_db/src/model.rs`
- [x] Six `LNVpsDbBase` methods: `upsert_agent_conversation`,
      `get_agent_conversation`, `append_agent_messages`,
      `list_agent_messages_after_watermark`, `list_agent_messages_paginated`,
      `compact_agent_conversation`
- [x] Implemented in `lnvps_db/src/mysql.rs`
- [x] Implemented in `lnvps_api_common/src/mock.rs`
- [x] 7 unit tests, incl. regressions for watermark monotonicity, transcript
      retention through compaction, and private/public thread isolation
- [x] Verified against real MariaDB: applied the full migration chain to a
      scratch DB and exercised every query (upsert idempotency, `RETURNING id`,
      the watermark join, `GREATEST` monotonicity, two-level FK cascade)
- [x] `cargo test --workspace --exclude lnvps_e2e --exclude lnvps_health`
      → 932 passed, 0 failed; clippy clean

### Increment 2 — rework `ConversationStore` in `lnvps_agent` — **COMPLETE**

- [x] Store trait reworked: `append` now takes a `SupportChannelKind`, and
      `save(conversation)` is replaced by `compact(sender_id, summary, cursor)`
- [x] Solved the "no message ids" problem with an opaque `cursor` on
      `SenderConversation`: `load` stamps it (row id for the DB store, message
      count for the file/memory stores) and `compact` takes it back. This also
      fixes a latent race — a message arriving *during* summarisation is no
      longer silently dropped from context
- [x] `DbConversationStore` in `src/conversation/db.rs` behind the new `db`
      feature (optional `lnvps_db` + `lnvps_api_common` deps)
- [x] Namespaced keys via `identity::conversation_key(identity, requester,
      channel)`: `user:<id>` (private channels, shared), `nostr:<hex>` (always
      separate), `email:<addr>` / `pubkey:<hex>` (anonymous)
- [x] `SupportChannel::kind()` added; email returns `Email`, kind-1 returns
      `Nostr`
- [x] `JsonFileStore` and `MemoryStore` migrated to the new trait; legacy
      on-disk format parsing still works
- [x] `SupportAgent::compact` passes the snapshot cursor through
- [x] 15 new tests (6 identity, 2 store, 7 DB store) incl. regressions for
      public/private thread isolation, cursor-bounded compaction, and
      transcript retention. 51 tests without `db`, 58 with
- [x] `cargo test --workspace --exclude lnvps_e2e --exclude lnvps_health`
      → 940 passed, 0 failed; clippy clean on both feature configurations

### Increment 3 — streaming `ChatSession` — **COMPLETE**

- [x] `src/session.rs`: `ChatEvent`, `ChatSession::new` / `::resolve`,
      `send() -> impl Stream<Item = ChatEvent>` via `futures::stream::unfold`
      over an mpsc receiver (no new dependency)
- [x] `ToolCallAccumulator` in `agent/mod.rs` reassembling streamed tool-call
      deltas by `index`, plus `SupportAgent::stream_chat_loop` and `stream_turn`
- [x] Live-chat channel prompt telling the model it *cannot* extend/refund/
      delete and must hand those to a human
- [x] Completed turns persist through `ConversationStore` exactly as the
      non-streaming path does
- [x] 6 accumulator unit tests (split call, interleaved calls, missing
      arguments, nameless call, empty chunks) + 5 end-to-end tests in
      `tests/streaming.rs` against a wiremock OpenAI server covering SSE
      parsing, tool dispatch, event ordering, persistence under `user:<id>`,
      and upstream failure
- [x] 67 tests in `lnvps_agent` with `db`; workspace green; clippy clean on
      both feature configurations

### Increment 4 — `DbToolExecutor` — **COMPLETE**

- [x] `agent/db_executor.rs` behind `db`, implementing `ToolExecutor` against
      `Arc<dyn LNVpsDb>`
- [x] Hand-built JSON projections for account/VM/details/payments/history/
      regions/templates/images — no struct is ever serialised wholesale
- [x] `owned_vm()` re-reads and ownership-checks the VM on every `vm_id`
      argument, and does not disclose the real owner in the error
- [x] start/stop/restart via `lnvps_api_common::host::get_host_client` +
      `WorkCommander` + `VmHistoryLogger`. No `VmPowerControl` trait was needed
      (see increment 0). Power tools are opt-in via `with_power_actions`, so an
      executor that can't reach a hypervisor is read-only by construction
- [x] `extend_vm`/`refund_vm`/`delete_vm` are explicitly refused with a
      hand-off message, in case the model invents the call
- [x] 11 tests, incl. a cross-user ownership regression across all six
      VM-scoped tools and two secret-leak regressions
- [x] **Verified the leak tests can fail**: temporarily reintroduced the
      regression (serialising `api_token`/`ssh_key` and `email_verify_token`)
      and confirmed both tests fail, then reverted
- [x] 78 lib tests in `lnvps_agent` with `db`; workspace green; clippy clean

### Increment 5 — WebSocket route in `lnvps_api` (~400 lines)

- [x] `lnvps_api/src/api/support.rs`: NIP-98 auth, upgrade, per-connection
      `ChatSession`, JSON frame protocol mapping `ChatEvent`
- [x] Wired `DbToolExecutor::with_power_actions(settings.provisioner,
      work_sender)` and `DbConversationStore::new(db, user_id)` from
      `RouterState`
- [x] Route registered behind the new `agent` cargo feature via
      `with_support_chat()`; `agent` config is `Option`, so the endpoint can be
      compiled in and left switched off
- [x] Per-message length cap and per-connection turn cap (both configurable)
- [x] Updated `API_DOCUMENTATION.md` and `API_CHANGELOG.md`

### Increment 6 — e2e coverage against a real LLM — **COMPLETE**

- [x] `lnvps_e2e/src/agent_chat.rs` — 6 tests driving the websocket end to end
- [x] `run-e2e.sh` builds/runs the user API with `--features agent`; e2e config
      gained an `agent:` section with sentinel instructions in `system-prompt`
- [x] Wired the previously-dead `system_prompt` config through as a real
      operator addendum (`ChatSession::with_extra_prompt`), which is also what
      makes the e2e assertions deterministic
- [x] Fixed `run-e2e.sh` still pointing at `lnvps_api --test ssh_client` after
      increment 0 moved that test to `lnvps_api_common`
- [x] Documented the approach in `docs/agents/e2e-tests.md`
- [x] Full suite green: 13 agent chat + 6 ssh_client
- [x] Tool-activity frames (`tool_start`/`tool_done`) restricted to callers with
      the `users:view` permission; ordinary customers get only reply content.
      `lnvps_api/agent` now enables `lnvps_api_common/admin` for the RBAC lookup;
      fails closed if permissions can't be resolved
- [x] **Adversarial tests (6)** — direct prompt injection / instruction
      override, social engineering for tool visibility, cross-user VM access,
      host-credential extraction, **indirect (second-order) injection via
      poisoned tool output**, and **multi-turn persuasion carried across a
      reconnect**. Each asserts on a server-owned fact (which tools dispatched,
      whether a planted sentinel leaked), never on the model's wording
- [x] `fresh_privileged_identity()` isolates the two history-poisoning tests on
      their own `user:<id>` thread so contamination can't destabilise others
- [x] `db::seed_standalone_vm` / `hard_delete_seeded_vm` build and tear down a
      full infra chain with no dependency on the lifecycle test

#### Bugs the live run found (all fixed, all now covered by offline tests)

1. **Every turn failed against vLLM** — the provider closes the SSE stream
   without a `data: [DONE]` sentinel, and `async-openai` reports that EOF as a
   `StreamError`. Now treated as a clean end when a `finish_reason` was seen (or
   as a truncation warning when content had already arrived). Regression test:
   `completes_when_provider_omits_the_done_sentinel`.
2. **Conversation history never loaded** — MariaDB implements `JSON` as
   `LONGTEXT` with the binary `utf8mb4_bin` collation, which sqlx surfaces as a
   BLOB, so decoding `agent_message.tool_calls` into `String` failed at runtime
   and every load fell back to an empty conversation. `AgentMessage.tool_calls`
   is now `Option<Vec<u8>>`, matching the existing `VmHistory.metadata`
   precedent, and the mock stores bytes so unit tests exercise the same shape.
   **The mock DB could not have caught this** — it stored a Rust `String`.
3. **Sentinel markers are not reliable as "include this somewhere"** — the
   escalation test failed with the agent refusing perfectly but omitting the
   marker. Rewording the e2e `system-prompt` to make it a *required final line*
   fixed it. General lesson: models follow format rules far more reliably than
   decorate-your-answer rules, and the security assertion should never depend on
   a sentinel — keep that on tool dispatch, which the server controls.
4. **`Final` did not match the streamed tokens** — when the model narrates
   before calling a tool ("Let me check..."), that prose is streamed but was
   then dropped from `Final`, which only carried the last iteration's text. A
   client rendering progressively would show something different from the final
   value. Regression test:
   `final_includes_narration_streamed_before_a_tool_call`.

## Notes

- The `users` table has three NOT NULL columns without defaults (`pubkey`,
  `contact_nip17`, `contact_email`) — relevant when hand-writing SQL fixtures.
- `ChatEvent` uses **struct variants**, not newtype variants: serde cannot
  serialize an internally-tagged (`#[serde(tag = "type")]`) newtype variant
  holding a primitive, and it fails at *runtime*, not compile time. The wire
  format is therefore flat — `{"type":"token","text":"..."}` — and is pinned by
  a test because it is the public websocket contract.
- wiremock's `set_body_string` forces `content-type: text/plain`, which the SSE
  client rejects outright. Use `set_body_raw(bytes, "text/event-stream")` for
  any test that streams.
- MariaDB stores `JSON` as `LONGTEXT` + a `json_valid` CHECK constraint, so a
  malformed `tool_calls` value fails the insert outright. Writers serialize with
  serde_json, so this is a safety net rather than something to code around.
- Increment 0 gave `lnvps_api_common` the optional `libvirt` feature, which
  pulls native libvirt C bindings via a git dependency. It is **off by default**
  and must be opted into, so crates depending on `lnvps_api_common` are
  unaffected unless they ask for it. Note that `--features libvirt` cannot be
  built on a machine without libvirt installed (fails at link time on macOS);
  this was already true before the move.
- Explicitly **out of scope** for this task, despite being real gaps in the
  agent: SSH-key tools, docs/knowledge-base retrieval, human escalation and
  ticket handoff, and token/cost accounting. Worth a follow-up work file.
- Adversarial coverage is a *sample*, not a proof. The tests pin the controls
  that exist (tool-set restriction, `owned_vm` ownership checks, hand-built
  projections, server-side permission gating) against representative attacks;
  they cannot show the model is unjailbreakable. That is why every one of them
  asserts on a server-side fact — the design intent is that a fully compromised
  model still cannot exceed its tool set or read another customer's row.
- Indirect injection is covered via `ssh_host_keys`, which is the realistic
  vector today (guest-controlled → customer-controlled → surfaced verbatim by
  `get_vm_details`). **Any new tool that surfaces customer-controlled free text
  widens this surface** — VM names, SSH key comments and firewall rule comments
  would all become injection vectors the moment a tool returns them, so add a
  case to `test_chat_resists_indirect_injection_via_tool_output` when that
  happens.
- Still unattacked: token/cost exhaustion (a cheap denial-of-wallet via long
  tool-heavy conversations — related to the missing cross-connection rate
  limit), and encoding tricks (base64/unicode-obfuscated instructions).
- The per-connection turn cap bounds one abusive socket but **not one abusive
  user across many sockets** — a cross-connection budget needs shared state
  (Redis) and is not wired up. Worth doing before this is exposed publicly at
  scale, since each turn costs model tokens.
- The e2e `agent:` block contains a live API key for the shared test model. If
  that endpoint moves or the key rotates, `agent_chat` tests fail on a third
  party being down rather than on this repository changing — consider marking
  them `#[ignore]` in the same way the live-service canaries are, if that
  becomes noisy.
- **Existing on-disk history is orphaned by increment 2.** The standalone binary
  still uses `JsonFileStore`, but conversation keys changed from a bare
  email/pubkey to the namespaced form, and `normalize_key` maps `user:7` and
  `email:bob@x.com` to new filenames. The old files are not deleted, just no
  longer found, so the agent starts each thread fresh. If the deployed agent has
  history worth keeping, a one-off rename pass is needed before shipping — it
  cannot be done automatically because the old key doesn't record whether the
  sender was a resolved customer or which channel they used.
- Increment 2 also changed behaviour for the existing channels: email and Nostr
  now key their conversations differently (and a known customer's email thread
  is keyed `user:<id>`, so it will merge with their live-chat thread once
  increment 5 lands — which is the intent).
- Retention: no automatic pruning is implemented. The corpus grows unbounded by
  design. If a retention window is ever required it needs a policy decision
  first, since it directly conflicts with the training-data goal.
