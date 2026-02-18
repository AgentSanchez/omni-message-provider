# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.12] - 2026-02-18

### Added
- **Jira**: Faux integration tests for `trigger_mode` — scenario-style tests covering mention/chat/both modes with dedup and metadata assertions

## [0.2.11] - 2026-02-18

### Added
- **Jira**: `trigger_mode` parameter (`mention`/`chat`/`both`) — in mention mode, only issues and comments containing trigger phrases are dispatched

## [0.2.10] - 2026-02-18

### Added
- **WebhookProvider**: New `WebhookProvider` abstract base class for inbound-only webhook providers
  - Separate from `MessageProvider` — no send_message, send_reaction, update_message, etc.
  - Minimal interface: `register_message_listener`, `start`, `get_app`, `get_formatting_rules`
- **PrometheusWebhookProvider**: Receive Prometheus Alertmanager webhook alerts
  - Accepts Alertmanager webhook POSTs at a configurable endpoint (default `/webhook`)
  - `parse_mode="alertmanager"` (default): Parse standard payload, emit one call per alert with normalized fields
  - `parse_mode="raw"`: Pass through entire JSON payload as-is to listeners
  - Optional `api_key` parameter for simple Bearer token auth
  - Health check at `GET /health`
  - Configurable `client_id`, `host`, `port`, `webhook_path`
- Prometheus example scripts: `prom_example.py` (listener) and `test_prom_alert.py` (test alert sender)
- **Jira**: `startup_delay` parameter (default 120s) — delays first poll to avoid re-processing old events on restart
- **Jira**: In-memory dedup of seen issue/comment IDs prevents re-dispatch within a run

### Changed
- `MessageProvider.send_reaction()` and `MessageProvider.update_message()` now include `channel: Optional[str] = None` in the base ABC signature
- `JiraMessageProvider.send_reaction()` and `JiraMessageProvider.update_message()` updated to match (parameter accepted but unused)

## [0.2.8] - 2026-02-16

### Added
- **Reaction Listeners**: New `register_reaction_listener(callback)` method across all providers
  - Discord: Listen to emoji reactions via `on_reaction_add` event
  - Slack: Listen to reactions via `reaction_added` event
  - FastAPI: New `/reaction/process` endpoint for incoming reactions
  - httpSMS/Jira: No-op (platforms don't support reactions)
- **Thread Clear**: New `clear_thread(channel, metadata)` and `register_thread_clear_listener(callback)` on all providers
  - Signal when a conversation should end
  - Useful for session management and cleanup
- httpSMS: New `HttpSmsMessageProvider` for [httpSMS](https://github.com/NdoleStudio/httpsms) integration
- httpSMS: Turn your Android phone into an SMS gateway
- httpSMS: Webhook receiver at `/webhook` for incoming messages
- httpSMS: Pluggable `message_authenticator` callback for authenticating incoming messages
- httpSMS: Built-in `/help` and `/clear` commands
- httpSMS: `help_text` parameter for custom help message
- httpSMS: `initial_text` parameter for welcome message to new conversations
- httpSMS: Timestamp-based message IDs

## [0.2.6] - 2026-02-11

### Added
- FastAPI: `provider_id` required parameter for provider identification
- FastAPI: Pluggable authentication layer with `authentication_provider` and `session_validator` callbacks
- FastAPI: Subscriber registration with `user_id` field and optional `auth_details`
- FastAPI: Re-registration support with existing `subscriber_id`
- FastAPI: Unified message types (`message`, `status_request`, `cancellation_request`) via single endpoint
- FastAPI: Request context cleanup with configurable TTL (`request_context_ttl`, default 1 hour)
- FastAPI: Max request context limit to prevent memory leaks (`max_request_contexts`, default 10000)

### Changed
- FastAPI: Renamed "registered clients" to "subscribers" for clarity
- FastAPI: `channel` field now required in incoming messages (must be valid `subscriber_id`)
- FastAPI: All requests go through `POST /message/process` with `type` field
- FastAPI: Removed separate `/status/{request_id}` and `/cancel/{request_id}` endpoints
- FastAPI: Status and cancellation requests are now message types handled by orchestrator

### Removed
- FastAPI: Automatic status message queueing (orchestrator sends messages directly)

## [0.2.5] - 2026-02-02
### Added
- Slack: in "mention" mode, thread replies are forwarded if the bot has previously responded in that thread (`active_thread_ttl` configurable, default 24h)
- Add permission debug to help troubleshoot Slack permission issues

## [0.2.4] - 2026-02-02
### Added
- Publish workflow now blocks on security scans

### Changed
- Version fix

## [0.2.3] - 2026-02-01
### Added
- Security scanning workflow in CI (pip-audit, bandit, semgrep)

### Changed
- Version fix

## [0.2.2] - 2026-02-01

### Added
- Slack: user email included in message metadata via profile lookup (`metadata.user_email`)

## [0.2.1] - 2026-02-01

### Changed
- Providers are now stateless: removed internal message/channel caching from Slack, Discord, and Jira
- Relay provider, hub, and client forward `channel` through the full dispatch chain
- Added changes to support other type checking

## [0.2.0] - 2026-02-01

### Added
- Slack: trigger mode (mention/chat/both), channel allowlist by name/ID, app_mention handler, and duplicate-event suppression
- Discord: trigger mode (mention/chat/command/both), command prefixes, and mention metadata flag
- Jira: startup ignore of pre-existing issues/comments and safer polling time handling
- Documentation updates for new configuration options and provider-specific metadata

### Changed
- Discord listener dispatch no longer blocks the event loop (avoids heartbeat stalls)
- FastAPI provider responses include success status and message IDs for outgoing sends
- WebSocket relay hub updated for modern websockets server types

## [0.1.0] - 2024-01-31

### Added
- Initial release of message-provider package
- `MessageProvider` abstract base class defining unified interface
- `DiscordMessageProvider` - Discord bot integration using discord.py
- `SlackMessageProvider` - Slack bot integration using slack-bolt (Socket Mode and HTTP Mode)
- `JiraMessageProvider` - Jira integration with polling-based issue and comment monitoring
- `FastAPIMessageProvider` - REST API message provider with polling and webhook support
- Relay system for distributed K8s architecture:
  - `RelayHub` - WebSocket server for routing messages between providers and orchestrators
  - `RelayMessageProvider` - WebSocket client for orchestrator pods
  - `RelayClient` - Wraps message providers to connect to RelayHub
- WebSocket + MessagePack for high-performance bidirectional relay
- Routing cache with sticky sessions based on (user_id, channel, client_id)
- Webhook system with HMAC signature verification
- Comprehensive examples for all providers
- Full test suite with pytest
- MIT License

### Features
- **Send messages** - `send_message(message, user_id, channel, previous_message_id)`
- **Send reactions** - `send_reaction(message_id, reaction)`
- **Update messages** - `update_message(message_id, new_text)`
- **Message listeners** - `register_message_listener(callback)`
- **Distributed routing** - Consistent routing with stable client_id across pod restarts

### Platform Support
- Discord - Full support with async message handling, reactions, and message editing
- Slack - Socket Mode and HTTP Mode support with threading
- Jira - Polling-based with issue creation monitoring and comment watching (labels + trigger phrases)
- FastAPI - REST API with queue-based message delivery

### Documentation
- Comprehensive README with installation, usage examples, and architecture diagrams
- Platform-specific mapping documentation (Jira: channel=issue_key, reaction=label, update=status)
- Example files for all providers and relay components
- Test documentation with coverage guidelines

[0.2.11]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.2.11
[0.2.10]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.2.10
[0.2.8]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.2.8
[0.2.7]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.2.7
[0.2.6]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.2.6
[0.2.5]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.2.5
[0.2.2]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.2.2
[0.2.3]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.2.3
[0.2.4]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.2.4
[0.2.1]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.2.1
[0.2.0]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.2.0
[0.1.0]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.1.0
