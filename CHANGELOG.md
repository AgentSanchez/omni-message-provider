# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.2.0
[0.1.0]: https://github.com/AgentSanchez/omni-message-provider/releases/tag/v0.1.0
