# Omni Message Provider

A unified Python interface for building chatbots and automated systems across multiple messaging platforms (Discord, Slack, Jira) with optional distributed relay support for scalable deployments.

## Features

- **Unified Interface**: Single `MessageProvider` interface for all platforms
- **Multiple Platforms**: Discord, Slack, Jira, FastAPI (custom), and polling clients
- **Distributed Architecture**: Optional WebSocket relay for microservices deployments
- **High Performance**: MessagePack serialization, WebSocket transport
- **Production Ready**: Kubernetes-ready, auto-reconnection, error handling

## Installation

### Basic Installation

```bash
pip install omni-message-provider
```

### With Platform Support

```bash
# Discord only
pip install omni-message-provider[discord]

# Slack only
pip install omni-message-provider[slack]

# Jira only
pip install omni-message-provider[jira]

# All platforms
pip install omni-message-provider[all]
```

## Quick Start

### Discord Bot

```python
import os
import discord
from message_provider import DiscordMessageProvider

# Configure Discord
intents = discord.Intents.default()
intents.message_content = True

# Create provider
provider = DiscordMessageProvider(
    bot_token=os.getenv("DISCORD_BOT_TOKEN"),
    client_id="discord:my-bot",
    intents=intents,
    trigger_mode="mention",
    command_prefixes=["!support", "!cq"]
)

# Handle messages
def message_handler(message):
    print(f"Received: {message['text']}")

    # Reply
    provider.send_message(
        message="Hello!",
        user_id=message['user_id'],
        channel=message['channel']
    )

provider.register_message_listener(message_handler)
provider.start()
```

### Slack Bot

```python
import os
from message_provider import SlackMessageProvider

provider = SlackMessageProvider(
    bot_token=os.getenv("SLACK_BOT_TOKEN"),
    app_token=os.getenv("SLACK_APP_TOKEN"),
    use_socket_mode=True,
    trigger_mode="mention",
    allowed_channels=["#support", "C12345678"]
)

def message_handler(message):
    provider.send_message(
        message="Got it!",
        user_id=message['user_id'],
        channel=message['channel']
    )

provider.register_message_listener(message_handler)
provider.start()
```

### Jira Issue Monitor

```python
import os
from message_provider import JiraMessageProvider

provider = JiraMessageProvider(
    server="https://company.atlassian.net",
    email=os.getenv("JIRA_EMAIL"),
    api_token=os.getenv("JIRA_API_TOKEN"),
    project_keys=["SUPPORT", "BUG"],
    client_id="jira:main",
    watch_labels=["bot-watching"],
    trigger_phrases=["@bot"]
)

def message_handler(message):
    if message['type'] == 'new_issue':
        # Add comment to ticket
        provider.send_message(
            message="We're on it!",
            channel=message['channel']  # Issue key
        )
        # Add label
        provider.send_reaction(message['channel'], "bot-acknowledged")
        # Change status
        provider.update_message(message['channel'], "In Progress")

provider.register_message_listener(message_handler)
provider.start()
```

## Distributed Architecture

For scalable, Kubernetes-ready deployments:

![Distributed Architecture](https://raw.githubusercontent.com/AgentSanchez/omni-message-provider/main/docs/distributed_architecture.png)

```python
# Message Provider Pod (Discord/Slack/Jira)
from message_provider import DiscordMessageProvider, RelayClient

discord_provider = DiscordMessageProvider(...)
relay_client = RelayClient(
    local_provider=discord_provider,
    relay_hub_url="ws://relay-hub:8765",
    client_id="discord:guild-123"
)
relay_client.start_blocking()

# RelayHub Pod (Central Router)
from message_provider import RelayHub, FastAPIMessageProvider

mp_provider = FastAPIMessageProvider(...)
hub = RelayHub(local_provider=mp_provider, port=8765)
await hub.start()

# Orchestrator Pods (Multiple instances)
from message_provider import RelayMessageProvider

provider = RelayMessageProvider(websocket_url="ws://relay-hub:8765")
provider.register_message_listener(my_handler)
provider.start()
```

## Unified Interface

All providers implement the same interface:

```python
class MessageProvider:
    def send_message(message: str, user_id: str, channel: str = None) -> dict:
        """Send a message"""

    def send_reaction(message_id: str, reaction: str) -> dict:
        """Add a reaction/label"""

    def update_message(message_id: str, new_text: str) -> dict:
        """Update a message/status"""

    def register_message_listener(callback: Callable) -> None:
        """Register callback for incoming messages"""

    def start() -> None:
        """Start the provider (blocking)"""
```

## Platform-Specific Mappings

### Discord
- `send_message()` → Send Discord message
- `send_reaction()` → Add emoji reaction
- `update_message()` → Edit message
- `channel` = Discord channel ID

### Slack
- `send_message()` → Post Slack message
- `send_reaction()` → Add reaction emoji
- `update_message()` → Update message
- `channel` = Slack channel ID

### Jira
- `send_message()` → Add comment to ticket
- `send_reaction()` → Add label to ticket
- `update_message()` → Change ticket status
- `channel` = Jira issue key (e.g., "SUPPORT-123")

## Message Format

All providers return messages in standardized format:

```python
{
    "type": "new_issue" | "new_comment" | "new_message",
    "message_id": "unique-id",
    "text": "message content",
    "user_id": "user-identifier",
    "channel": "channel-identifier",
    "metadata": {
        "client_id": "platform:instance",
        # Platform-specific fields
    }
}
```

### Provider-Specific Fields

Provider-specific data is included under `metadata`. Use it only when needed.

```python
{
    "type": "new_message",
    "message_id": "unique-id",
    "text": "message content",
    "user_id": "user-identifier",
    "channel": "channel-identifier",
    "metadata": {
        "client_id": "platform:instance",
        "provider": "slack",  # comment: "slack", "discord", "jira", "fastapi", "relay"
        "provider_data": {    # comment: provider-specific details (see below)
            # comment: Slack example
            "thread_ts": "1700000000.123456",
            "channel_type": "channel",
            "event_type": "app_mention"
        }
    }
}
```

Slack provider_data (examples):
```python
{
    "thread_ts": "1700000000.123456",  # comment: parent thread timestamp
    "channel_type": "channel",         # comment: channel, group, im, mpim
    "event_type": "app_mention"        # comment: app_mention or message
}
```

Discord provider_data (examples):
```python
{
    "author_name": "User#1234",        # comment: display name
    "author_discriminator": "1234",    # comment: discriminator (if available)
    "guild_id": "1234567890",          # comment: server ID
    "guild_name": "My Server",         # comment: server name
    "channel_name": "support",         # comment: channel name
    "is_thread": False,                # comment: thread flag
    "thread_id": None,                 # comment: thread ID if applicable
    "reference_message_id": None,      # comment: replied-to message ID
    "is_mention": False                # comment: whether the bot was mentioned
}
```

Jira provider_data (examples):
```python
{
    "issue_key": "SUPPORT-123",        # comment: issue key
    "project": "SUPPORT",              # comment: project key
    "project_name": "Support",         # comment: project name
    "issue_type": "Bug",               # comment: issue type
    "priority": "High",                # comment: priority
    "status": "In Progress",           # comment: current status
    "labels": ["bot-watching"],        # comment: issue labels
    "reporter_name": "Jane Doe",       # comment: reporter display name
    "reporter_email": "jane@acme.com",  # comment: reporter email if available
    "created": "2024-01-01T00:00:00Z",  # comment: created timestamp
    "url": "https://.../browse/KEY"     # comment: issue URL
}
```

## Configuration

All providers accept explicit parameters (no environment variables in library):

```python
# User controls their own env var names
provider = DiscordMessageProvider(
    bot_token=os.getenv("MY_DISCORD_TOKEN"),  # Your choice
    client_id=os.getenv("MY_CLIENT_ID"),
    trigger_mode="both",  # "mention", "chat", "command", "both"
    command_prefixes=["!support", "!cq"]
)
```

## Examples

See the `src/message_provider/examples/` directory for complete working examples:
- `discord_example.py` - Discord bot with reactions
- `slack_example.py` - Slack bot with Socket Mode
- `jira_example.py` - Jira issue monitor
- `relay_example.py` - Distributed relay setup
- `polling_client_example.py` - FastAPI polling client

## Development

```bash
# Clone repository
git clone https://github.com/AgentSanchez/omni-message-provider
cd omni-message-provider

# Install with dev dependencies
pip install -e ".[dev,all]"

# Run tests
pytest

# Format code
black src/message_provider/
ruff check src/message_provider/
```

## Requirements

- Python 3.9+
- Core: `fastapi`, `uvicorn`, `websockets`, `msgpack`
- Optional: `discord.py`, `slack-bolt`, `jira`

## License

MIT License - see LICENSE file

## Support

- Documentation: https://github.com/AgentSanchez/omni-message-provider#readme
- Issues: https://github.com/AgentSanchez/omni-message-provider/issues
