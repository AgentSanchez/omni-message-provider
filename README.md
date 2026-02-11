# Omni Message Provider

A unified Python interface for building chatbots and automated systems across multiple messaging platforms (Discord, Slack, Jira) with optional distributed relay support for scalable deployments.

## Features

- **Unified Interface**: Single `MessageProvider` interface for all platforms
- **Multiple Platforms**: Discord, Slack, Jira, FastAPI (HTTP/REST), and polling clients
- **Distributed Architecture**: Optional WebSocket relay for microservices deployments
- **Authentication Layer**: Pluggable authentication for HTTP provider
- **Request Tracking**: Status updates and cancellation support
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

    channel = message['channel']
    message_id = message['message_id']

    # Reply (threads the response)
    provider.send_message(
        message="Hello!",
        user_id=message['user_id'],
        channel=channel,
        previous_message_id=message_id
    )

    # React to the original message
    provider.send_reaction(message_id, "👍", channel=channel)

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
    client_id="slack:my-workspace",
    use_socket_mode=True,
    trigger_mode="mention",
    allowed_channels=["#support", "C12345678"]
)

def message_handler(message):
    channel = message['channel']
    message_id = message['message_id']

    # Reply in thread (previous_message_id is used as thread_ts)
    provider.send_message(
        message="Got it!",
        user_id=message['user_id'],
        channel=channel,
        previous_message_id=message_id
    )

    # React to the original message
    provider.send_reaction(message_id, "eyes", channel=channel)

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
            user_id="bot",
            channel=message['channel']  # Issue key
        )
        # Add label
        provider.send_reaction(message['channel'], "bot-acknowledged")
        # Change status
        provider.update_message(message['channel'], "In Progress")

provider.register_message_listener(message_handler)
provider.start()
```

### FastAPI/HTTP Provider

The HTTP provider allows external clients to connect via REST API. It uses a unified message endpoint where all requests (messages, status requests, cancellations) go through the same API with a `type` field.

```python
import os
from message_provider import FastAPIMessageProvider

# Basic setup (no authentication)
provider = FastAPIMessageProvider(
    provider_id="http:my-service",
    api_key=os.getenv("API_KEY"),  # Optional server-level API key
    host="0.0.0.0",
    port=9547
)

# Handle incoming messages from HTTP clients
def message_handler(message):
    msg_type = message.get('type', 'message')
    channel = message['channel']

    if msg_type in ('message', 'new_message'):
        # Regular message
        print(f"Received from {message['user_id']}: {message['text']}")

        # Send reply back to the subscriber
        provider.send_message(
            message="I received your message!",
            user_id="bot",
            channel=channel,
            previous_message_id=message['message_id']
        )

    elif msg_type == 'status_request':
        # Client requesting status update
        request_id = message.get('request_id')
        print(f"Status requested for {request_id}")
        # Look up status and send reply message

    elif msg_type == 'cancellation_request':
        # Client requesting cancellation
        request_id = message.get('request_id')
        print(f"Cancellation requested for {request_id}")
        # Handle cancellation logic

provider.register_message_listener(message_handler)
provider.start()
```

## FastAPI Provider Authentication

The FastAPI provider supports a pluggable authentication layer with two callbacks:

### Authentication Provider

Called during subscriber registration to validate credentials and issue session tokens:

```python
def my_auth_provider(user_id: str, auth_details: dict) -> dict:
    """
    Validate user credentials at registration time.

    Args:
        user_id: The user ID provided during registration
        auth_details: Dict containing credentials (password, token, etc.)

    Returns:
        Dict with:
        - "allowed": bool (required) - Whether registration is allowed
        - "session_token": str (optional) - Token for subsequent requests
        - "reason": str (optional) - Reason for rejection
        - Any additional fields are stored with the subscriber
    """
    # Example: Check against your user database
    if not validate_user(user_id, auth_details.get("password")):
        return {"allowed": False, "reason": "Invalid credentials"}

    # Generate a session token
    session_token = generate_token(user_id)

    return {
        "allowed": True,
        "session_token": session_token,
        "user_role": "standard"  # Extra data stored with subscriber
    }
```

### Session Validator

Called on each request to validate the session token:

```python
def my_session_validator(subscriber_id: str, session_token: str) -> bool:
    """
    Validate session token on each request.

    Args:
        subscriber_id: The subscriber's UUID
        session_token: Token from Authorization header

    Returns:
        True if valid, False otherwise
    """
    # Example: Validate token against your session store
    return validate_token(session_token)
```

### Complete Authentication Example

```python
from message_provider import FastAPIMessageProvider

# Simple in-memory auth (use a real database in production)
users = {"alice": "password123", "bob": "secret456"}
sessions = {}

def auth_provider(user_id: str, auth_details: dict) -> dict:
    password = auth_details.get("password")
    if users.get(user_id) != password:
        return {"allowed": False, "reason": "Invalid credentials"}

    import uuid
    token = str(uuid.uuid4())
    sessions[token] = user_id
    return {"allowed": True, "session_token": token}

def session_validator(subscriber_id: str, session_token: str) -> bool:
    return session_token in sessions

provider = FastAPIMessageProvider(
    provider_id="http:authenticated-service",
    authentication_provider=auth_provider,
    session_validator=session_validator
)
```

### Client Registration Flow

1. **Register**: Client sends credentials, receives `subscriber_id` and `session_token`
2. **Send Messages**: All requests go through `POST /message/process` with `type` field
3. **Receive Replies**: Client polls `GET /messages/{subscriber_id}` for responses
4. **Re-register**: Client can re-register with same `subscriber_id` to refresh session

```python
# 1. Register
POST /subscriber/register
{
    "user_id": "alice",
    "auth_details": {"password": "password123"},
    "source_type": "web"
}

# Response
{
    "status": "registered",
    "subscriber_id": "uuid-here",
    "session_token": "token-here"
}

# 2. Send message
POST /message/process
Authorization: Bearer <session_token>
{
    "type": "message",
    "user_id": "alice",
    "text": "Hello!",
    "channel": "uuid-here"
}

# 3. Request status (same endpoint, different type)
POST /message/process
Authorization: Bearer <session_token>
{
    "type": "status_request",
    "user_id": "alice",
    "channel": "uuid-here",
    "request_id": "msg_abc123"
}

# 4. Poll for all responses
GET /messages/{subscriber_id}
Authorization: Bearer <session_token>
```

## Unified Message Types

All client requests go through `POST /message/process` with a `type` field:

| Type | Description | Required Fields |
|------|-------------|-----------------|
| `message` | Regular text message (default) | `text`, `user_id`, `channel` |
| `status_request` | Request status of a previous message | `user_id`, `channel`, `request_id` |
| `cancellation_request` | Request cancellation of active work | `user_id`, `channel`, `request_id` |

```python
# Send a regular message
POST /message/process
{
    "type": "message",
    "text": "Hello!",
    "user_id": "alice",
    "channel": "subscriber-uuid"
}

# Request status update
POST /message/process
{
    "type": "status_request",
    "user_id": "alice",
    "channel": "subscriber-uuid",
    "request_id": "msg_abc123"
}

# Request cancellation
POST /message/process
{
    "type": "cancellation_request",
    "user_id": "alice",
    "channel": "subscriber-uuid",
    "request_id": "msg_abc123"
}
```

The orchestrator receives all message types through the same listener and handles them based on type:

```python
# Register listeners for specific events (optional)
provider.register_request_status_update_listener(
    lambda req_id, info: print(f"Status request for {req_id}")
)

provider.register_request_cancellation_listener(
    lambda req_id, info: print(f"Cancellation for {req_id}")
)

# Main message handler receives everything
def message_handler(message):
    msg_type = message.get('type', 'message')

    if msg_type == 'status_request':
        # Client wants status - send a message back with current status
        provider.send_message(
            message=f"Status: processing",
            user_id="bot",
            channel=message['channel']
        )
    elif msg_type == 'cancellation_request':
        # Handle cancellation
        pass
    else:
        # Regular message processing
        pass
```

## Distributed Architecture

For scalable, Kubernetes-ready deployments:

```
┌─────────────────┐
│ SlackProvider   │──► RelayClient (client_id="slack:ws1") ──┐
└─────────────────┘                                          │
                                                             │ WS
┌─────────────────┐                                          ▼
│ DiscordProvider │──► RelayClient (client_id="discord:g1") ──► RelayHub
└─────────────────┘                                          ▲
                                                             │ WS
┌─────────────────┐                                          │
│ Orchestrator    │◄─► RelayMessageProvider ─────────────────┘
└─────────────────┘
```

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

mp_provider = FastAPIMessageProvider(provider_id="http:hub")
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
    def send_message(message: str, user_id: str, channel: str = None,
                     previous_message_id: str = None) -> dict:
        """Send a message. Use previous_message_id to reply in a thread."""

    def send_reaction(message_id: str, reaction: str, channel: str = None) -> dict:
        """Add a reaction/label. channel is required for Discord, Slack, FastAPI."""

    def update_message(message_id: str, new_text: str, channel: str = None) -> dict:
        """Update a message/status. channel is required for Discord, Slack, FastAPI."""

    def register_message_listener(callback: Callable) -> None:
        """Register callback for incoming messages"""

    def start() -> None:
        """Start the provider (blocking)"""

    def get_formatting_rules() -> str:
        """Return formatting syntax for this provider (mrkdwn, markdown, plaintext, jira)"""

    def request_status_update(request_id: str, channel: str = None) -> dict:
        """Get status of a request (FastAPI only)"""

    def register_request_status_update_listener(callback: Callable) -> None:
        """Register callback for status updates (FastAPI only)"""

    def request_cancellation(request_id: str, channel: str = None) -> dict:
        """Request cancellation of active request (FastAPI only)"""

    def register_request_cancellation_listener(callback: Callable) -> None:
        """Register callback for cancellation requests (FastAPI only)"""
```

Providers are stateless -- they do not cache message or channel metadata internally. The application is responsible for tracking conversation state.

## Platform-Specific Mappings

### Discord
- `client_id` = Provider instance identifier (e.g., "discord:my-bot")
- `channel` = Discord channel ID
- `send_message()` → Send Discord message (uses `previous_message_id` as reply reference)
- `send_reaction(channel=...)` → Add emoji reaction (channel required)
- `update_message(channel=...)` → Edit message (channel required)
- `get_formatting_rules()` → Returns "markdown"

### Slack
- `client_id` = Provider instance identifier (e.g., "slack:my-workspace")
- `channel` = Slack channel ID
- `send_message()` → Post Slack message (uses `previous_message_id` as `thread_ts`)
- `send_reaction(channel=...)` → Add reaction emoji (channel required)
- `update_message(channel=...)` → Update message (channel required)
- `get_formatting_rules()` → Returns "mrkdwn"

### Jira
- `client_id` = Provider instance identifier (e.g., "jira:main")
- `channel` = Jira issue key (e.g., "SUPPORT-123")
- `send_message()` → Add comment to ticket
- `send_reaction()` → Add label to ticket
- `update_message()` → Change ticket status
- `get_formatting_rules()` → Returns "jira"

### FastAPI/HTTP
- `provider_id` = Provider instance identifier (e.g., "http:my-service")
- `channel` = Subscriber UUID (returned at registration)
- `send_message(channel=...)` → Send to specific subscriber (channel required)
- `send_reaction(channel=...)` → Send reaction to subscriber (channel required)
- `update_message(channel=...)` → Send update to subscriber (channel required)
- `get_formatting_rules()` → Returns "plaintext"

## Message Format

All providers return messages in standardized format:

```python
{
    "type": "new_issue" | "new_comment" | "new_message",
    "message_id": "unique-id",
    "text": "message content",
    "user_id": "user-identifier",
    "channel": "channel-identifier",
    "thread_id": "thread-identifier",  # Optional
    "metadata": {
        "client_id": "platform:instance",  # or "provider_id" for FastAPI
        # Platform-specific fields
    }
}
```

## Configuration

All providers accept explicit parameters (no environment variables in library):

```python
# Discord
provider = DiscordMessageProvider(
    bot_token=os.getenv("MY_DISCORD_TOKEN"),
    client_id="discord:my-bot",
    trigger_mode="both",  # "mention", "chat", "command", "both"
    command_prefixes=["!support", "!cq"]
)

# Slack
provider = SlackMessageProvider(
    bot_token=os.getenv("SLACK_BOT_TOKEN"),
    app_token=os.getenv("SLACK_APP_TOKEN"),
    client_id="slack:my-workspace",
    use_socket_mode=True,
    trigger_mode="mention",
    allowed_channels=["#support"]
)

# FastAPI/HTTP
provider = FastAPIMessageProvider(
    provider_id="http:my-service",
    api_key=os.getenv("API_KEY"),  # Optional server-level key
    authentication_provider=my_auth_func,  # Optional
    session_validator=my_validator_func,   # Optional
    request_context_ttl=3600,              # Cleanup tracked requests after 1 hour (default)
    max_request_contexts=10000,            # Force cleanup if exceeds this count (default)
    session_validator=my_validator_func,   # Optional
    host="0.0.0.0",
    port=9547
)
```

## Examples

See the `src/message_provider/examples/` directory for complete working examples:
- `discord_example.py` - Discord bot with reactions
- `slack_example.py` - Slack bot with Socket Mode
- `jira_example.py` - Jira issue monitor
- `relay_example.py` - Distributed relay setup
- `polling_client_example.py` - FastAPI polling client with status tracking

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
