# Omni Message Provider

A unified Python interface for building chatbots and automated systems across multiple messaging platforms (Discord, Slack, Jira, httpSMS) with optional distributed relay support for scalable deployments. Also supports inbound-only webhook providers (Prometheus Alertmanager).

## Features

- **Unified Interface**: Single `MessageProvider` interface for all platforms
- **Webhook Providers**: Inbound-only `WebhookProvider` base class for services that push data in (Prometheus Alertmanager)
- **Multiple Platforms**: Discord, Slack, Jira, httpSMS, Prometheus, FastAPI (HTTP/REST), and polling clients
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

### httpSMS Provider

[httpSMS](https://github.com/NdoleStudio/httpsms) turns your Android phone into an SMS gateway. This provider integrates with the httpSMS API to send and receive SMS messages.

**Setup:** See [httpSMS GitHub](https://github.com/NdoleStudio/httpsms) for installation and configuration.

**Built-in commands:**
- `/help` - Sends help text to the user
- `/clear` - Ends the conversation (triggers thread clear listeners)

```python
import os
from message_provider import HttpSmsMessageProvider

provider = HttpSmsMessageProvider(
    api_key=os.getenv("HTTPSMS_API_KEY"),
    phone_number="+15551234567",  # Your phone number registered with httpSMS
    client_id="httpsms:main",
    help_text="Commands: /help, /clear. Or just send a message!",  # Optional
    initial_text="Welcome! Send /help for available commands."  # Optional: sent to new users
)

def message_handler(message):
    sender = message['user_id']  # Sender's phone number (= channel)
    text = message['text']

    # Reply to the sender
    provider.send_message(
        message=f"Thanks for your message: {text}",
        user_id="bot",
        channel=sender  # Recipient phone number
    )

# Handle conversation endings (from /clear or programmatic clear_thread)
def on_thread_clear(channel, metadata):
    print(f"Conversation with {channel} ended: {metadata.get('reason')}")

provider.register_message_listener(message_handler)
provider.register_thread_clear_listener(on_thread_clear)
provider.start()  # Starts webhook server on port 9548

# Programmatically end a conversation:
# provider.clear_thread("+15559876543", metadata={"reason": "task_complete"})
```

### Prometheus Alertmanager Webhook

`PrometheusWebhookProvider` is an inbound-only provider that receives [Prometheus Alertmanager](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config) webhook POSTs. Unlike `MessageProvider`, it extends `WebhookProvider` — a separate base class for services that only push data in (no send_message, send_reaction, etc.).

```python
import os
from message_provider import PrometheusWebhookProvider

provider = PrometheusWebhookProvider(
    client_id="prometheus:prod",
    parse_mode="alertmanager",  # or "raw" for full payload pass-through
    api_key=os.getenv("WEBHOOK_API_KEY"),  # Optional auth
    port=9549,
)

def alert_handler(alert):
    status = alert['status']       # "firing" or "resolved"
    text = alert['text']           # annotations.summary or description
    labels = alert['labels']       # { "alertname": "...", "severity": "...", ... }
    alert_id = alert['alert_id']   # fingerprint

    print(f"[{status.upper()}] {labels.get('alertname')}: {text}")

provider.register_message_listener(alert_handler)
provider.start()  # Starts webhook server on port 9549
```

Configure Alertmanager to POST to `http://your-host:9549/webhook`.

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `client_id` | `str` | `"prometheus:default"` | Unique identifier for this provider instance |
| `parse_mode` | `str` | `"alertmanager"` | `"alertmanager"` to normalize per-alert, or `"raw"` for full payload pass-through |
| `api_key` | `str \| None` | `None` | Optional Bearer token for authenticating incoming webhooks |
| `host` | `str` | `"0.0.0.0"` | Webhook server bind address |
| `port` | `int` | `9549` | Webhook server port |
| `webhook_path` | `str` | `"/webhook"` | Path for the webhook endpoint |

#### Parse Modes

**`"alertmanager"` (default)** — Parses the standard Alertmanager payload and emits one listener call **per alert** with normalized fields:

```python
{
    "type": "alert",
    "alert_id": "abc123",              # fingerprint (or generated UUID)
    "status": "firing",                # "firing" or "resolved"
    "text": "Memory usage is above 90%",  # annotations.summary or .description
    "labels": {"alertname": "HighMemory", "severity": "critical", ...},
    "annotations": {"summary": "...", "description": "...", ...},
    "starts_at": "2026-02-18T10:00:00.000Z",
    "ends_at": "0001-01-01T00:00:00Z",  # or actual end time for resolved
    "generator_url": "http://prometheus:9090/graph?...",
    "channel": "{}:{alertname=\"HighMemory\"}",  # groupKey or alertname
    "metadata": {
        "client_id": "prometheus:prod",
        "receiver": "webhook-test",
        "external_url": "http://alertmanager:9093",
        "group_labels": {"alertname": "HighMemory"},
        "common_labels": {...},
        "common_annotations": {...},
        "raw_payload": {...}           # full original Alertmanager payload
    },
    "timestamp": "2026-02-18T10:00:05.123Z"  # when the webhook was received
}
```

**`"raw"`** — Passes the entire JSON body as-is. One listener call per POST regardless of how many alerts are in the payload:

```python
{
    "type": "alert",
    "text": "<str representation of payload>",
    "channel": "prometheus:prod",      # client_id
    "metadata": {
        "client_id": "prometheus:prod",
        "raw_payload": {...}           # full original payload
    },
    "timestamp": "2026-02-18T10:00:05.123Z"
}
```

#### API Key Authentication

When `api_key` is set, every POST to the webhook endpoint must include an `Authorization` header:

```
Authorization: Bearer <your-api-key>
```

Requests without a valid key receive `401 Unauthorized`. The `GET /health` endpoint is always unauthenticated.

#### Alertmanager Configuration

Point Alertmanager's webhook receiver at your provider:

```yaml
# alertmanager.yml
receivers:
  - name: 'omni-webhook'
    webhook_configs:
      - url: 'http://your-host:9549/webhook'
        # If using api_key authentication:
        http_config:
          authorization:
            type: Bearer
            credentials: 'your-api-key'
```

#### Testing Locally

Two example scripts are provided for local development:

```bash
# Terminal 1: Start the listener
python -m message_provider.examples.prom_example

# Terminal 2: Fire a test alert
python -m message_provider.examples.test_prom_alert localhost:9549
```

`test_prom_alert.py` sends a realistic Alertmanager payload to the given host:port. Use `--resolved` to send a resolved alert, `--api-key` to include auth, and `--raw` to send a minimal non-Alertmanager payload. See `--help` for all options.

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

## Reaction Listeners

Listen for incoming reactions (emojis) from users on messages:

```python
# Discord and Slack have native reaction support
def reaction_handler(reaction):
    print(f"User {reaction['user_id']} reacted with {reaction['reaction']}")
    print(f"On message {reaction['message_id']} in {reaction['channel']}")

    # Reaction data includes:
    # - message_id: ID of the message that was reacted to
    # - reaction: The emoji (e.g., "👍" or "thumbsup")
    # - user_id: Who reacted
    # - channel: Where the reaction occurred
    # - metadata: Provider-specific metadata

provider.register_reaction_listener(reaction_handler)
```

### FastAPI Reaction Endpoint

HTTP clients can send reactions via `POST /reaction/process`:

```python
POST /reaction/process
Authorization: Bearer <session_token>
{
    "message_id": "msg_abc123",
    "reaction": "👍",
    "user_id": "alice",
    "channel": "subscriber-uuid"
}
```

## Thread Clear Events

Signal when a conversation should end. Useful for session management:

```python
def on_thread_clear(channel, metadata):
    print(f"Conversation in {channel} ended: {metadata}")
    # Clean up session state, context, etc.

provider.register_thread_clear_listener(on_thread_clear)

# Programmatically end a conversation
provider.clear_thread("channel-123", metadata={"reason": "task_complete"})
```

For httpSMS, users can type `/clear` to trigger this event.

## Unified Message Types

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

    def register_reaction_listener(callback: Callable) -> None:
        """Register callback for incoming reactions (Discord, Slack, FastAPI)"""

    def clear_thread(channel: str, metadata: dict = None) -> dict:
        """Signal that a conversation should end"""

    def register_thread_clear_listener(callback: Callable) -> None:
        """Register callback for thread clear events"""

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

### httpSMS
- `client_id` = Provider instance identifier (e.g., "httpsms:main")
- `channel` = Recipient phone number (e.g., "+15559876543")
- `send_message(channel=...)` → Send SMS to phone number (channel required)
- `send_reaction(channel=...)` → Send reaction as text message "[emoji]" (channel required)
- `update_message(channel=...)` → Send update as text message "[Update] ..." (channel required)
- `get_formatting_rules()` → Returns "plaintext"
- **Setup:** [httpSMS GitHub](https://github.com/NdoleStudio/httpsms)

### Prometheus Alertmanager (WebhookProvider)
- `client_id` = Provider instance identifier (e.g., "prometheus:prod")
- `channel` = groupKey or alertname
- Inbound-only: no `send_message`, `send_reaction`, `update_message`
- `register_message_listener()` receives normalized alert dicts
- `parse_mode="alertmanager"` → one listener call per alert
- `parse_mode="raw"` → one listener call with full payload
- `get_formatting_rules()` → Returns "plaintext"

### FastAPI/HTTP
- `provider_id` = Provider instance identifier (e.g., "http:my-service")
- `channel` = Subscriber UUID (returned at registration)
- `send_message(channel=...)` → Send to specific subscriber (channel required)
- `send_reaction(channel=...)` → Send reaction to subscriber (channel required)
- `update_message(channel=...)` → Send update to subscriber (channel required)
- `get_formatting_rules()` → Returns "plaintext"

## Message Format

All providers use the same message structure for incoming and outgoing messages:

```python
{
    "type": "message",              # See message types below
    "message_id": "msg_abc123",
    "text": "message content",      # Optional for non-message types
    "user_id": "user-identifier",
    "channel": "channel-identifier",
    "thread_id": "thread-identifier",  # Optional
    "request_id": "msg_xyz789",     # For status/cancellation requests
    "metadata": {
        "provider_id": "http:my-service",  # or "client_id" for Discord/Slack/Jira
        # Platform-specific fields
    },
    "timestamp": "2026-02-11T10:30:00Z"
}
```

### Message Types

| Type | Description | Key Fields |
|------|-------------|------------|
| `message` | Regular text message | `text` (required) |
| `status_request` | Client requesting status update | `request_id` |
| `cancellation_request` | Client requesting cancellation | `request_id` |
| `reaction` | Emoji/label reaction | `reaction`, `message_id` |
| `update` | Message edit/update | `text`, `message_id` |

For Discord/Slack/Jira, incoming messages use types like `new_message`, `new_issue`, `new_comment`.
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

# httpSMS (https://github.com/NdoleStudio/httpsms)
provider = HttpSmsMessageProvider(
    api_key=os.getenv("HTTPSMS_API_KEY"),
    phone_number="+15551234567",
    client_id="httpsms:main",
    message_authenticator=my_auth_func,  # Optional: authenticate incoming messages
    help_text="Custom help message",     # Optional: sent on /help command
    initial_text="Welcome message",      # Optional: sent to new conversations
    host="0.0.0.0",
    port=9548
)

# FastAPI/HTTP
provider = FastAPIMessageProvider(
    provider_id="http:my-service",
    api_key=os.getenv("API_KEY"),  # Optional server-level key
    authentication_provider=my_auth_func,  # Optional
    session_validator=my_validator_func,   # Optional
    request_context_ttl=3600,              # Cleanup tracked requests after 1 hour (default)
    max_request_contexts=10000,            # Force cleanup if exceeds this count (default)
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
- `prom_example.py` - Prometheus Alertmanager webhook listener
- `test_prom_alert.py` - Fire test alerts at a running Prometheus provider

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
