import logging
import time
from typing import Optional, Callable, Dict, Any, List, Set, Tuple
from message_provider.message_provider import MessageProvider

log = logging.getLogger(__name__)

try:
    from slack_bolt import App
    from slack_bolt.adapter.socket_mode import SocketModeHandler
    from slack_sdk.errors import SlackApiError
    _SLACK_AVAILABLE = True
except ImportError:
    App = None
    SocketModeHandler = None
    SlackApiError = None
    _SLACK_AVAILABLE = False


_PERMISSION_ERRORS = frozenset({
    "missing_scope", "not_authed", "invalid_auth", "token_revoked",
    "account_inactive", "no_permission", "org_login_required",
    "ekm_access_denied",
})


class SlackMessageProvider(MessageProvider):
    """
    Slack implementation of MessageProvider using Slack Bolt framework.

    Supports both Socket Mode (no public URL needed) and HTTP mode.

    Args:
        bot_token: Slack Bot User OAuth Token (xoxb-...) - Required
        client_id: Unique identifier for this instance (e.g., "slack:workspace-T01234").
                   Required for distributed relay routing to maintain consistency across restarts.
        app_token: App-level token for Socket Mode (xapp-...) - Required if use_socket_mode=True
        signing_secret: Signing secret for HTTP mode - Required if use_socket_mode=False
        use_socket_mode: Whether to use Socket Mode (True) or HTTP mode (False). Default: True
        token_verification_enabled: Whether to call Slack auth.test on initialization.
                                    Default: False (avoids network calls during init)
        allowed_channels: Optional list of Slack channel IDs to accept incoming messages from.
                          If provided, messages from other channels are ignored.
                          Names like "#general" are supported if the token has conversations:read.
        trigger_mode: Controls which events trigger callbacks. Options:
                      "mention" (only app mentions), "chat" (only messages), "both" (default).
                      In "mention" mode, thread replies are still forwarded if the bot has
                      previously sent a message in that thread.
        active_thread_ttl: Seconds to track threads the bot has participated in.
                           Used by "mention" mode for thread reply forwarding. Default: 86400 (24h).

    Usage:
        # Socket Mode (recommended for development)
        import os
        provider = SlackMessageProvider(
            bot_token=os.getenv("SLACK_BOT_TOKEN"),
            client_id="slack:my-workspace",  # Stable identifier
            app_token=os.getenv("SLACK_APP_TOKEN"),
            use_socket_mode=True
        )
        provider.register_message_listener(my_handler)
        provider.start()

        # HTTP Mode (for production with public URL)
        provider = SlackMessageProvider(
            bot_token=os.getenv("SLACK_BOT_TOKEN"),
            client_id="slack:my-workspace",  # Stable identifier
            signing_secret=os.getenv("SLACK_SIGNING_SECRET"),
            use_socket_mode=False
        )
        provider.start(port=3000)
    """

    def __init__(
        self,
        bot_token: str,
        client_id: str,
        app_token: Optional[str] = None,
        signing_secret: Optional[str] = None,
        use_socket_mode: bool = True,
        token_verification_enabled: bool = False,
        allowed_channels: Optional[List[str]] = None,
        trigger_mode: str = "both",
        active_thread_ttl: float = 86400.0,
    ):
        super().__init__()

        if not _SLACK_AVAILABLE:
            raise ImportError(
                "slack-bolt and slack-sdk libraries are required for SlackMessageProvider. "
                "Install with: pip install omni-message-provider[slack]"
            )

        # Validation
        if not bot_token:
            raise ValueError("bot_token is required")
        if not client_id:
            raise ValueError("client_id is required for distributed relay routing")

        if use_socket_mode and not app_token:
            raise ValueError("app_token is required for Socket Mode")

        if not use_socket_mode and not signing_secret:
            raise ValueError("signing_secret is required for HTTP mode")

        # Configuration
        self.bot_token = bot_token
        self.client_id = client_id
        self.app_token = app_token
        self.signing_secret = signing_secret
        self.use_socket_mode = use_socket_mode
        self.token_verification_enabled = token_verification_enabled
        self.allowed_channels: Optional[Set[str]] = set(allowed_channels) if allowed_channels else None
        self.trigger_mode = trigger_mode.lower().strip()
        if self.trigger_mode not in {"mention", "chat", "both"}:
            raise ValueError("trigger_mode must be one of: 'mention', 'chat', 'both'")
        self.allowed_channel_names: Set[str] = set()
        self._channel_name_cache: Dict[str, str] = {}
        self._recent_message_ids: Dict[str, float] = {}
        self._recent_message_ttl_sec = 5.0
        self._active_threads: Dict[str, float] = {}
        self._active_thread_ttl_sec = active_thread_ttl

        # Initialize Slack Bolt app
        self.app = App(
            token=self.bot_token,
            signing_secret=self.signing_secret,
            token_verification_enabled=self.token_verification_enabled
        )

        if self.allowed_channels:
            resolved_ids, unresolved_names = self._resolve_allowed_channels(self.allowed_channels)
            self.allowed_channels = resolved_ids
            self.allowed_channel_names = unresolved_names
            if self.allowed_channel_names:
                log.warning(
                    "[SlackMessageProvider] Unresolved channel names (will resolve on demand): %s",
                    ", ".join(sorted(self.allowed_channel_names))
                )

        # Message listeners
        self.message_listeners = []
        self.thread_clear_listeners = []

        # Setup event handlers
        self._setup_handlers()

        log.info(f"[SlackMessageProvider] Initialized in {'Socket' if self.use_socket_mode else 'HTTP'} mode with client_id: {client_id}")

    def _setup_handlers(self):
        """Setup Slack event handlers."""

        def _try_claim_message(message_id: Optional[str]) -> bool:
            """Atomically claim a message ID. Returns True if this is the first claim."""
            if not message_id:
                return False
            now = time.monotonic()
            # Prune old entries
            cutoff = now - self._recent_message_ttl_sec
            stale = [mid for mid, ts in self._recent_message_ids.items() if ts < cutoff]
            for mid in stale:
                self._recent_message_ids.pop(mid, None)
            # setdefault is atomic in CPython — first caller wins
            existing = self._recent_message_ids.setdefault(message_id, now)
            return existing == now

        @self.app.event("app_mention")
        def handle_app_mention_events(event, say):
            """Handle Slack app mentions."""
            if self.trigger_mode == "chat":
                return
            # Ignore bot messages and message changes
            if event.get("subtype") in ["bot_message", "message_changed", "message_deleted"]:
                return

            user_id = event.get("user")
            text = event.get("text", "")
            channel = event.get("channel")
            thread_ts = event.get("thread_ts")
            ts = event.get("ts")

            if self.allowed_channels is not None:
                if channel in self.allowed_channels:
                    pass
                elif self._is_allowed_channel_name(channel):
                    pass
                else:
                    return
            if not _try_claim_message(ts):
                return

            user_email = self._get_user_email(user_id)

            message_data = {
                "message_id": ts,
                "text": text,
                "user_id": user_id,
                "channel": channel,
                "metadata": {
                    "client_id": self.client_id,
                    "thread_ts": thread_ts,
                    "ts": ts,
                    "channel_type": event.get("channel_type"),
                    "event_type": "app_mention",
                    "user_email": user_email,
                }
            }

            log.info(f"[SlackMessageProvider] Received app mention from {user_id} ({user_email}) in {channel}: {text}")

            self._notify_listeners(message_data)

        @self.app.event("message")
        def handle_message_events(event, say):
            """Handle incoming Slack messages."""
            if self.trigger_mode == "mention":
                thread_ts = event.get("thread_ts")
                if not thread_ts or not self._is_active_thread(thread_ts):
                    return
            # Ignore bot messages and message changes
            if event.get("subtype") in ["bot_message", "message_changed", "message_deleted"]:
                return

            # Extract message data
            user_id = event.get("user")
            text = event.get("text", "")
            channel = event.get("channel")
            thread_ts = event.get("thread_ts")
            ts = event.get("ts")

            if self.allowed_channels is not None:
                if channel in self.allowed_channels:
                    pass
                elif self._is_allowed_channel_name(channel):
                    pass
                else:
                    return
            if not _try_claim_message(ts):
                return

            user_email = self._get_user_email(user_id)

            # Build message data compatible with MessageProvider interface
            message_data = {
                "message_id": ts,
                "text": text,
                "user_id": user_id,
                "channel": channel,
                "metadata": {
                    "client_id": self.client_id,
                    "thread_ts": thread_ts,
                    "ts": ts,
                    "channel_type": event.get("channel_type"),
                    "user_email": user_email,
                }
            }

            log.info(f"[SlackMessageProvider] Received message from {user_id} ({user_email}) in {channel}: {text}")

            # Notify all registered listeners
            self._notify_listeners(message_data)

    def _handle_slack_api_error(self, e, operation: str) -> dict:
        """Log a SlackApiError with context. Permission errors are logged at warning level."""
        error_code = e.response.get("error", "unknown_error")
        msg = f"[SlackMessageProvider] {operation}: {error_code}"

        if error_code in _PERMISSION_ERRORS:
            needed = e.response.get("needed")
            provided = e.response.get("provided")
            if needed:
                msg += f" (scope needed: {needed})"
            if provided:
                msg += f" (scopes provided: {provided})"
            log.warning(msg)
        else:
            log.error(msg)

        return {"success": False, "error": error_code}

    def _get_user_email(self, user_id: str) -> str:
        """Fetch user email from Slack profile."""
        try:
            response = self.app.client.users_info(user=user_id)
            user = response.data.get("user", {}) if hasattr(response, 'data') else response.get("user", {})
            profile = user.get("profile", {})
            return profile.get("email", "unknown@example.com")
        except SlackApiError as e:
            self._handle_slack_api_error(e, f"Failed to fetch email for user {user_id}")
            return "unknown@example.com"
        except Exception as e:
            log.error(f"[SlackMessageProvider] Failed to fetch email for {user_id}: {e}")
            return "unknown@example.com"

    def _resolve_allowed_channels(self, allowed_channels: Set[str]) -> Tuple[Set[str], Set[str]]:
        """Resolve channel names to IDs; keep IDs as-is."""
        ids: Set[str] = set()
        names: Set[str] = set()

        for value in allowed_channels:
            if not value:
                continue
            cleaned = value.strip()
            if cleaned.startswith("#"):
                cleaned = cleaned[1:]
            if cleaned.startswith(("C", "G", "D")):
                ids.add(cleaned)
            else:
                names.add(cleaned)

        if not names:
            return ids, names

        try:
            resolved_names: Set[str] = set()
            cursor = None
            while True:
                response = self.app.client.conversations_list(
                    limit=1000,
                    cursor=cursor,
                    types="public_channel,private_channel"
                )
                channels = response.get("channels", [])
                for channel in channels:
                    channel_name = channel.get("name")
                    channel_id = channel.get("id")
                    if channel_name in names and channel_id:
                        ids.add(channel_id)
                        resolved_names.add(channel_name)

                cursor = response.get("response_metadata", {}).get("next_cursor")
                if not cursor:
                    break

            unresolved = names.difference(resolved_names)
            if unresolved:
                log.warning(
                    "[SlackMessageProvider] Could not resolve channels: %s",
                    ", ".join(sorted(unresolved))
                )
        except SlackApiError as e:
            self._handle_slack_api_error(e, "Failed to resolve channel names")
        except Exception as e:
            log.error(f"[SlackMessageProvider] Failed to resolve channel names: {e}")

        return ids, names.difference(resolved_names)

    def _is_allowed_channel_name(self, channel_id: Optional[str]) -> bool:
        if not channel_id or not self.allowed_channel_names:
            return False
        cached = self._channel_name_cache.get(channel_id)
        if cached:
            return cached in self.allowed_channel_names
        try:
            response = self.app.client.conversations_info(channel=channel_id)
            channel = response.get("channel", {})
            name = channel.get("name")
            if name:
                self._channel_name_cache[channel_id] = name
                return name in self.allowed_channel_names
        except SlackApiError as e:
            self._handle_slack_api_error(e, f"Failed to resolve channel id {channel_id}")
        except Exception as e:
            log.error(f"[SlackMessageProvider] Failed to resolve channel id {channel_id}: {e}")
        return False
    def _is_active_thread(self, thread_ts: str) -> bool:
        """Check if the bot has sent a message in this thread."""
        now = time.monotonic()
        cutoff = now - self._active_thread_ttl_sec
        stale = [ts for ts, t in self._active_threads.items() if t < cutoff]
        for ts in stale:
            self._active_threads.pop(ts, None)
        return thread_ts in self._active_threads

    def _notify_listeners(self, message_data: dict):
        """Notify all registered message listeners."""
        for listener in self.message_listeners:
            try:
                listener(message_data)
            except Exception as e:
                log.error(f"[SlackMessageProvider] Listener error: {str(e)}")

    def send_message(
        self,
        message: str,
        user_id: str,
        channel: Optional[str] = None,
        previous_message_id: Optional[str] = None
    ) -> dict:
        """
        Send a message to Slack.

        Args:
            message: Text to send
            user_id: Slack user ID (for DM) or channel ID
            channel: Optional channel override
            previous_message_id: If provided, reply in thread

        Returns:
            Dict with message metadata including ts (message ID)
        """
        try:
            # Determine target channel
            target_channel = channel or user_id

            # Use previous_message_id directly as thread_ts for threading
            thread_ts = previous_message_id if previous_message_id else None

            # Send message
            result = self.app.client.chat_postMessage(
                channel=target_channel,
                text=message,
                thread_ts=thread_ts
            )

            message_id = result["ts"]

            if thread_ts:
                self._active_threads[thread_ts] = time.monotonic()

            log.info(f"[SlackMessageProvider] Sent message to {target_channel}: {message[:50]}...")

            return {
                "success": True,
                "message_id": message_id,
                "channel": result["channel"],
                "thread_ts": thread_ts
            }

        except SlackApiError as e:
            return self._handle_slack_api_error(e, "Failed to send message")
        except Exception as e:
            log.error(f"[SlackMessageProvider] Failed to send message: {e}")
            return {"success": False, "error": str(e)}

    def send_reaction(self, message_id: str, reaction: str, channel: Optional[str] = None) -> dict:
        """
        Add a reaction to a Slack message.

        Args:
            message_id: Slack message timestamp (ts)
            reaction: Reaction name without colons (e.g., "thumbsup", "heart")
            channel: Optional channel ID. Falls back to cached metadata if not provided.

        Returns:
            Dict with success status
        """
        try:
            if not channel:
                return {
                    "success": False,
                    "error": "channel is required"
                }

            # Remove colons if present in reaction
            clean_reaction = reaction.strip(":")

            # Add reaction
            self.app.client.reactions_add(
                channel=channel,
                timestamp=message_id,
                name=clean_reaction
            )

            log.info(f"[SlackMessageProvider] Added reaction :{clean_reaction}: to message {message_id}")

            return {
                "success": True,
                "message_id": message_id,
                "reaction": clean_reaction
            }

        except SlackApiError as e:
            return self._handle_slack_api_error(e, "Failed to add reaction")
        except Exception as e:
            log.error(f"[SlackMessageProvider] Failed to add reaction: {e}")
            return {"success": False, "error": str(e)}

    def update_message(self, message_id: str, new_text: str, channel: Optional[str] = None) -> dict:
        """
        Update an existing Slack message.

        Args:
            message_id: Slack message timestamp (ts)
            new_text: New message text
            channel: Channel ID where the message exists

        Returns:
            Dict with success status
        """
        try:
            if not channel:
                return {
                    "success": False,
                    "error": "channel is required"
                }

            # Update message
            result = self.app.client.chat_update(
                channel=channel,
                ts=message_id,
                text=new_text
            )

            log.info(f"[SlackMessageProvider] Updated message {message_id}")

            return {
                "success": True,
                "message_id": result["ts"],
                "channel": result["channel"]
            }

        except SlackApiError as e:
            return self._handle_slack_api_error(e, "Failed to update message")
        except Exception as e:
            log.error(f"[SlackMessageProvider] Failed to update message: {e}")
            return {"success": False, "error": str(e)}

    def register_message_listener(self, callback: Callable):
        """
        Register a callback function to be called when messages are received.

        Args:
            callback: Function that takes a message dict as parameter
        """
        if not callable(callback):
            raise ValueError("Callback must be a callable function")

        self.message_listeners.append(callback)
        log.info(f"[SlackMessageProvider] Registered message listener")

    def start(self, port: int = 3000):
        """
        Start the Slack message provider.

        Args:
            port: Port for HTTP mode (ignored in Socket Mode)
        """
        if self.use_socket_mode:
            log.info("[SlackMessageProvider] Starting in Socket Mode...")
            handler = SocketModeHandler(self.app, self.app_token)
            handler.start()
        else:
            log.info(f"[SlackMessageProvider] Starting in HTTP mode on port {port}...")
            self.app.start(port=port)

    def get_formatting_rules(self) -> str:
        """Return Slack's mrkdwn formatting syntax."""
        return "mrkdwn"

    def request_status_update(self, request_id: str, channel: Optional[str] = None) -> dict:
        """Slack doesn't have built-in request tracking. Returns not supported."""
        return {"success": False, "error": "Request status tracking not yet supported for Slack"}

    def register_request_status_update_listener(self, callback: Callable) -> None:
        """Slack doesn't have built-in request tracking. No-op."""
        log.debug("[SlackMessageProvider] Status update listeners not yet supported")

    def request_cancellation(self, request_id: str, channel: Optional[str] = None) -> dict:
        """Slack doesn't have built-in request cancellation. Returns not supported."""
        return {"success": False, "error": "Request cancellation not yet supported for Slack"}

    def register_request_cancellation_listener(self, callback: Callable) -> None:
        """Slack doesn't have built-in request cancellation. No-op."""
        log.debug("[SlackMessageProvider] Cancellation listeners not yet supported")

    def clear_thread(self, channel: str, metadata: Optional[dict] = None) -> dict:
        """
        Signal that a conversation in a channel should end.

        Args:
            channel: The channel ID whose conversation is ending
            metadata: Optional metadata about the clear event

        Returns:
            dict with success status
        """
        if not channel:
            return {"success": False, "error": "channel is required"}

        log.info(f"[SlackMessageProvider] Clearing thread for {channel}")

        for listener in self.thread_clear_listeners:
            try:
                listener(channel, metadata or {})
            except Exception as e:
                log.error(f"[SlackMessageProvider] Thread clear listener error: {e}")

        return {"success": True, "channel": channel}

    def register_thread_clear_listener(self, callback: Callable) -> None:
        """Register callback for thread clear events."""
        if not callable(callback):
            raise ValueError("Callback must be a callable function")
        self.thread_clear_listeners.append(callback)
