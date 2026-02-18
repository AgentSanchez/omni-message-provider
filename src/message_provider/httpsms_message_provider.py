"""httpSMS Message Provider - Integration with httpSMS (https://github.com/NdoleStudio/httpsms).

httpSMS turns your Android phone into an SMS gateway. This provider integrates with
the httpSMS API to send and receive SMS messages.

Setup: https://github.com/NdoleStudio/httpsms
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Callable, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests

from message_provider.message_provider import MessageProvider

log = logging.getLogger(__name__)

# httpSMS API endpoint
HTTPSMS_API_URL = "https://api.httpsms.com/v1/messages/send"


class HttpSmsIncomingWebhook(BaseModel):
    """
    Incoming SMS webhook payload from httpSMS.

    Configure your httpSMS webhook to POST to your /webhook endpoint.
    See: https://github.com/NdoleStudio/httpsms
    """
    sender: str  # Phone number of sender (e.g., "+15559876543")
    recipient: str  # Your phone number that received the message
    content: str  # Message text
    timestamp: Optional[str] = None  # ISO timestamp from gateway
    metadata: Optional[dict] = None


class HttpSmsMessageProvider(MessageProvider):
    """
    httpSMS Message Provider.

    Integrates with httpSMS (https://github.com/NdoleStudio/httpsms) to send and
    receive SMS messages using your Android phone as a gateway.

    SMS is 1:1 communication - channel is the phone number, and there are no threads.
    The provider uses a default thread ID for all messages. Applications can signal
    when a conversation should end using clear_thread().

    Built-in commands:
        /help - Sends help_text to the user
        /clear - Triggers thread clear event (ends conversation)

    Args:
        api_key: Your httpSMS API key (from https://httpsms.com)
        phone_number: Your phone number registered with httpSMS (sender ID)
        client_id: Unique identifier for this provider instance
        message_authenticator: Optional callback for authenticating incoming messages.
            Called with (sender: str, recipient: str, content: str, metadata: dict) -> dict:
            - "allowed": bool (required) - Whether to process the message
            - "reason": str (optional) - Reason for rejection (logged)
        help_text: Optional help message sent when user types /help.
            Default: "Send /help for help or /clear to start a new conversation."
        initial_text: Optional message sent to new conversations (first message from a number).
            Set to None to disable. Default: None (disabled).
        host: Webhook server host. Default: "0.0.0.0"
        port: Webhook server port. Default: 9548

    Usage:
        provider = HttpSmsMessageProvider(
            api_key=os.getenv("HTTPSMS_API_KEY"),
            phone_number="+15551234567",
            client_id="httpsms:main",
            help_text="Commands: /help, /clear. Or just send a message!",
            initial_text="Welcome! Send /help for available commands."
        )

        provider.register_message_listener(my_handler)
        provider.register_thread_clear_listener(my_clear_handler)
        provider.start()

    Setup:
        1. Install the httpSMS Android app on your phone
        2. Create an account at https://httpsms.com
        3. Get your API key from the dashboard
        4. Configure a webhook URL pointing to your server's /webhook endpoint
    """

    # Default thread ID for SMS (no real threads in SMS)
    DEFAULT_THREAD_ID = "sms_default"
    DEFAULT_HELP_TEXT = "Send /help for help or /clear to start a new conversation."

    def __init__(
        self,
        api_key: str,
        phone_number: str,
        client_id: str = "httpsms:default",
        message_authenticator: Optional[Callable[[str, str, str, dict], dict]] = None,
        help_text: Optional[str] = None,
        initial_text: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 9548
    ):
        super().__init__()

        if not api_key:
            raise ValueError("api_key is required")
        if not phone_number:
            raise ValueError("phone_number is required")

        self.api_key = api_key
        self.phone_number = phone_number
        self.client_id = client_id
        self.message_authenticator = message_authenticator
        self.help_text = help_text if help_text is not None else self.DEFAULT_HELP_TEXT
        self.initial_text = initial_text
        self.host = host
        self.port = port

        self.app = FastAPI(
            title="httpSMS Message Provider",
            description="Webhook receiver for httpSMS gateway",
            version="1.0.0"
        )

        self.message_listeners: List[Callable] = []
        self.thread_clear_listeners: List[Callable] = []

        # Track known senders for initial_text
        self._known_senders: set = set()

        self._setup_routes()
        log.info(f"[HttpSmsMessageProvider] Initialized for {phone_number}")

    def _generate_message_id(self, timestamp: Optional[str] = None) -> str:
        """Generate message ID based on timestamp."""
        if timestamp:
            return f"sms_{timestamp.replace(':', '').replace('-', '').replace('.', '')}"
        return f"sms_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"

    def _setup_routes(self):
        @self.app.post("/webhook")
        async def webhook_receiver(payload: HttpSmsIncomingWebhook):
            """Receive incoming SMS via httpSMS webhook."""
            sender = payload.sender
            recipient = payload.recipient
            content = payload.content
            timestamp = payload.timestamp or datetime.now(timezone.utc).isoformat()
            message_id = self._generate_message_id(payload.timestamp)

            log.debug(f"[HttpSmsMessageProvider] Webhook from {sender}")

            # Verify recipient matches our phone number
            if recipient != self.phone_number:
                log.warning(f"[HttpSmsMessageProvider] Wrong recipient: {recipient}")
                raise HTTPException(status_code=403, detail="Wrong recipient")

            # Authenticate message if authenticator is configured
            if self.message_authenticator:
                auth_result = self.message_authenticator(
                    sender, recipient, content, payload.metadata or {}
                )
                if not auth_result.get("allowed", False):
                    reason = auth_result.get("reason", "Not authorized")
                    log.info(f"[HttpSmsMessageProvider] Message rejected: {reason}")
                    raise HTTPException(status_code=403, detail=reason)

            # Check if this is a new sender and send initial_text
            is_new_sender = sender not in self._known_senders
            if is_new_sender:
                self._known_senders.add(sender)
                if self.initial_text:
                    log.info(f"[HttpSmsMessageProvider] Sending initial text to {sender}")
                    self.send_message(self.initial_text, "bot", channel=sender)

            # Handle /help command
            content_lower = content.strip().lower()
            if content_lower == "/help":
                log.info(f"[HttpSmsMessageProvider] Help requested by {sender}")
                self.send_message(self.help_text, "bot", channel=sender)
                return {"message": "OK", "action": "help"}

            # Handle /clear command
            if content_lower == "/clear":
                log.info(f"[HttpSmsMessageProvider] Clear requested by {sender}")
                self.clear_thread(sender, metadata={"reason": "user_cleared"})
                return {"message": "OK", "action": "clear"}

            # Build message - channel is the sender's phone number
            message_data = {
                "source_type": "httpsms",
                "type": "message",
                "message_id": message_id,
                "text": content,
                "user_id": sender,
                "channel": sender,  # In SMS, channel = phone number
                "thread_id": self.DEFAULT_THREAD_ID,
                "metadata": {
                    "client_id": self.client_id,
                    "is_new_sender": is_new_sender,
                    **(payload.metadata or {})
                },
                "timestamp": timestamp
            }

            log.info(f"[HttpSmsMessageProvider] Processing from {sender}")
            self._notify_listeners(message_data)

            return {"message": "OK"}

        @self.app.get("/health")
        async def health_check():
            return {
                "status": "healthy",
                "client_id": self.client_id,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }

    def register_message_listener(self, callback: Callable) -> None:
        if not callable(callback):
            raise ValueError("Callback must be callable")
        self.message_listeners.append(callback)

    def register_thread_clear_listener(self, callback: Callable) -> None:
        """
        Register a listener for thread clear events.

        Called when clear_thread() is invoked, signaling that a conversation
        with a phone number should be considered ended.

        Args:
            callback: Function called with (channel: str, metadata: dict)
        """
        if not callable(callback):
            raise ValueError("Callback must be callable")
        self.thread_clear_listeners.append(callback)

    def clear_thread(self, channel: str, metadata: Optional[dict] = None) -> dict:
        """
        Signal that a conversation with a phone number is ended.

        Applications call this when a conversation should be marked as complete
        and not continued. Notifies all registered thread_clear_listeners.
        Also removes the sender from known_senders so they receive initial_text
        on their next message.

        Args:
            channel: The phone number whose conversation is ending
            metadata: Optional metadata about the clear event

        Returns:
            dict with success status
        """
        if not channel:
            return {"success": False, "error": "channel (phone number) is required"}

        log.info(f"[HttpSmsMessageProvider] Clearing thread for {channel}")

        # Remove from known senders so they get initial_text on next message
        self._known_senders.discard(channel)

        for listener in self.thread_clear_listeners:
            try:
                listener(channel, metadata or {})
            except Exception as e:
                log.error(f"[HttpSmsMessageProvider] Thread clear listener error: {e}")

        return {"success": True, "channel": channel}

    def _notify_listeners(self, message_data: dict):
        for listener in self.message_listeners:
            try:
                listener(message_data)
            except Exception as e:
                log.error(f"[HttpSmsMessageProvider] Listener error: {e}")

    def send_message(
        self,
        message: str,
        user_id: str,
        channel: Optional[str] = None,
        previous_message_id: Optional[str] = None
    ) -> dict:
        """Send SMS via httpSMS. Channel is the recipient phone number."""
        if not channel:
            return {"success": False, "error": "channel (recipient phone) is required"}

        headers = {
            "x-api-key": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        payload = {
            "content": message,
            "from": self.phone_number,
            "to": channel
        }

        try:
            response = requests.post(
                HTTPSMS_API_URL,
                headers=headers,
                json=payload,
                timeout=30
            )
            response.raise_for_status()

            response_data = response.json()
            # Use API message ID if available, otherwise generate from timestamp
            api_message_id = response_data.get("data", {}).get("id")
            message_id = api_message_id or self._generate_message_id()

            log.info(f"[HttpSmsMessageProvider] Sent to {channel}")
            return {"success": True, "message_id": message_id, "channel": channel}

        except requests.exceptions.RequestException as e:
            log.error(f"[HttpSmsMessageProvider] Send failed: {e}")
            return {"success": False, "error": str(e), "channel": channel}

    def send_reaction(self, message_id: str, reaction: str, channel: Optional[str] = None) -> dict:
        """SMS doesn't support reactions. Sends as text message."""
        if not channel:
            return {"success": False, "error": "channel required"}
        return self.send_message(f"[{reaction}]", "bot", channel)

    def update_message(self, message_id: str, new_text: str, channel: Optional[str] = None) -> dict:
        """SMS doesn't support message updates. Sends as new message."""
        if not channel:
            return {"success": False, "error": "channel required"}
        return self.send_message(f"[Update] {new_text}", "bot", channel)

    def get_formatting_rules(self) -> str:
        return "plaintext"

    def request_status_update(self, request_id: str, channel: Optional[str] = None) -> dict:
        return {"success": False, "error": "Not supported for SMS"}

    def register_request_status_update_listener(self, callback: Callable) -> None:
        pass

    def request_cancellation(self, request_id: str, channel: Optional[str] = None) -> dict:
        return {"success": False, "error": "Not supported for SMS"}

    def register_request_cancellation_listener(self, callback: Callable) -> None:
        pass

    def register_reaction_listener(self, callback: Callable) -> None:
        """SMS doesn't support reactions. No-op."""
        log.debug("[HttpSmsMessageProvider] Reaction listeners not supported for SMS")

    def get_app(self) -> FastAPI:
        return self.app

    def start(self, host: Optional[str] = None, port: Optional[int] = None):
        import uvicorn
        uvicorn.run(
            self.app,
            host=host or self.host,
            port=port or self.port
        )
