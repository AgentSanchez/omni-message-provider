import logging
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Callable
from datetime import datetime
from collections import defaultdict
import requests
import uuid
from message_provider.message_provider import MessageProvider

log = logging.getLogger(__name__)


class IncomingMessage(BaseModel):
    type: str = "message"  # "message", "status_request", "cancellation_request"
    text: Optional[str] = None  # Required for type="message", optional otherwise
    user_id: str
    channel: str  # Required - must be a valid subscriber_id
    thread_id: Optional[str] = None
    request_id: Optional[str] = None  # For status_request/cancellation_request
    metadata: Optional[dict] = None


class SubscriberRegistration(BaseModel):
    subscriber_id: Optional[str] = None  # Client-specified ID for re-registration
    user_id: str  # Required - identifies the user
    auth_details: Optional[dict] = None  # Optional auth credentials/tokens
    webhook_url: Optional[HttpUrl] = None
    webhook_api_key: Optional[str] = None
    source_type: str = "api"  # e.g., 'discord', 'slack', 'api'
    formatting_details: Optional[dict] = None
    description: Optional[str] = None


class MessageResponse(BaseModel):
    message_id: str
    status: str
    timestamp: str


class FastAPIMessageProvider(MessageProvider):
    """
    FastAPI-based REST API implementation of MessageProvider.

    Supports both webhook (push) and polling modes for subscribers.

    Args:
        provider_id: Unique identifier for this provider instance (e.g., "http:main")
        api_key: Optional API key for server-level authentication.
        authentication_provider: Optional callback for user authentication at registration.
            Called with (user_id: str, auth_details: dict) -> dict with keys:
            - "allowed": bool (required)
            - "session_token": str (optional, returned to client)
            - Any additional data to store with subscriber
        session_validator: Optional callback for validating session tokens on requests.
            Called with (subscriber_id: str, session_token: str) -> bool
        host: Host to bind to. Default: "0.0.0.0"
        port: Port to listen on. Default: 9547

    Usage:
        def my_auth_provider(user_id: str, auth_details: dict) -> dict:
            # Validate credentials, return session token
            if validate_user(user_id, auth_details):
                return {"allowed": True, "session_token": generate_token()}
            return {"allowed": False}

        def my_session_validator(subscriber_id: str, session_token: str) -> bool:
            return validate_token(session_token)

        provider = FastAPIMessageProvider(
            provider_id="http:my-service",
            authentication_provider=my_auth_provider,
            session_validator=my_session_validator
        )
    """

    def __init__(
        self,
        provider_id: str,
        api_key: Optional[str] = None,
        authentication_provider: Optional[Callable[[str, dict], dict]] = None,
        session_validator: Optional[Callable[[str, str], bool]] = None,
        host: str = "0.0.0.0",
        port: int = 9547,
        request_context_ttl: int = 3600,  # seconds, default 1 hour
        max_request_contexts: int = 10000  # max tracked requests before forced cleanup
    ):
        super().__init__()

        if not provider_id or not provider_id.strip():
            raise ValueError("provider_id is required")

        if port <= 0 or port > 65535:
            raise ValueError(f"port must be between 1 and 65535, got {port}")

        self.provider_id = provider_id
        self.api_key = api_key
        self.authentication_provider = authentication_provider
        self.session_validator = session_validator
        self.host = host
        self.port = port
        self.request_context_ttl = request_context_ttl
        self.max_request_contexts = max_request_contexts
        self.app = FastAPI(
            title="Message Provider API",
            description="REST API for message provider service",
            version="1.0.0"
        )

        # Subscribers (HTTP clients that receive outbound messages)
        self.registered_subscribers: Dict[str, dict] = {}  # subscriber_id -> subscriber_data

        # Message queues for polling subscribers
        self.message_queues: Dict[str, List[dict]] = defaultdict(list)

        # Message listeners (orchestrator callbacks)
        self.message_listeners: List[Callable] = []

        # Request tracking for status updates and cancellation
        self.request_status: Dict[str, dict] = {}  # request_id -> status_info
        self.request_context: Dict[str, dict] = {}  # request_id -> {channel, user_id, thread_id, created_at}
        self.status_update_listeners: List[Callable] = []
        self.cancellation_listeners: List[Callable] = []
        self.thread_clear_listeners: List[Callable] = []
        self._last_cleanup = datetime.utcnow()

        self._setup_routes()
        log.debug(f"[FastAPIMessageProvider] Initialized provider_id={provider_id}")

    def _cleanup_expired_contexts(self, force: bool = False):
        """
        Remove expired request contexts to prevent memory leaks.
        Called periodically or when max contexts exceeded.
        """
        now = datetime.utcnow()

        # Only run cleanup every 60 seconds unless forced
        if not force and (now - self._last_cleanup).total_seconds() < 60:
            return

        # Force cleanup if we exceed max contexts
        if len(self.request_context) > self.max_request_contexts:
            force = True

        if not force:
            self._last_cleanup = now
            return

        cutoff = now.timestamp() - self.request_context_ttl
        expired = []

        for req_id, context in self.request_context.items():
            created_at = context.get('created_at', 0)
            if created_at < cutoff:
                expired.append(req_id)

        for req_id in expired:
            self.request_context.pop(req_id, None)
            self.request_status.pop(req_id, None)

        if expired:
            log.debug(f"[FastAPIMessageProvider] Cleaned up {len(expired)} expired request contexts")

        self._last_cleanup = now

    def _validate_api_key(self, authorization: Optional[str] = None) -> bool:
        """Validate server-level API key."""
        if not self.api_key:
            return True
        if not authorization:
            return False
        try:
            scheme, token = authorization.split()
            return scheme.lower() == "bearer" and token == self.api_key
        except ValueError:
            return False

    def _extract_session_token(self, authorization: Optional[str]) -> Optional[str]:
        """Extract session token from Authorization header."""
        if not authorization:
            return None
        try:
            scheme, token = authorization.split()
            if scheme.lower() == "bearer":
                return token
        except ValueError:
            pass
        return None

    def _validate_subscriber_session(
        self,
        subscriber_id: str,
        authorization: Optional[str]
    ) -> tuple[bool, Optional[dict]]:
        """
        Validate subscriber exists and session is valid.
        Returns (is_valid, subscriber_data or None)
        """
        subscriber = self.registered_subscribers.get(subscriber_id)
        if not subscriber:
            return False, None

        # If no session validator, subscriber existence is enough
        if not self.session_validator:
            return True, subscriber

        # Validate session token
        session_token = self._extract_session_token(authorization)
        if not session_token:
            return False, None

        if self.session_validator(subscriber_id, session_token):
            return True, subscriber

        return False, None

    def _find_subscriber(self, channel: Optional[str]) -> Optional[dict]:
        """Find subscriber by channel (subscriber_id)."""
        if not channel:
            return None
        return self.registered_subscribers.get(channel)

    def send_message(self, message: str, user_id: str, channel: Optional[str] = None,
                     previous_message_id: Optional[str] = None, thread_id: Optional[str] = None) -> dict:
        message_id = f"msg_{uuid.uuid4().hex}"
        payload = {
            "type": "message",
            "message_id": message_id,
            "text": message,
            "user_id": user_id,
            "channel": channel,
            "thread_id": thread_id,
            "previous_message_id": previous_message_id,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"provider_id": self.provider_id}
        }

        if channel:
            subscriber = self._find_subscriber(channel)
            if not subscriber:
                return {"success": False, "error": f"Subscriber not found: {channel}"}
            return self._send_to_subscriber(subscriber, payload, message_id)

        return {"success": False, "error": "channel (subscriber_id) is required"}

    def _send_to_subscriber(self, subscriber: dict, payload: dict, message_id: str) -> dict:
        subscriber_id = subscriber.get('subscriber_id')

        if subscriber.get('url'):
            try:
                headers = {"Content-Type": "application/json"}
                if subscriber.get('webhook_api_key'):
                    headers["Authorization"] = f"Bearer {subscriber['webhook_api_key']}"
                response = requests.post(subscriber['url'], json=payload, headers=headers, timeout=30)
                response.raise_for_status()
                return {"success": True, "message_id": message_id, "subscriber_id": subscriber_id}
            except Exception as e:
                log.error(f"[FastAPIMessageProvider] Send failed to {subscriber_id}: {e}")
                return {"success": False, "message_id": message_id, "subscriber_id": subscriber_id, "error": str(e)}
        else:
            # Polling mode
            self.message_queues[subscriber_id].append(payload)
            return {"success": True, "message_id": message_id, "subscriber_id": subscriber_id, "queued": True}

    def send_reaction(self, message_id: str, reaction: str, channel: Optional[str] = None) -> dict:
        payload = {
            "type": "reaction",
            "message_id": message_id,
            "reaction": reaction,
            "channel": channel,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"provider_id": self.provider_id}
        }

        if channel:
            subscriber = self._find_subscriber(channel)
            if not subscriber:
                return {"success": False, "error": f"Subscriber not found: {channel}"}
            return self._send_to_subscriber(subscriber, payload, message_id)

        return {"success": False, "error": "channel (subscriber_id) is required"}

    def update_message(self, message_id: str, new_text: str, channel: Optional[str] = None) -> dict:
        payload = {
            "type": "update",
            "message_id": message_id,
            "text": new_text,
            "channel": channel,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"provider_id": self.provider_id}
        }

        if channel:
            subscriber = self._find_subscriber(channel)
            if not subscriber:
                return {"success": False, "error": f"Subscriber not found: {channel}"}
            return self._send_to_subscriber(subscriber, payload, message_id)

        return {"success": False, "error": "channel (subscriber_id) is required"}

    def register_message_listener(self, callback: Callable) -> None:
        if not callable(callback):
            raise ValueError("Callback must be a callable function")
        self.message_listeners.append(callback)

    def _notify_listeners(self, message_data: dict):
        for listener in self.message_listeners:
            try:
                listener(message_data)
            except Exception as e:
                log.error(f"[FastAPIMessageProvider] Listener error: {e}")

    def _handle_incoming(self, message_data: dict):
        """
        Route incoming messages to appropriate handler based on type,
        then notify listeners.
        """
        msg_type = message_data.get("type", "message")

        if msg_type == "status_request":
            self._handle_status_request(message_data)
        elif msg_type == "cancellation_request":
            self._handle_cancellation_request(message_data)
        else:
            # Regular message or unknown type - just pass through
            pass

        # All types get sent to listeners
        self._notify_listeners(message_data)

    def _handle_status_request(self, message_data: dict):
        """Handle status request - notify status update listeners."""
        request_id = message_data.get("request_id") or message_data.get("message_id")
        self._notify_status_update_request(request_id, message_data)

    def _handle_cancellation_request(self, message_data: dict):
        """Handle cancellation request - notify cancellation listeners."""
        request_id = message_data.get("request_id") or message_data.get("message_id")
        self._notify_cancellation(request_id, message_data)

    def get_formatting_rules(self) -> str:
        """HTTP provider supports plaintext or client-specified formatting."""
        return "plaintext"

    def request_status_update(self, request_id: str, channel: Optional[str] = None) -> dict:
        """
        Request a status update for a request.

        This notifies registered status update listeners (orchestrator) that a client
        is requesting status. The orchestrator may refresh the status from external
        systems and call update_request_status() to push the new status.

        Returns current stored status (which may be updated by listener callbacks).
        """
        context = self.request_context.get(request_id, {})

        # Notify listeners that a status update was requested
        request_info = {
            "type": "status_request",  # Differentiates from status_change
            "request_id": request_id,
            "channel": channel or context.get("channel"),
            "user_id": context.get("user_id"),
            "thread_id": context.get("thread_id"),
            "requested_at": datetime.utcnow().isoformat()
        }
        self._notify_status_update_request(request_id, request_info)

        # Return current stored status
        status = self.request_status.get(request_id)
        if status:
            return {"success": True, "request_id": request_id, "status": status}
        return {"success": False, "request_id": request_id, "error": "Request not found"}

    def register_request_status_update_listener(self, callback: Callable) -> None:
        """Register callback for status update notifications."""
        if not callable(callback):
            raise ValueError("Callback must be a callable function")
        self.status_update_listeners.append(callback)

    def _notify_status_update(self, request_id: str, status_info: dict):
        """Notify listeners of status change (called when status is updated)."""
        # Add type field if not present
        if "type" not in status_info:
            status_info = {"type": "status_change", **status_info}
        for listener in self.status_update_listeners:
            try:
                listener(request_id, status_info)
            except Exception as e:
                log.error(f"[FastAPIMessageProvider] Status listener error: {e}")

    def _notify_status_update_request(self, request_id: str, request_info: dict):
        """Notify listeners that a client is requesting status (so orchestrator can refresh)."""
        for listener in self.status_update_listeners:
            try:
                listener(request_id, request_info)
            except Exception as e:
                log.error(f"[FastAPIMessageProvider] Status request listener error: {e}")

    def update_request_status(self, request_id: str, status: str, details: Optional[dict] = None) -> None:
        """Update status of a request (called by orchestrator)."""
        timestamp = datetime.utcnow().isoformat()
        status_info = {
            "status": status,
            "updated_at": timestamp,
            "details": details or {}
        }
        self.request_status[request_id] = status_info
        self._notify_status_update(request_id, status_info)

        # Queue status update to subscriber (message format without text)
        context = self.request_context.get(request_id, {})
        channel = context.get("channel")
        if channel and channel in self.registered_subscribers:
            status_message = {
                "type": "status_update",
                "message_id": request_id,
                "user_id": context.get("user_id"),
                "channel": channel,
                "thread_id": context.get("thread_id"),
                "status": status,
                "details": details or {},
                "timestamp": timestamp,
                "metadata": {"provider_id": self.provider_id}
            }
            self.message_queues[channel].append(status_message)

    def request_cancellation(self, request_id: str, channel: Optional[str] = None) -> dict:
        """Request cancellation of an active request."""
        status = self.request_status.get(request_id)
        if not status:
            return {"success": False, "request_id": request_id, "error": "Request not found"}

        if status.get("status") in ("completed", "cancelled", "failed"):
            return {"success": False, "request_id": request_id, "error": f"Request already {status.get('status')}"}

        self.update_request_status(request_id, "cancellation_requested")
        self._notify_cancellation(request_id, {"requested_at": datetime.utcnow().isoformat()})
        return {"success": True, "request_id": request_id, "status": "cancellation_requested"}

    def register_request_cancellation_listener(self, callback: Callable) -> None:
        """Register callback for cancellation notifications."""
        if not callable(callback):
            raise ValueError("Callback must be a callable function")
        self.cancellation_listeners.append(callback)

    def _notify_cancellation(self, request_id: str, cancellation_info: dict):
        """Notify listeners of cancellation request."""
        for listener in self.cancellation_listeners:
            try:
                listener(request_id, cancellation_info)
            except Exception as e:
                log.error(f"[FastAPIMessageProvider] Cancellation listener error: {e}")

    def clear_thread(self, channel: str, metadata: Optional[dict] = None) -> dict:
        """
        Signal that a conversation with a subscriber should end.

        Args:
            channel: The subscriber_id whose conversation is ending
            metadata: Optional metadata about the clear event

        Returns:
            dict with success status
        """
        if not channel:
            return {"success": False, "error": "channel (subscriber_id) is required"}

        log.info(f"[FastAPIMessageProvider] Clearing thread for {channel}")

        for listener in self.thread_clear_listeners:
            try:
                listener(channel, metadata or {})
            except Exception as e:
                log.error(f"[FastAPIMessageProvider] Thread clear listener error: {e}")

        return {"success": True, "channel": channel}

    def register_thread_clear_listener(self, callback: Callable) -> None:
        """Register callback for thread clear events."""
        if not callable(callback):
            raise ValueError("Callback must be a callable function")
        self.thread_clear_listeners.append(callback)

    def _setup_routes(self):
        @self.app.post("/subscriber/register")
        async def register_subscriber(
            subscriber: SubscriberRegistration,
            authorization: Optional[str] = Header(None)
        ):
            # Validate server-level API key if configured
            if self.api_key and not self._validate_api_key(authorization):
                raise HTTPException(status_code=401, detail="Invalid or missing API key")

            errors = []
            if not subscriber.user_id:
                errors.append("user_id is required")
            if subscriber.webhook_url and not subscriber.webhook_api_key:
                errors.append("webhook_api_key is required when webhook_url is provided")
            if subscriber.webhook_api_key and not subscriber.webhook_url:
                errors.append("webhook_url is required when webhook_api_key is provided")
            if errors:
                raise HTTPException(status_code=400, detail={"errors": errors})

            # Authentication via external provider
            session_token = None
            auth_data = {}
            if self.authentication_provider:
                auth_result = self.authentication_provider(
                    subscriber.user_id,
                    subscriber.auth_details or {}
                )
                if not auth_result.get("allowed", False):
                    raise HTTPException(
                        status_code=403,
                        detail=auth_result.get("reason", "Authentication failed")
                    )
                session_token = auth_result.get("session_token")
                # Store any additional auth data
                auth_data = {k: v for k, v in auth_result.items() if k not in ("allowed", "session_token")}

            # Support re-registration with client-specified ID
            is_reregistration = False
            if subscriber.subscriber_id:
                subscriber_id = subscriber.subscriber_id
                is_reregistration = subscriber_id in self.registered_subscribers
            else:
                subscriber_id = str(uuid.uuid4())

            subscriber_data = {
                "subscriber_id": subscriber_id,
                "user_id": subscriber.user_id,
                "url": str(subscriber.webhook_url) if subscriber.webhook_url else None,
                "webhook_api_key": subscriber.webhook_api_key,
                "source_type": subscriber.source_type,
                "formatting_details": subscriber.formatting_details,
                "description": subscriber.description,
                "registered_at": datetime.utcnow().isoformat(),
                **auth_data  # Include any additional auth data
            }

            self.registered_subscribers[subscriber_id] = subscriber_data

            response = {
                "status": "re-registered" if is_reregistration else "registered",
                "subscriber_id": subscriber_id,
                "subscriber": subscriber_data
            }
            if session_token:
                response["session_token"] = session_token

            log.debug(f"[FastAPIMessageProvider] {'Re-registered' if is_reregistration else 'Registered'} subscriber {subscriber_id}")
            return response

        @self.app.post("/message/process", response_model=MessageResponse)
        async def process_message(
            message: IncomingMessage,
            background_tasks: BackgroundTasks,
            authorization: Optional[str] = Header(None)
        ):
            # Validate subscriber exists
            subscriber = self.registered_subscribers.get(message.channel)
            if not subscriber:
                raise HTTPException(
                    status_code=404,
                    detail=f"Subscriber not found: {message.channel}"
                )

            # Validate session if session_validator is configured
            if self.session_validator:
                session_token = self._extract_session_token(authorization)
                if not session_token or not self.session_validator(message.channel, session_token):
                    raise HTTPException(status_code=401, detail="Invalid or missing session token")

            # Validate text is provided for regular messages
            if message.type == "message" and not message.text:
                raise HTTPException(status_code=400, detail="text is required for message type")

            # Use provided request_id or generate new one
            message_id = message.request_id or f"msg_{uuid.uuid4().hex}"
            timestamp = datetime.utcnow().isoformat()

            # Build message data - passed directly to orchestrator
            message_data = {
                "type": message.type,
                "message_id": message_id,
                "text": message.text,
                "user_id": message.user_id,
                "channel": message.channel,
                "thread_id": message.thread_id,
                "request_id": message.request_id,
                "metadata": {
                    "provider_id": self.provider_id,
                    "subscriber_id": message.channel,
                    **(message.metadata or {})
                },
                "timestamp": timestamp
            }

            # Track request context (for routing replies)
            self.request_context[message_id] = {
                "channel": message.channel,
                "user_id": message.user_id,
                "thread_id": message.thread_id,
                "created_at": datetime.utcnow().timestamp()
            }

            # Cleanup expired contexts periodically
            self._cleanup_expired_contexts()

            # Route to appropriate handler, then notify listeners
            self._handle_incoming(message_data)

            return MessageResponse(
                message_id=message_id,
                status="received",
                timestamp=timestamp
            )

        @self.app.get("/subscriber/list")
        async def list_subscribers(authorization: Optional[str] = Header(None)):
            if self.api_key and not self._validate_api_key(authorization):
                raise HTTPException(status_code=401, detail="Invalid or missing API key")
            return {"subscribers": list(self.registered_subscribers.values()), "count": len(self.registered_subscribers)}

        @self.app.delete("/subscriber/{subscriber_id}")
        async def unregister_subscriber(
            subscriber_id: str,
            authorization: Optional[str] = Header(None)
        ):
            # Validate session or API key
            if self.session_validator:
                valid, _ = self._validate_subscriber_session(subscriber_id, authorization)
                if not valid:
                    raise HTTPException(status_code=401, detail="Invalid or missing session token")
            elif self.api_key and not self._validate_api_key(authorization):
                raise HTTPException(status_code=401, detail="Invalid or missing API key")

            if subscriber_id not in self.registered_subscribers:
                raise HTTPException(status_code=404, detail="Subscriber not found")

            del self.registered_subscribers[subscriber_id]
            self.message_queues.pop(subscriber_id, None)
            return {"status": "unregistered", "subscriber_id": subscriber_id}

        @self.app.get("/messages/{subscriber_id}")
        async def retrieve_messages(
            subscriber_id: str,
            clear: bool = True,
            authorization: Optional[str] = Header(None)
        ):
            # Validate session or API key
            if self.session_validator:
                valid, _ = self._validate_subscriber_session(subscriber_id, authorization)
                if not valid:
                    raise HTTPException(status_code=401, detail="Invalid or missing session token")
            elif self.api_key and not self._validate_api_key(authorization):
                raise HTTPException(status_code=401, detail="Invalid or missing API key")

            if subscriber_id not in self.registered_subscribers:
                raise HTTPException(status_code=404, detail="Subscriber not found")

            messages = self.message_queues.get(subscriber_id, []).copy()
            if clear:
                self.message_queues[subscriber_id].clear()

            return {
                "subscriber_id": subscriber_id,
                "messages": messages,
                "count": len(messages),
                "cleared": clear,
                "timestamp": datetime.utcnow().isoformat()
            }

        @self.app.get("/health")
        async def health_check():
            return {
                "status": "healthy",
                "provider_id": self.provider_id,
                "subscribers_count": len(self.registered_subscribers),
                "timestamp": datetime.utcnow().isoformat()
            }

    def get_app(self) -> FastAPI:
        return self.app

    def start(self, host: Optional[str] = None, port: Optional[int] = None):
        import uvicorn
        start_host = host if host is not None else self.host
        start_port = port if port is not None else self.port
        log.info(f"[FastAPIMessageProvider] Starting on {start_host}:{start_port}")
        uvicorn.run(self.app, host=start_host, port=start_port)
