import asyncio
import logging
from typing import Optional, Callable, List
import msgpack
from datetime import datetime
from message_provider.message_provider import MessageProvider

try:
    import websockets
except ImportError:
    raise ImportError("websockets library required. Install with: pip install websockets")

log = logging.getLogger(__name__)


class RelayMessageProvider(MessageProvider):
    """
    MessageProvider implementation that relays all operations over WebSocket to RelayHub.

    This runs in orchestrator pods and connects to the RelayHub in the MP service.

    Args:
        websocket_url: WebSocket URL to connect to (e.g., "ws://mp-service:8765")
        reconnect_interval: Seconds to wait before reconnecting on disconnect. Default: 5

    Usage:
        # In orchestrator
        provider = RelayMessageProvider(websocket_url="ws://mp-service:8765")
        provider.register_message_listener(orchestrator.message_handler)
        provider.start()  # Blocking
    """

    def __init__(
        self,
        websocket_url: str,
        reconnect_interval: int = 5
    ):
        super().__init__()

        if not websocket_url:
            raise ValueError("websocket_url is required")

        self.websocket_url = websocket_url
        self.reconnect_interval = reconnect_interval

        # WebSocket connection
        self.websocket = None

        # Message listeners
        self.message_listeners: List[Callable] = []

        # Event loop
        self.loop = None
        self.running = False

        log.info(f"[RelayMessageProvider] Initialized with URL: {websocket_url}")

    def register_message_listener(self, callback: Callable):
        """
        Register a callback function to be called when messages are received.

        Args:
            callback: Function that takes a message dict as parameter
        """
        if not callable(callback):
            raise ValueError("Callback must be a callable function")

        self.message_listeners.append(callback)
        log.info(f"[RelayMessageProvider] Registered message listener")

    def _notify_listeners(self, message_data: dict):
        """Notify all registered message listeners."""
        for listener in self.message_listeners:
            try:
                listener(message_data)
            except Exception as e:
                log.error(f"[RelayMessageProvider] Listener error: {str(e)}")

    async def _send_to_hub(self, payload: dict):
        """Send data to RelayHub over WebSocket."""
        if self.websocket is None or self.websocket.closed:
            log.error("[RelayMessageProvider] WebSocket not connected, cannot send")
            return

        try:
            packed = msgpack.packb(payload)
            await self.websocket.send(packed)
            log.debug(f"[RelayMessageProvider] Sent to hub: {payload['type']}")
        except Exception as e:
            log.error(f"[RelayMessageProvider] Failed to send to hub: {str(e)}")

    def send_message(
        self,
        message: str,
        user_id: str,
        channel: Optional[str] = None,
        previous_message_id: Optional[str] = None
    ) -> dict:
        """
        Send a message through the relay to the MP service.

        Args:
            message: Text to send
            user_id: User ID
            channel: Optional channel override
            previous_message_id: If provided, reply to this message

        Returns:
            Dict with status (actual send happens async)
        """
        payload = {
            'type': 'send_message',
            'data': {
                'message': message,
                'user_id': user_id,
                'channel': channel,
                'previous_message_id': previous_message_id
            },
            'timestamp': datetime.utcnow().isoformat()
        }

        # Schedule send on event loop
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self._send_to_hub(payload),
                self.loop
            )
            return {"status": "sent"}
        else:
            log.error("[RelayMessageProvider] Event loop not running")
            return {"status": "error", "error": "Event loop not running"}

    def send_reaction(self, message_id: str, reaction: str) -> dict:
        """
        Add a reaction through the relay to the MP service.

        Args:
            message_id: Message ID
            reaction: Reaction emoji/text

        Returns:
            Dict with status (actual send happens async)
        """
        payload = {
            'type': 'send_reaction',
            'data': {
                'message_id': message_id,
                'reaction': reaction
            },
            'timestamp': datetime.utcnow().isoformat()
        }

        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self._send_to_hub(payload),
                self.loop
            )
            return {"status": "sent"}
        else:
            log.error("[RelayMessageProvider] Event loop not running")
            return {"status": "error", "error": "Event loop not running"}

    def update_message(self, message_id: str, new_text: str) -> dict:
        """
        Update a message through the relay to the MP service.

        Args:
            message_id: Message ID
            new_text: New message text

        Returns:
            Dict with status (actual send happens async)
        """
        payload = {
            'type': 'update_message',
            'data': {
                'message_id': message_id,
                'new_text': new_text
            },
            'timestamp': datetime.utcnow().isoformat()
        }

        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self._send_to_hub(payload),
                self.loop
            )
            return {"status": "sent"}
        else:
            log.error("[RelayMessageProvider] Event loop not running")
            return {"status": "error", "error": "Event loop not running"}

    async def _handle_hub_message(self, message_bytes: bytes):
        """Handle incoming message from RelayHub."""
        try:
            payload = msgpack.unpackb(message_bytes)
            msg_type = payload.get('type')
            data = payload.get('data', {})

            log.debug(f"[RelayMessageProvider] Received from hub: {msg_type}")

            if msg_type == 'incoming_message':
                # Message from user (Discord/Slack) forwarded through hub
                self._notify_listeners(data)

            else:
                log.warning(f"[RelayMessageProvider] Unknown message type from hub: {msg_type}")

        except Exception as e:
            log.error(f"[RelayMessageProvider] Error handling hub message: {str(e)}")

    async def _connect_loop(self):
        """Main connection loop with reconnection logic."""
        while self.running:
            try:
                log.info(f"[RelayMessageProvider] Connecting to {self.websocket_url}...")

                async with websockets.connect(self.websocket_url) as websocket:
                    self.websocket = websocket
                    log.info(f"[RelayMessageProvider] Connected to RelayHub")

                    # Listen for messages
                    async for message in websocket:
                        await self._handle_hub_message(message)

            except websockets.exceptions.ConnectionClosed:
                log.warning(f"[RelayMessageProvider] Connection closed")

            except Exception as e:
                log.error(f"[RelayMessageProvider] Connection error: {str(e)}")

            finally:
                self.websocket = None

                if self.running:
                    log.info(f"[RelayMessageProvider] Reconnecting in {self.reconnect_interval}s...")
                    await asyncio.sleep(self.reconnect_interval)

    async def _run_async(self):
        """Run the WebSocket client."""
        self.running = True
        self.loop = asyncio.get_running_loop()

        try:
            await self._connect_loop()
        except asyncio.CancelledError:
            log.info("[RelayMessageProvider] Shutting down...")
        finally:
            self.running = False

    def start(self):
        """
        Start the relay message provider.

        This is a blocking call that runs the WebSocket client until stopped.
        """
        log.info("[RelayMessageProvider] Starting...")

        try:
            asyncio.run(self._run_async())
        except KeyboardInterrupt:
            log.info("[RelayMessageProvider] Interrupted by user")
            self.running = False

    def stop(self):
        """Stop the relay message provider."""
        log.info("[RelayMessageProvider] Stopping...")
        self.running = False
