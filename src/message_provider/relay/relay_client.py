import asyncio
import logging
from typing import Optional
import msgpack
from datetime import datetime

try:
    import websockets
except ImportError:
    raise ImportError("websockets library required. Install with: pip install websockets")

log = logging.getLogger(__name__)


class RelayClient:
    """
    Relay client that connects a MessageProvider to RelayHub.

    Wraps a message provider (Discord, Slack, Jira, etc.) and relays messages
    bidirectionally between the provider and the RelayHub.

    Args:
        local_provider: MessageProvider instance (e.g., DiscordMessageProvider)
        relay_hub_url: WebSocket URL of RelayHub (e.g., "ws://relay-hub:8765")
        client_id: Unique identifier for this client (e.g., "discord:main")
        reconnect_interval: Seconds to wait before reconnecting. Default: 5

    Usage:
        # In message provider pod
        discord_provider = DiscordMessageProvider(
            bot_token=token,
            client_id="discord:main"
        )

        relay_client = RelayClient(
            local_provider=discord_provider,
            relay_hub_url="ws://relay-hub:8765",
            client_id="discord:main"
        )

        # Start both in parallel
        await asyncio.gather(
            discord_provider.start_async(),  # If provider has async start
            relay_client.start()
        )
    """

    def __init__(
        self,
        local_provider,
        relay_hub_url: str,
        client_id: str,
        reconnect_interval: int = 5
    ):
        if not local_provider:
            raise ValueError("local_provider is required")
        if not relay_hub_url:
            raise ValueError("relay_hub_url is required")
        if not client_id:
            raise ValueError("client_id is required")

        self.local_provider = local_provider
        self.relay_hub_url = relay_hub_url
        self.client_id = client_id
        self.reconnect_interval = reconnect_interval

        # WebSocket connection
        self.websocket = None

        # Event loop
        self.loop = None
        self.running = False

        # Register as listener on local provider
        self.local_provider.register_message_listener(self._on_local_message)

        log.info(f"[RelayClient] Initialized for client_id: {client_id}")
        log.info(f"[RelayClient] Will connect to: {relay_hub_url}")

    def _on_local_message(self, message_data: dict):
        """
        Called when local provider (Discord/Slack/Jira) receives a message.
        Forwards it to RelayHub.
        """
        # Add client_id to metadata if not present
        if 'metadata' not in message_data:
            message_data['metadata'] = {}

        if 'client_id' not in message_data['metadata']:
            message_data['metadata']['client_id'] = self.client_id

        # Schedule send to hub
        if self.loop and self.loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self._send_to_hub({
                    'type': 'incoming_message',
                    'data': message_data,
                    'timestamp': datetime.utcnow().isoformat()
                }),
                self.loop
            )
        else:
            log.warning("[RelayClient] Event loop not running, cannot forward message")

    async def _send_to_hub(self, payload: dict):
        """Send data to RelayHub over WebSocket."""
        if self.websocket is None or self.websocket.closed:
            log.warning("[RelayClient] WebSocket not connected, cannot send")
            return

        try:
            packed = msgpack.packb(payload)
            await self.websocket.send(packed)
            log.debug(f"[RelayClient] Sent to hub: {payload['type']}")
        except Exception as e:
            log.error(f"[RelayClient] Failed to send to hub: {str(e)}")

    async def _handle_hub_message(self, message_bytes: bytes):
        """
        Handle message from RelayHub (send_message, send_reaction, update_message).
        """
        try:
            payload = msgpack.unpackb(message_bytes)
            msg_type = payload.get('type')
            data = payload.get('data', {})

            log.debug(f"[RelayClient] Received from hub: {msg_type}")

            if msg_type == 'send_message':
                # Hub wants to send a message through local provider
                self.local_provider.send_message(
                    message=data.get('message'),
                    user_id=data.get('user_id'),
                    channel=data.get('channel'),
                    previous_message_id=data.get('previous_message_id')
                )

            elif msg_type == 'send_reaction':
                # Hub wants to add a reaction through local provider
                self.local_provider.send_reaction(
                    message_id=data.get('message_id'),
                    reaction=data.get('reaction')
                )

            elif msg_type == 'update_message':
                # Hub wants to update a message through local provider
                self.local_provider.update_message(
                    message_id=data.get('message_id'),
                    new_text=data.get('new_text')
                )

            else:
                log.warning(f"[RelayClient] Unknown message type from hub: {msg_type}")

        except Exception as e:
            log.error(f"[RelayClient] Error handling hub message: {str(e)}")

    async def _connect_loop(self):
        """Main connection loop with reconnection logic."""
        while self.running:
            try:
                log.info(f"[RelayClient] Connecting to {self.relay_hub_url}...")

                async with websockets.connect(self.relay_hub_url) as websocket:
                    self.websocket = websocket
                    log.info(f"[RelayClient] Connected to RelayHub")

                    # Listen for messages from hub
                    async for message in websocket:
                        await self._handle_hub_message(message)

            except websockets.exceptions.ConnectionClosed:
                log.warning(f"[RelayClient] Connection closed")

            except Exception as e:
                log.error(f"[RelayClient] Connection error: {str(e)}")

            finally:
                self.websocket = None

                if self.running:
                    log.info(f"[RelayClient] Reconnecting in {self.reconnect_interval}s...")
                    await asyncio.sleep(self.reconnect_interval)

    async def _run_async(self):
        """Run the relay client."""
        self.running = True
        self.loop = asyncio.get_running_loop()

        try:
            await self._connect_loop()
        except asyncio.CancelledError:
            log.info("[RelayClient] Shutting down...")
        finally:
            self.running = False

    async def start(self):
        """
        Start the relay client (async).

        This connects to RelayHub and relays messages bidirectionally.
        """
        log.info("[RelayClient] Starting...")
        await self._run_async()

    def start_blocking(self):
        """
        Start the relay client (blocking).

        This is a blocking call that runs until stopped.
        """
        log.info("[RelayClient] Starting in blocking mode...")

        try:
            asyncio.run(self._run_async())
        except KeyboardInterrupt:
            log.info("[RelayClient] Interrupted by user")
            self.running = False

    def stop(self):
        """Stop the relay client."""
        log.info("[RelayClient] Stopping...")
        self.running = False
