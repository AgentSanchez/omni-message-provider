import asyncio
import logging
from typing import Dict, Optional, Set, Tuple, Callable
import msgpack
from datetime import datetime
try:
    import websockets
    from websockets.server import ServerConnection
except ImportError:
    raise ImportError("websockets library required. Install with: pip install websockets")

log = logging.getLogger(__name__)


class RelayHub:
    """
    WebSocket server hub for relaying messages between MP service and orchestrators.

    The hub runs in the MP (Message Provider) service and orchestrators connect to it.
    Routes messages to the same orchestrator based on (user_id, channel, client_id).

    Args:
        local_provider: MessageProvider instance (e.g., FastAPIMessageProvider with Discord/Slack)
        host: WebSocket server host. Default: "0.0.0.0"
        port: WebSocket server port. Default: 8765

    Usage:
        # In MP service
        mp_provider = FastAPIMessageProvider(...)
        hub = RelayHub(local_provider=mp_provider, port=8765)
        await hub.start()
    """

    def __init__(
        self,
        local_provider,
        host: str = "0.0.0.0",
        port: int = 8765
    ):
        self.local_provider = local_provider
        self.host = host
        self.port = port

        # Active WebSocket connections from orchestrators
        self.connections: Set[ServerConnection] = set()

        # Routing cache: (user_id, channel, client_id) -> WebSocket connection
        self.routing_cache: Dict[Tuple[str, str, str], ServerConnection] = {}

        # Round-robin index for load balancing new conversations
        self.next_connection_index = 0

        # Register listener on local provider to receive incoming messages
        self.local_provider.register_message_listener(self._on_local_message)

        log.info(f"[RelayHub] Initialized on {host}:{port}")

    def _get_routing_key(self, user_id: str, channel: str, client_id: str) -> Tuple[str, str, str]:
        """Generate routing key from message data."""
        return (user_id, channel, client_id)

    def _select_connection(self, routing_key: Tuple[str, str, str]) -> Optional[ServerConnection]:
        """
        Select which orchestrator connection to use for this routing key.
        Uses cached connection if available, otherwise round-robin.
        """
        # Check cache first
        if routing_key in self.routing_cache:
            cached_conn = self.routing_cache[routing_key]
            # Verify connection is still active
            if cached_conn in self.connections:
                return cached_conn
            else:
                # Stale cache entry, remove it
                del self.routing_cache[routing_key]

        # No cache hit, select connection via round-robin
        if not self.connections:
            log.warning("[RelayHub] No orchestrator connections available")
            return None

        connections_list = list(self.connections)
        selected = connections_list[self.next_connection_index % len(connections_list)]
        self.next_connection_index = (self.next_connection_index + 1) % len(connections_list)

        # Cache the selection
        self.routing_cache[routing_key] = selected

        log.info(f"[RelayHub] Assigned routing key {routing_key} to connection {id(selected)}")

        return selected

    def _on_local_message(self, message_data: dict):
        """
        Called when local provider (Discord/Slack) receives a message.
        Routes it to the appropriate orchestrator.
        """
        user_id = message_data.get('user_id', '')
        channel = message_data.get('channel', '')
        # Extract client_id from metadata or use source_type
        metadata = message_data.get('metadata', {})
        client_id = metadata.get('client_id', message_data.get('source_type', 'unknown'))

        routing_key = self._get_routing_key(user_id, channel, client_id)

        # Select orchestrator connection
        connection = self._select_connection(routing_key)
        if connection is None:
            log.error(f"[RelayHub] Cannot route message - no orchestrator available")
            return

        # Send message to orchestrator
        asyncio.create_task(self._send_to_orchestrator(connection, {
            'type': 'incoming_message',
            'data': message_data,
            'timestamp': datetime.utcnow().isoformat()
        }))

    async def _send_to_orchestrator(self, connection: ServerConnection, payload: dict):
        """Send data to orchestrator over WebSocket."""
        try:
            packed = msgpack.packb(payload)
            await connection.send(packed)
            log.debug(f"[RelayHub] Sent to orchestrator: {payload['type']}")
        except Exception as e:
            log.error(f"[RelayHub] Failed to send to orchestrator: {str(e)}")

    async def _handle_orchestrator_message(self, message_bytes: bytes):
        """
        Handle message from orchestrator (send_message, send_reaction, update_message).
        """
        try:
            payload = msgpack.unpackb(message_bytes)
            msg_type = payload.get('type')
            data = payload.get('data', {})

            log.debug(f"[RelayHub] Received from orchestrator: {msg_type}")

            if msg_type == 'send_message':
                # Orchestrator wants to send a message
                self.local_provider.send_message(
                    message=data.get('message'),
                    user_id=data.get('user_id'),
                    channel=data.get('channel'),
                    previous_message_id=data.get('previous_message_id')
                )

            elif msg_type == 'send_reaction':
                # Orchestrator wants to add a reaction
                self.local_provider.send_reaction(
                    message_id=data.get('message_id'),
                    reaction=data.get('reaction')
                )

            elif msg_type == 'update_message':
                # Orchestrator wants to update a message
                self.local_provider.update_message(
                    message_id=data.get('message_id'),
                    new_text=data.get('new_text')
                )

            else:
                log.warning(f"[RelayHub] Unknown message type from orchestrator: {msg_type}")

        except Exception as e:
            log.error(f"[RelayHub] Error handling orchestrator message: {str(e)}")

    async def _handle_connection(self, websocket: ServerConnection):
        """Handle a new orchestrator WebSocket connection."""
        log.info(f"[RelayHub] New orchestrator connected: {websocket.remote_address}")

        # Add to active connections
        self.connections.add(websocket)

        try:
            # Listen for messages from this orchestrator
            async for message in websocket:
                await self._handle_orchestrator_message(message)

        except websockets.exceptions.ConnectionClosed:
            log.info(f"[RelayHub] Orchestrator disconnected: {websocket.remote_address}")

        finally:
            # Remove from active connections
            self.connections.discard(websocket)

            # Clean up routing cache entries for this connection
            to_remove = [k for k, v in self.routing_cache.items() if v == websocket]
            for key in to_remove:
                del self.routing_cache[key]

            log.info(f"[RelayHub] Cleaned up {len(to_remove)} routing entries for disconnected orchestrator")

    async def start(self):
        """Start the RelayHub WebSocket server."""
        log.info(f"[RelayHub] Starting WebSocket server on {self.host}:{self.port}")

        async with websockets.serve(self._handle_connection, self.host, self.port):
            log.info(f"[RelayHub] WebSocket server running on ws://{self.host}:{self.port}")
            # Keep server running
            await asyncio.Future()  # Run forever

    def run(self):
        """Blocking method to run the RelayHub server."""
        asyncio.run(self.start())
