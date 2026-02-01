import logging
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict
from datetime import datetime
from collections import defaultdict
import requests
import uuid
from message_provider.message_provider import MessageProvider

log = logging.getLogger(__name__)


class IncomingMessage(BaseModel):
    text: str
    user_id: str
    channel: Optional[str] = None
    metadata: Optional[dict] = None


class ClientRegistration(BaseModel):
    webhook_url: Optional[HttpUrl] = None
    webhook_api_key: Optional[str] = None
    source_type: str  # e.g., 'discord', 'slack', 'api'
    formatting_details: Optional[dict] = None  # Platform-specific formatting information
    description: Optional[str] = None


class MessageResponse(BaseModel):
    message_id: str
    status: str
    timestamp: str


class FastAPIMessageProvider(MessageProvider):
    """
    FastAPI-based REST API implementation of MessageProvider.

    Supports both webhook (push) and polling modes for clients.

    Args:
        api_key: Optional API key for authentication. If None, no authentication is required.
        host: Host to bind to. Default: "0.0.0.0" (all interfaces)
        port: Port to listen on. Default: 9547

    Usage:
        import os
        provider = FastAPIMessageProvider(
            api_key=os.getenv("MESSAGE_API_KEY"),
            host="0.0.0.0",
            port=9547
        )
        provider.register_message_listener(my_handler)
        provider.start()
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 9547
    ):
        super().__init__()

        # Validate port
        if port <= 0 or port > 65535:
            raise ValueError(f"port must be between 1 and 65535, got {port}")

        self.api_key = api_key
        self.host = host
        self.port = port
        self.app = FastAPI(
            title="Message Provider API",
            description="REST API for message provider service",
            version="1.0.0"
        )
        self.registered_clients: List[dict] = []
        self.message_listeners = []
        self.message_queues: Dict[str, List[dict]] = defaultdict(list)
        self._setup_routes()
        log.info("[FastAPIMessageProvider] Server initialized")

    def _validate_api_key(self, authorization: Optional[str] = None) -> bool:
        if not self.api_key:
            return True

        if not authorization:
            return False

        try:
            scheme, token = authorization.split()
            return scheme.lower() == "bearer" and token == self.api_key
        except ValueError:
            return False

    def send_message(self, message: str, user_id: str, channel: Optional[str] = None,
                     previous_message_id: Optional[str] = None) -> dict:
        message_id = f"msg_{uuid.uuid4().hex}"
        payload = {
            "message_id": message_id,
            "text": message,
            "user_id": user_id,
            "channel": channel,
            "previous_message_id": previous_message_id,
            "timestamp": datetime.utcnow().isoformat()
        }

        results = []
        for client in self.registered_clients:
            client_id = client.get('client_id')

            if client.get('url'):
                try:
                    log.info(f"[FastAPIMessageProvider] Sending to client {client_id}: {client['url']}")
                    response = requests.post(
                        client['url'],
                        json=payload,
                        timeout=30
                    )
                    response.raise_for_status()
                    results.append({"client_id": client_id, "client_url": client['url'], "status": "success"})
                except Exception as e:
                    log.error(f"[FastAPIMessageProvider] Failed to send to {client['url']}: {str(e)}")
                    results.append({"client_id": client_id, "client_url": client['url'], "status": "failed", "error": str(e)})
            else:
                log.info(f"[FastAPIMessageProvider] Queueing message for client {client_id} (polling mode)")
                self.message_queues[client_id].append(payload)
                results.append({"client_id": client_id, "status": "queued"})

        success = all(result.get("status") != "failed" for result in results)
        return {"success": success, "message_id": message_id, "results": results}

    def register_message_listener(self, callback):
        if not callable(callback):
            raise ValueError("Callback must be a callable function")
        self.message_listeners.append(callback)
        log.info(f"[FastAPIMessageProvider] Registered message listener")

    def _notify_listeners(self, message_data: dict):
        for listener in self.message_listeners:
            try:
                listener(message_data)
            except Exception as e:
                log.error(f"[FastAPIMessageProvider] Listener failed: {str(e)}")

    def _send_to_clients(self, message_data: dict):
        for client in self.registered_clients:
            client_id = client.get('client_id')

            if client.get('url'):
                try:
                    log.info(f"[FastAPIMessageProvider] Sending to client {client_id}: {client['url']}")
                    headers = {
                        "Authorization": f"Bearer {client['api_key']}",
                        "Content-Type": "application/json"
                    }
                    requests.post(
                        client['url'],
                        json=message_data,
                        headers=headers,
                        timeout=30
                    )
                except Exception as e:
                    log.error(f"[FastAPIMessageProvider] Failed to send to {client['url']}: {str(e)}")
            else:
                log.info(f"[FastAPIMessageProvider] Queueing message for client {client_id} (polling mode)")
                self.message_queues[client_id].append(message_data)

    def _setup_routes(self):
        @self.app.post("/message/process", response_model=MessageResponse)
        async def process_message(
            message: IncomingMessage,
            background_tasks: BackgroundTasks,
            authorization: Optional[str] = Header(None)
        ):
            if not self._validate_api_key(authorization):
                log.warning("[FastAPIMessageProvider] Unauthorized process attempt")
                raise HTTPException(status_code=401, detail="Invalid or missing API key")

            try:
                message_id = f"msg_{datetime.utcnow().timestamp()}"
                timestamp = datetime.utcnow().isoformat()

                message_data = {
                    "message_id": message_id,
                    "text": message.text,
                    "user_id": message.user_id,
                    "channel": message.channel,
                    "metadata": message.metadata,
                    "timestamp": timestamp
                }

                # Only notify listeners (orchestrator), do NOT send to clients
                # Clients should only receive outgoing messages via send_message()
                self._notify_listeners(message_data)

                log.info(f"[FastAPIMessageProvider] Processed message: {message_id}")

                return MessageResponse(
                    message_id=message_id,
                    status="processed",
                    timestamp=timestamp
                )

            except Exception as e:
                log.error(f"[FastAPIMessageProvider] Error processing message: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Failed to process message: {str(e)}")

        @self.app.post("/client/register")
        async def register_client(
            client: ClientRegistration,
            authorization: Optional[str] = Header(None)
        ):
            if not self._validate_api_key(authorization):
                log.warning("[FastAPIMessageProvider] Unauthorized client registration")
                raise HTTPException(status_code=401, detail="Invalid or missing API key")

            # Validate required fields
            errors = []
            if not client.source_type:
                errors.append("source_type is required")

            # Validate webhook fields consistency
            if client.webhook_url and not client.webhook_api_key:
                errors.append("webhook_api_key is required when webhook_url is provided")
            if client.webhook_api_key and not client.webhook_url:
                errors.append("webhook_url is required when webhook_api_key is provided")

            if errors:
                raise HTTPException(status_code=400, detail={"errors": errors})

            client_id = str(uuid.uuid4())
            client_data = {
                "client_id": client_id,
                "url": str(client.webhook_url) if client.webhook_url else None,
                "api_key": client.webhook_api_key,
                "source_type": client.source_type,
                "formatting_details": client.formatting_details,
                "description": client.description,
                "registered_at": datetime.utcnow().isoformat()
            }

            self.registered_clients.append(client_data)

            if client.webhook_url:
                log.info(f"[FastAPIMessageProvider] Registered client {client_id} with webhook: {client.webhook_url} (type: {client.source_type})")
            else:
                log.info(f"[FastAPIMessageProvider] Registered client {client_id} without webhook (polling mode) (type: {client.source_type})")

            return {
                "status": "registered",
                "client": client_data,
                "total_clients": len(self.registered_clients)
            }

        @self.app.get("/client/list")
        async def list_clients(authorization: Optional[str] = Header(None)):
            if not self._validate_api_key(authorization):
                log.warning("[FastAPIMessageProvider] Unauthorized client list")
                raise HTTPException(status_code=401, detail="Invalid or missing API key")

            return {"clients": self.registered_clients, "count": len(self.registered_clients)}

        @self.app.delete("/client/unregister")
        async def unregister_client(
            client_url: str,
            authorization: Optional[str] = Header(None)
        ):
            if not self._validate_api_key(authorization):
                log.warning("[FastAPIMessageProvider] Unauthorized client unregister")
                raise HTTPException(status_code=401, detail="Invalid or missing API key")

            initial_count = len(self.registered_clients)
            self.registered_clients = [c for c in self.registered_clients if c['url'] != client_url]
            removed = initial_count - len(self.registered_clients)

            if removed > 0:
                log.info(f"[FastAPIMessageProvider] Unregistered client: {client_url}")
                return {"status": "unregistered", "client_url": client_url}
            else:
                raise HTTPException(status_code=404, detail="Client not found")

        @self.app.get("/messages/retrieve")
        async def retrieve_messages(
            client_id: str,
            clear: bool = True,
            authorization: Optional[str] = Header(None)
        ):
            if not self._validate_api_key(authorization):
                log.warning("[FastAPIMessageProvider] Unauthorized message retrieval")
                raise HTTPException(status_code=401, detail="Invalid or missing API key")

            if client_id not in self.message_queues:
                return {
                    "client_id": client_id,
                    "messages": [],
                    "count": 0,
                    "timestamp": datetime.utcnow().isoformat()
                }

            messages = self.message_queues[client_id].copy()

            if clear:
                self.message_queues[client_id].clear()
                log.info(f"[FastAPIMessageProvider] Retrieved and cleared {len(messages)} messages for client: {client_id}")
            else:
                log.info(f"[FastAPIMessageProvider] Retrieved {len(messages)} messages for client: {client_id} (without clearing)")

            return {
                "client_id": client_id,
                "messages": messages,
                "count": len(messages),
                "cleared": clear,
                "timestamp": datetime.utcnow().isoformat()
            }

        @self.app.get("/health")
        async def health_check():
            return {
                "status": "healthy",
                "registered_clients_count": len(self.registered_clients),
                "timestamp": datetime.utcnow().isoformat()
            }

    def get_app(self) -> FastAPI:
        return self.app

    def send_reaction(self, message_id: str, reaction: str) -> dict:
        payload = {
            "type": "reaction",
            "message_id": message_id,
            "reaction": reaction,
            "timestamp": datetime.utcnow().isoformat()
        }

        results = []
        for client in self.registered_clients:
            client_id = client.get('client_id')

            if client.get('url'):
                # Webhook mode: send immediately
                try:
                    log.info(f"[FastAPIMessageProvider] Sending reaction to client {client_id}: {client['url']}")
                    response = requests.post(
                        client['url'],
                        json=payload,
                        timeout=30
                    )
                    response.raise_for_status()
                    results.append({"client_id": client_id, "client_url": client['url'], "status": "success"})
                except Exception as e:
                    log.error(f"[FastAPIMessageProvider] Failed to send reaction to {client['url']}: {str(e)}")
                    results.append({"client_id": client_id, "client_url": client['url'], "status": "failed", "error": str(e)})
            else:
                # Polling mode: queue it
                log.info(f"[FastAPIMessageProvider] Queueing reaction for client {client_id}")
                self.message_queues[client_id].append(payload)
                results.append({"client_id": client_id, "status": "queued"})

        success = all(result.get("status") != "failed" for result in results)
        return {"success": success, "results": results}

    def update_message(self, message_id: str, new_text: str) -> dict:
        payload = {
            "type": "update",
            "message_id": message_id,
            "text": new_text,
            "timestamp": datetime.utcnow().isoformat()
        }

        results = []
        for client in self.registered_clients:
            client_id = client.get('client_id')

            if client.get('url'):
                # Webhook mode: send immediately
                try:
                    log.info(f"[FastAPIMessageProvider] Sending message update to client {client_id}: {client['url']}")
                    response = requests.post(
                        client['url'],
                        json=payload,
                        timeout=30
                    )
                    response.raise_for_status()
                    results.append({"client_id": client_id, "client_url": client['url'], "status": "success"})
                except Exception as e:
                    log.error(f"[FastAPIMessageProvider] Failed to send update to {client['url']}: {str(e)}")
                    results.append({"client_id": client_id, "client_url": client['url'], "status": "failed", "error": str(e)})
            else:
                # Polling mode: queue it
                log.info(f"[FastAPIMessageProvider] Queueing message update for client {client_id}")
                self.message_queues[client_id].append(payload)
                results.append({"client_id": client_id, "status": "queued"})

        success = all(result.get("status") != "failed" for result in results)
        return {"success": success, "results": results}

    def start(self, host: Optional[str] = None, port: Optional[int] = None):
        import uvicorn
        # Use provided params, fall back to instance config
        start_host = host if host is not None else self.host
        start_port = port if port is not None else self.port
        log.info(f"[FastAPIMessageProvider] Starting server on {start_host}:{start_port}")
        uvicorn.run(self.app, host=start_host, port=start_port)


# For direct uvicorn usage, create your own app.py:
#
# from message_provider import FastAPIMessageProvider
# import os
#
# provider = FastAPIMessageProvider(
#     api_key=os.getenv("MESSAGE_API_KEY"),
#     host=os.getenv("API_HOST", "0.0.0.0"),
#     port=int(os.getenv("API_PORT", "9547"))
# )
# app = provider.get_app()
#
# Then run: uvicorn your_app:app
