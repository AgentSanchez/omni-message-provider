"""Prometheus Webhook Provider - Receives Prometheus Alertmanager webhook alerts.

This provider accepts Alertmanager webhook POSTs and dispatches normalized alert
data to registered listeners. It is inbound-only (no send capability).

Alertmanager webhook docs:
https://prometheus.io/docs/alerting/latest/configuration/#webhook_config
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, Callable, List

from fastapi import FastAPI, HTTPException, Request

from message_provider.webhook_provider import WebhookProvider

log = logging.getLogger(__name__)


class PrometheusWebhookProvider(WebhookProvider):
    """
    Prometheus Alertmanager Webhook Provider.

    Receives Alertmanager webhook POSTs and dispatches alerts to registered listeners.
    Supports two parse modes:
        - "alertmanager" (default): Parse the standard Alertmanager payload,
          emit one listener call per alert with normalized fields.
        - "raw": Pass the entire JSON payload as-is to listeners.

    Args:
        client_id: Unique identifier for this provider instance
        parse_mode: How to parse incoming payloads ("alertmanager" or "raw")
        api_key: Optional API key for authenticating webhook requests
        host: Webhook server host. Default: "0.0.0.0"
        port: Webhook server port. Default: 9549
        webhook_path: Path for the webhook endpoint. Default: "/webhook"

    Usage:
        provider = PrometheusWebhookProvider(
            client_id="prometheus:prod",
            api_key=os.getenv("WEBHOOK_API_KEY"),
        )

        def alert_handler(alert):
            print(f"Alert: {alert['status']} - {alert['text']}")

        provider.register_message_listener(alert_handler)
        provider.start()
    """

    VALID_PARSE_MODES = ("alertmanager", "raw")

    def __init__(
        self,
        client_id: str = "prometheus:default",
        parse_mode: str = "alertmanager",
        api_key: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 9549,
        webhook_path: str = "/webhook",
    ):
        if not client_id:
            raise ValueError("client_id is required")
        if parse_mode not in self.VALID_PARSE_MODES:
            raise ValueError(
                f"parse_mode must be one of {self.VALID_PARSE_MODES}, got {parse_mode!r}"
            )

        self.client_id = client_id
        self.parse_mode = parse_mode
        self.api_key = api_key
        self.host = host
        self.port = port
        self.webhook_path = webhook_path

        self.app = FastAPI(
            title="Prometheus Webhook Provider",
            description="Webhook receiver for Prometheus Alertmanager",
            version="1.0.0",
        )

        self.message_listeners: List[Callable] = []

        self._setup_routes()
        log.info(f"[PrometheusWebhookProvider] Initialized ({client_id}, mode={parse_mode})")

    def _setup_routes(self):
        @self.app.post(self.webhook_path)
        async def webhook_receiver(request: Request):
            """Receive Alertmanager webhook POST."""
            # API key validation
            if self.api_key:
                auth_header = request.headers.get("Authorization", "")
                # Support "Bearer <key>" or raw key
                token = auth_header.removeprefix("Bearer ").strip()
                if token != self.api_key:
                    raise HTTPException(status_code=401, detail="Invalid or missing API key")

            try:
                payload = await request.json()
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid JSON payload")

            received_at = datetime.now(timezone.utc).isoformat()

            if self.parse_mode == "raw":
                message_data = {
                    "source_type": "prometheus",
                    "type": "alert",
                    "text": str(payload),
                    "channel": self.client_id,
                    "metadata": {
                        "client_id": self.client_id,
                        "raw_payload": payload,
                    },
                    "timestamp": received_at,
                }
                self._notify_listeners(message_data)
            else:
                # alertmanager mode
                alerts = self._parse_alertmanager(payload, received_at)
                for alert in alerts:
                    self._notify_listeners(alert)

            return {"message": "OK"}

        @self.app.get("/health")
        async def health_check():
            return {
                "status": "healthy",
                "client_id": self.client_id,
                "parse_mode": self.parse_mode,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def _parse_alertmanager(self, payload: dict, received_at: str) -> list:
        """Parse Alertmanager payload into a list of normalized alert dicts."""
        alerts = []
        raw_alerts = payload.get("alerts", [])

        # Envelope-level fields
        receiver = payload.get("receiver", "")
        external_url = payload.get("externalURL", "")
        group_key = payload.get("groupKey", "")
        group_labels = payload.get("groupLabels", {})
        common_labels = payload.get("commonLabels", {})
        common_annotations = payload.get("commonAnnotations", {})

        for raw_alert in raw_alerts:
            labels = raw_alert.get("labels", {})
            annotations = raw_alert.get("annotations", {})
            status = raw_alert.get("status", "unknown")
            fingerprint = raw_alert.get("fingerprint", "")

            # Use fingerprint as alert_id, or generate one
            alert_id = fingerprint or str(uuid.uuid4())

            # Text: prefer summary, fall back to description
            text = annotations.get("summary") or annotations.get("description") or ""

            # Channel: use groupKey if available, otherwise alertname
            channel = group_key or labels.get("alertname", self.client_id)

            alert_data = {
                "source_type": "prometheus",
                "type": "alert",
                "alert_id": alert_id,
                "status": status,
                "text": text,
                "labels": labels,
                "annotations": annotations,
                "starts_at": raw_alert.get("startsAt", ""),
                "ends_at": raw_alert.get("endsAt", ""),
                "generator_url": raw_alert.get("generatorURL", ""),
                "channel": channel,
                "metadata": {
                    "client_id": self.client_id,
                    "receiver": receiver,
                    "external_url": external_url,
                    "group_labels": group_labels,
                    "common_labels": common_labels,
                    "common_annotations": common_annotations,
                    "raw_payload": payload,
                },
                "timestamp": received_at,
            }
            alerts.append(alert_data)

        return alerts

    def _notify_listeners(self, data: dict):
        """Notify all registered listeners, isolating errors."""
        for listener in self.message_listeners:
            try:
                listener(data)
            except Exception as e:
                log.error(f"[PrometheusWebhookProvider] Listener error: {e}")

    def register_message_listener(self, callback: Callable) -> None:
        if not callable(callback):
            raise ValueError("Callback must be callable")
        self.message_listeners.append(callback)

    def get_formatting_rules(self) -> str:
        return "plaintext"

    def get_app(self) -> FastAPI:
        return self.app

    def start(self, host: Optional[str] = None, port: Optional[int] = None):
        import uvicorn
        uvicorn.run(
            self.app,
            host=host or self.host,
            port=port or self.port,
        )
