import os
import secrets
import hmac
import hashlib
import uuid
import logging
from typing import Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, HttpUrl
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx

log = logging.getLogger(__name__)


class WebhookRegistration(BaseModel):
    url: HttpUrl
    events: List[str]
    description: Optional[str] = None


class WebhookRecord(BaseModel):
    id: str
    url: str
    events: List[str]
    secret: str
    description: Optional[str] = None
    created_at: datetime
    active: bool = True

    @classmethod
    def create(cls, registration: WebhookRegistration, secret: str):
        return cls(
            id=str(uuid.uuid4()),
            url=str(registration.url),
            events=registration.events,
            secret=secret,
            description=registration.description,
            created_at=datetime.utcnow(),
            active=True
        )


class WebhookResponse(BaseModel):
    id: str
    url: str
    events: List[str]
    secret: str
    description: Optional[str] = None
    created_at: datetime

    @classmethod
    def from_record(cls, record: WebhookRecord):
        return cls(
            id=record.id,
            url=record.url,
            events=record.events,
            secret=record.secret,
            description=record.description,
            created_at=record.created_at
        )


class WebhookEvent(BaseModel):
    event: str
    data: Dict
    timestamp: datetime = None

    def __init__(self, **data):
        if data.get('timestamp') is None:
            data['timestamp'] = datetime.utcnow()
        super().__init__(**data)


class WebhookStorage:
    def __init__(self):
        self._webhooks: Dict[str, WebhookRecord] = {}

    def add(self, webhook: WebhookRecord) -> WebhookRecord:
        self._webhooks[webhook.id] = webhook
        log.info(f"Registered webhook {webhook.id} for events: {webhook.events}")
        return webhook

    def get(self, webhook_id: str) -> Optional[WebhookRecord]:
        return self._webhooks.get(webhook_id)

    def get_all(self) -> List[WebhookRecord]:
        return list(self._webhooks.values())

    def get_by_event(self, event: str) -> List[WebhookRecord]:
        return [
            webhook for webhook in self._webhooks.values()
            if webhook.active and event in webhook.events
        ]

    def delete(self, webhook_id: str) -> bool:
        if webhook_id in self._webhooks:
            del self._webhooks[webhook_id]
            log.info(f"Deleted webhook {webhook_id}")
            return True
        return False


_storage = None


def get_storage() -> WebhookStorage:
    global _storage
    if _storage is None:
        _storage = WebhookStorage()
    return _storage


security = HTTPBearer()


def get_api_key() -> str:
    api_key = os.environ.get("WEBHOOK_API_KEY")
    if not api_key:
        api_key = secrets.token_urlsafe(32)
        print(f"WARNING: WEBHOOK_API_KEY not set. Using temporary key: {api_key}")
    return api_key


def verify_api_key(credentials: HTTPAuthorizationCredentials = Security(security)) -> bool:
    expected_key = get_api_key()

    if credentials.credentials != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return True


def generate_webhook_secret() -> str:
    return secrets.token_urlsafe(32)


def generate_signature(payload: str, secret: str) -> str:
    return hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


async def send_webhook(webhook: WebhookRecord, event: WebhookEvent) -> bool:
    payload = event.model_dump_json()
    signature = generate_signature(payload, webhook.secret)

    headers = {
        'Content-Type': 'application/json',
        'X-Webhook-Signature': signature,
        'X-Webhook-Event': event.event,
        'X-Webhook-Id': webhook.id,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                webhook.url,
                content=payload,
                headers=headers
            )

            if response.status_code >= 200 and response.status_code < 300:
                log.info(f"Webhook delivered successfully to {webhook.url} (event: {event.event})")
                return True
            else:
                log.warning(
                    f"Webhook delivery failed to {webhook.url}: "
                    f"HTTP {response.status_code} - {response.text}"
                )
                return False

    except httpx.TimeoutException:
        log.error(f"Webhook delivery timeout to {webhook.url}")
        return False
    except Exception as e:
        log.error(f"Webhook delivery error to {webhook.url}: {e}")
        return False


async def deliver_webhook_event(event_name: str, data: Dict) -> List[bool]:
    storage = get_storage()
    webhooks = storage.get_by_event(event_name)

    if not webhooks:
        log.debug(f"No webhooks registered for event: {event_name}")
        return []

    event = WebhookEvent(event=event_name, data=data)
    results = []

    log.info(f"Delivering event '{event_name}' to {len(webhooks)} webhook(s)")

    for webhook in webhooks:
        result = await send_webhook(webhook, event)
        results.append(result)

    return results


def verify_webhook_signature(payload: str, signature: str, secret: str) -> bool:
    expected_signature = generate_signature(payload, secret)
    return hmac.compare_digest(expected_signature, signature)
