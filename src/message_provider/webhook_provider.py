"""WebhookProvider - Abstract base class for inbound-only webhook providers.

Unlike MessageProvider which is bidirectional (send + receive), WebhookProvider
is for services that only push data inward via webhooks. There is no send_message,
send_reaction, update_message, etc.

Examples: Prometheus Alertmanager, GitHub webhooks, PagerDuty, etc.
"""

from abc import ABC, abstractmethod
from typing import Callable

from fastapi import FastAPI


class WebhookProvider(ABC):
    """
    Abstract base class for inbound-only webhook providers.

    Defines a minimal interface for services that receive data via HTTP webhooks
    and dispatch it to registered listeners. No outbound messaging capability.
    """

    @abstractmethod
    def register_message_listener(self, callback: Callable) -> None:
        """
        Register a callback to be called when webhook data is received.

        Args:
            callback: Function that takes a message/event dict as parameter
        """
        pass

    @abstractmethod
    def start(self) -> None:
        """
        Start the webhook server.

        This is typically a blocking call that runs until stopped.
        """
        pass

    @abstractmethod
    def get_formatting_rules(self) -> str:
        """
        Return formatting rules/syntax description for this provider.

        Returns:
            String describing the formatting syntax (e.g., "plaintext", "markdown")
        """
        pass

    @abstractmethod
    def get_app(self) -> FastAPI:
        """
        Return the FastAPI application instance.

        Useful for mounting the webhook server in an existing ASGI app
        or for testing with FastAPI's TestClient.

        Returns:
            The FastAPI app instance
        """
        pass
