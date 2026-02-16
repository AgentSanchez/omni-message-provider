from abc import ABC, abstractmethod
from typing import Optional, Callable


class MessageProvider(ABC):
    """
    Abstract base class for all message providers.

    Defines the unified interface for sending messages, reactions, and updates
    across different platforms (Discord, Slack, Jira, etc.).
    """

    def __init__(self):
        pass

    @abstractmethod
    def send_message(
        self,
        message: str,
        user_id: str,
        channel: Optional[str] = None,
        previous_message_id: Optional[str] = None
    ):
        """
        Send a message to a user or channel.

        Args:
            message: Text to send
            user_id: User ID (or channel ID for some platforms)
            channel: Optional channel override
            previous_message_id: If provided, reply to this message (thread/reply)

        Returns:
            Dict with success status and message metadata
        """
        pass

    @abstractmethod
    def send_reaction(self, message_id: str, reaction: str):
        """
        Add a reaction to a message.

        Args:
            message_id: ID of the message to react to
            reaction: Reaction to add (emoji, label, etc.)

        Returns:
            Dict with success status
        """
        pass

    @abstractmethod
    def update_message(self, message_id: str, new_text: str):
        """
        Update an existing message.

        Args:
            message_id: ID of the message to update
            new_text: New message text (or status for platforms like Jira)

        Returns:
            Dict with success status
        """
        pass

    @abstractmethod
    def register_message_listener(self, callback: Callable):
        """
        Register a callback to be called when messages are received.

        Args:
            callback: Function that takes a message dict as parameter
        """
        pass

    @abstractmethod
    def start(self):
        """
        Start the message provider.

        This is typically a blocking call that runs the provider until stopped.
        """
        pass

    @abstractmethod
    def get_formatting_rules(self) -> str:
        """
        Return formatting rules/syntax description for this provider.

        Returns:
            String describing the formatting syntax (e.g., "mrkdwn", "markdown", "plaintext")
        """
        pass

    @abstractmethod
    def request_status_update(self, request_id: str, channel: Optional[str] = None) -> dict:
        """
        Poll for status of a previously submitted request.

        Args:
            request_id: ID of the request to check
            channel: Optional channel/subscriber context

        Returns:
            Dict with status info (e.g., pending, processing, completed, failed)
        """
        pass

    @abstractmethod
    def register_request_status_update_listener(self, callback: Callable) -> None:
        """
        Register a callback for request status update notifications.

        Args:
            callback: Function called with (request_id, status_info) when status changes
        """
        pass

    @abstractmethod
    def request_cancellation(self, request_id: str, channel: Optional[str] = None) -> dict:
        """
        Request cancellation of an active request.

        Args:
            request_id: ID of the request to cancel
            channel: Optional channel/subscriber context

        Returns:
            Dict with success status and cancellation info
        """
        pass

    @abstractmethod
    def register_request_cancellation_listener(self, callback: Callable) -> None:
        """
        Register a callback for cancellation notifications.

        Args:
            callback: Function called with (request_id, cancellation_info) when cancelled
        """
        pass

    def clear_thread(self, channel: str, metadata: Optional[dict] = None) -> dict:
        """
        Signal that a conversation/thread should end.

        Applications call this when a conversation should be marked as complete
        and not continued. Useful for session management and cleanup.

        Args:
            channel: Channel/thread identifier to clear
            metadata: Optional metadata about the clear event

        Returns:
            Dict with success status
        """
        return {"success": False, "error": "Not supported by this provider"}

    def register_thread_clear_listener(self, callback: Callable) -> None:
        """
        Register a callback for thread clear events.

        Args:
            callback: Function called with (channel, metadata) when thread is cleared
        """
        pass

    def register_reaction_listener(self, callback: Callable) -> None:
        """
        Register a callback to be called when reactions are received.

        Callback receives a dict with:
            - message_id: ID of the message that was reacted to
            - reaction: The emoji/reaction name
            - user_id: ID of the user who reacted
            - channel: Channel/conversation where the reaction occurred
            - metadata: Provider-specific metadata

        Args:
            callback: Function that takes a reaction dict as parameter
        """
        pass
