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
