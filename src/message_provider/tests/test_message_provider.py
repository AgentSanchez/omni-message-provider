"""Tests for MessageProvider abstract base class."""

import pytest
from message_provider.message_provider import MessageProvider


class MockMessageProvider(MessageProvider):
    """Mock implementation for testing."""

    def __init__(self):
        super().__init__()
        self.sent_messages = []
        self.sent_reactions = []
        self.updated_messages = []
        self.listeners = []

    def send_message(self, message, user_id, channel=None, previous_message_id=None):
        self.sent_messages.append({
            'message': message,
            'user_id': user_id,
            'channel': channel,
            'previous_message_id': previous_message_id
        })
        return {'success': True, 'message_id': 'test_123'}

    def send_reaction(self, message_id, reaction):
        self.sent_reactions.append({
            'message_id': message_id,
            'reaction': reaction
        })
        return {'success': True}

    def update_message(self, message_id, new_text):
        self.updated_messages.append({
            'message_id': message_id,
            'new_text': new_text
        })
        return {'success': True}

    def register_message_listener(self, callback):
        self.listeners.append(callback)

    def start(self):
        pass


class TestMessageProvider:
    """Test cases for MessageProvider interface."""

    def test_send_message(self):
        """Test send_message method."""
        provider = MockMessageProvider()
        result = provider.send_message(
            message="Hello",
            user_id="user123",
            channel="channel456"
        )

        assert result['success'] is True
        assert len(provider.sent_messages) == 1
        assert provider.sent_messages[0]['message'] == "Hello"
        assert provider.sent_messages[0]['user_id'] == "user123"
        assert provider.sent_messages[0]['channel'] == "channel456"

    def test_send_reaction(self):
        """Test send_reaction method."""
        provider = MockMessageProvider()
        result = provider.send_reaction(
            message_id="msg123",
            reaction="👍"
        )

        assert result['success'] is True
        assert len(provider.sent_reactions) == 1
        assert provider.sent_reactions[0]['message_id'] == "msg123"
        assert provider.sent_reactions[0]['reaction'] == "👍"

    def test_update_message(self):
        """Test update_message method."""
        provider = MockMessageProvider()
        result = provider.update_message(
            message_id="msg123",
            new_text="Updated text"
        )

        assert result['success'] is True
        assert len(provider.updated_messages) == 1
        assert provider.updated_messages[0]['message_id'] == "msg123"
        assert provider.updated_messages[0]['new_text'] == "Updated text"

    def test_register_message_listener(self):
        """Test register_message_listener method."""
        provider = MockMessageProvider()

        def handler(message):
            pass

        provider.register_message_listener(handler)
        assert len(provider.listeners) == 1
        assert provider.listeners[0] == handler
