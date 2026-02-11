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
        self.status_listeners = []
        self.cancellation_listeners = []

    def send_message(self, message, user_id, channel=None, previous_message_id=None):
        self.sent_messages.append({
            'message': message,
            'user_id': user_id,
            'channel': channel,
            'previous_message_id': previous_message_id
        })
        return {'success': True, 'message_id': 'test_123'}

    def send_reaction(self, message_id, reaction, channel=None):
        self.sent_reactions.append({
            'message_id': message_id,
            'reaction': reaction,
            'channel': channel
        })
        return {'success': True}

    def update_message(self, message_id, new_text, channel=None):
        self.updated_messages.append({
            'message_id': message_id,
            'new_text': new_text,
            'channel': channel
        })
        return {'success': True}

    def register_message_listener(self, callback):
        self.listeners.append(callback)

    def start(self):
        pass

    def get_formatting_rules(self) -> str:
        return "mock"

    def request_status_update(self, request_id, channel=None):
        return {"success": True, "request_id": request_id, "status": "mock_status"}

    def register_request_status_update_listener(self, callback):
        self.status_listeners.append(callback)

    def request_cancellation(self, request_id, channel=None):
        return {"success": True, "request_id": request_id, "status": "cancelled"}

    def register_request_cancellation_listener(self, callback):
        self.cancellation_listeners.append(callback)


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

    def test_get_formatting_rules(self):
        """Test get_formatting_rules method."""
        provider = MockMessageProvider()
        assert provider.get_formatting_rules() == "mock"

    def test_request_status_update(self):
        """Test request_status_update method."""
        provider = MockMessageProvider()
        result = provider.request_status_update("request123")
        assert result['success'] is True
        assert result['request_id'] == "request123"

    def test_register_request_status_update_listener(self):
        """Test register_request_status_update_listener method."""
        provider = MockMessageProvider()

        def handler(request_id, status):
            pass

        provider.register_request_status_update_listener(handler)
        assert len(provider.status_listeners) == 1

    def test_request_cancellation(self):
        """Test request_cancellation method."""
        provider = MockMessageProvider()
        result = provider.request_cancellation("request123")
        assert result['success'] is True
        assert result['request_id'] == "request123"

    def test_register_request_cancellation_listener(self):
        """Test register_request_cancellation_listener method."""
        provider = MockMessageProvider()

        def handler(request_id, info):
            pass

        provider.register_request_cancellation_listener(handler)
        assert len(provider.cancellation_listeners) == 1
