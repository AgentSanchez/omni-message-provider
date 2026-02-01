"""Tests for FastAPIMessageProvider."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock


class TestFastAPIMessageProvider:
    """Test cases for FastAPIMessageProvider."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider()

        assert provider.host == "0.0.0.0"
        assert provider.port == 9547
        assert provider.app is not None

    def test_init_custom_values(self):
        """Test initialization with custom values."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(
            api_key="custom_key",
            host="127.0.0.1",
            port=8000
        )

        assert provider.host == "127.0.0.1"
        assert provider.port == 8000

    def test_register_message_listener(self):
        """Test registering a message listener."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider()

        def handler(message):
            pass

        provider.register_message_listener(handler)
        assert len(provider.message_listeners) == 1

    def test_send_message(self):
        """Test sending a message."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider()
        result = provider.send_message(
            message="Test message",
            user_id="user123",
            channel="channel456"
        )

        assert result['success'] is True
        assert 'message_id' in result

    def test_send_reaction(self):
        """Test sending a reaction."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider()
        result = provider.send_reaction(
            message_id="msg123",
            reaction="👍"
        )

        assert result['success'] is True

    def test_update_message(self):
        """Test updating a message."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider()
        result = provider.update_message(
            message_id="msg123",
            new_text="Updated text"
        )

        assert result['success'] is True

    def test_api_endpoint_process_message(self):
        """Test /message/process API endpoint."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(api_key="test_key")
        client = TestClient(provider.app)

        # Mock listener
        received_messages = []

        def handler(message):
            received_messages.append(message)

        provider.register_message_listener(handler)

        # Send message
        response = client.post(
            "/message/process",
            json={
                "user_id": "user123",
                "text": "Hello",
                "channel": "channel456"
            },
            headers={"Authorization": "Bearer test_key"}
        )

        assert response.status_code == 200
        assert len(received_messages) == 1
        assert received_messages[0]['text'] == "Hello"

    def test_api_endpoint_unauthorized(self):
        """Test unauthorized access to API endpoint."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(api_key="test_key")
        client = TestClient(provider.app)

        response = client.post(
            "/message/process",
            json={
                "user_id": "user123",
                "text": "Hello"
            },
            headers={"Authorization": "Bearer wrong_key"}
        )

        assert response.status_code == 401

    def test_health_check(self):
        """Test health check endpoint."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider()
        client = TestClient(provider.app)

        response = client.get("/health")

        assert response.status_code == 200
        assert response.json()['status'] == "healthy"
