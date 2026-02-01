"""Tests for relay components."""

import pytest
from unittest.mock import Mock, AsyncMock, MagicMock, patch
import asyncio


@pytest.mark.asyncio
class TestRelayHub:
    """Test cases for RelayHub."""

    def test_init_success(self):
        """Test successful initialization."""
        from message_provider.relay.relay_hub import RelayHub

        mock_provider = Mock()
        mock_provider.register_message_listener = Mock()

        hub = RelayHub(
            local_provider=mock_provider,
            host="0.0.0.0",
            port=8765
        )

        assert hub.local_provider == mock_provider
        assert hub.host == "0.0.0.0"
        assert hub.port == 8765
        assert len(hub.connections) == 0

    def test_register_local_provider_listener(self):
        """Test that local provider listener is registered."""
        from message_provider.relay.relay_hub import RelayHub

        mock_provider = Mock()
        mock_provider.register_message_listener = Mock()

        hub = RelayHub(local_provider=mock_provider)

        mock_provider.register_message_listener.assert_called_once()


@pytest.mark.asyncio
class TestRelayMessageProvider:
    """Test cases for RelayMessageProvider."""

    def test_init_requires_websocket_url(self):
        """Test that websocket_url is required."""
        from message_provider.relay.relay_message_provider import RelayMessageProvider

        with pytest.raises(ValueError, match="websocket_url is required"):
            RelayMessageProvider(websocket_url="")

    def test_init_success(self):
        """Test successful initialization."""
        from message_provider.relay.relay_message_provider import RelayMessageProvider

        provider = RelayMessageProvider(
            websocket_url="ws://localhost:8765",
            reconnect_interval=10
        )

        assert provider.websocket_url == "ws://localhost:8765"
        assert provider.reconnect_interval == 10
        assert len(provider.message_listeners) == 0

    def test_register_message_listener(self):
        """Test registering a message listener."""
        from message_provider.relay.relay_message_provider import RelayMessageProvider

        provider = RelayMessageProvider(websocket_url="ws://localhost:8765")

        def handler(message):
            pass

        provider.register_message_listener(handler)
        assert len(provider.message_listeners) == 1

    def test_register_message_listener_not_callable(self):
        """Test that non-callable listener raises error."""
        from message_provider.relay.relay_message_provider import RelayMessageProvider

        provider = RelayMessageProvider(websocket_url="ws://localhost:8765")

        with pytest.raises(ValueError, match="Callback must be a callable"):
            provider.register_message_listener("not_a_function")

    def test_send_message(self):
        """Test sending a message through relay."""
        from message_provider.relay.relay_message_provider import RelayMessageProvider

        provider = RelayMessageProvider(websocket_url="ws://localhost:8765")
        provider.loop = asyncio.get_event_loop()
        provider.websocket = Mock()

        result = provider.send_message(
            message="Test",
            user_id="user123",
            channel="channel456"
        )

        # Should return status without waiting for actual send
        assert 'status' in result


@pytest.mark.asyncio
class TestRelayClient:
    """Test cases for RelayClient."""

    def test_init_requires_local_provider(self):
        """Test that local_provider is required."""
        from message_provider.relay.relay_client import RelayClient

        with pytest.raises(ValueError, match="local_provider is required"):
            RelayClient(
                local_provider=None,
                relay_hub_url="ws://localhost:8765",
                client_id="test:client"
            )

    def test_init_requires_relay_hub_url(self):
        """Test that relay_hub_url is required."""
        from message_provider.relay.relay_client import RelayClient

        with pytest.raises(ValueError, match="relay_hub_url is required"):
            RelayClient(
                local_provider=Mock(),
                relay_hub_url="",
                client_id="test:client"
            )

    def test_init_requires_client_id(self):
        """Test that client_id is required."""
        from message_provider.relay.relay_client import RelayClient

        with pytest.raises(ValueError, match="client_id is required"):
            RelayClient(
                local_provider=Mock(),
                relay_hub_url="ws://localhost:8765",
                client_id=""
            )

    def test_init_success(self):
        """Test successful initialization."""
        from message_provider.relay.relay_client import RelayClient

        mock_provider = Mock()
        mock_provider.register_message_listener = Mock()

        client = RelayClient(
            local_provider=mock_provider,
            relay_hub_url="ws://localhost:8765",
            client_id="test:client",
            reconnect_interval=10
        )

        assert client.local_provider == mock_provider
        assert client.relay_hub_url == "ws://localhost:8765"
        assert client.client_id == "test:client"
        assert client.reconnect_interval == 10

        # Should register as listener on local provider
        mock_provider.register_message_listener.assert_called_once()

    def test_on_local_message_adds_client_id(self):
        """Test that local messages get client_id added."""
        from message_provider.relay.relay_client import RelayClient

        mock_provider = Mock()
        mock_provider.register_message_listener = Mock()

        client = RelayClient(
            local_provider=mock_provider,
            relay_hub_url="ws://localhost:8765",
            client_id="test:client"
        )

        message_data = {
            'text': 'Hello',
            'user_id': 'user123'
        }

        # Simulate message from local provider
        client._on_local_message(message_data)

        # Should have metadata with client_id
        assert 'metadata' in message_data
        assert message_data['metadata']['client_id'] == "test:client"
