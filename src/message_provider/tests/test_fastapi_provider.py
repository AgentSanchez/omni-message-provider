"""Tests for FastAPIMessageProvider."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock


class TestFastAPIMessageProvider:
    """Test cases for FastAPIMessageProvider."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")

        assert provider.provider_id == "test:provider"
        assert provider.host == "0.0.0.0"
        assert provider.port == 9547
        assert provider.app is not None
        assert provider.authentication_provider is None
        assert provider.session_validator is None

    def test_init_requires_provider_id(self):
        """Test that provider_id is required."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        with pytest.raises(TypeError):
            FastAPIMessageProvider()

    def test_init_custom_values(self):
        """Test initialization with custom values."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(
            provider_id="test:custom",
            api_key="custom_key",
            host="127.0.0.1",
            port=8000
        )

        assert provider.provider_id == "test:custom"
        assert provider.host == "127.0.0.1"
        assert provider.port == 8000

    def test_init_with_auth_callbacks(self):
        """Test initialization with authentication callbacks."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        def auth_provider(user_id, auth_details):
            return {"allowed": True}

        def session_validator(subscriber_id, session_token):
            return True

        provider = FastAPIMessageProvider(
            provider_id="test:provider",
            authentication_provider=auth_provider,
            session_validator=session_validator
        )

        assert provider.authentication_provider is auth_provider
        assert provider.session_validator is session_validator

    def test_register_message_listener(self):
        """Test registering a message listener."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")

        def handler(message):
            pass

        provider.register_message_listener(handler)
        assert len(provider.message_listeners) == 1

    def test_send_message_requires_channel(self):
        """Test that send_message requires a channel (subscriber_id)."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        result = provider.send_message(
            message="Test message",
            user_id="user123"
        )

        assert result['success'] is False
        assert "channel" in result['error'].lower()

    def test_send_message_unknown_subscriber(self):
        """Test sending to unknown subscriber returns error."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        result = provider.send_message(
            message="Test message",
            user_id="user123",
            channel="unknown-subscriber-id"
        )

        assert result['success'] is False
        assert "not found" in result['error'].lower()

    def test_send_reaction_requires_channel(self):
        """Test that send_reaction requires a channel."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        result = provider.send_reaction(
            message_id="msg123",
            reaction="👍"
        )

        assert result['success'] is False
        assert "channel" in result['error'].lower()

    def test_update_message_requires_channel(self):
        """Test that update_message requires a channel."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        result = provider.update_message(
            message_id="msg123",
            new_text="Updated text"
        )

        assert result['success'] is False
        assert "channel" in result['error'].lower()

    def test_subscriber_registration(self):
        """Test subscriber registration endpoint."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        client = TestClient(provider.app)

        response = client.post(
            "/subscriber/register",
            json={
                "user_id": "user123",
                "source_type": "api"
            }
        )

        assert response.status_code == 200
        assert "subscriber_id" in response.json()
        assert response.json()['status'] == "registered"

    def test_subscriber_registration_requires_user_id(self):
        """Test that subscriber registration requires user_id."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        client = TestClient(provider.app)

        response = client.post(
            "/subscriber/register",
            json={
                "source_type": "api"
            }
        )

        assert response.status_code == 422  # Pydantic validation error

    def test_subscriber_reregistration(self):
        """Test subscriber re-registration with existing ID."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        client = TestClient(provider.app)

        # First registration
        response1 = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "api"}
        )
        subscriber_id = response1.json()['subscriber_id']

        # Re-registration with same ID
        response2 = client.post(
            "/subscriber/register",
            json={
                "subscriber_id": subscriber_id,
                "user_id": "user123",
                "source_type": "api"
            }
        )

        assert response2.status_code == 200
        assert response2.json()['status'] == "re-registered"
        assert response2.json()['subscriber_id'] == subscriber_id

    def test_process_message_requires_valid_subscriber(self):
        """Test that /message/process requires valid subscriber."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        client = TestClient(provider.app)

        response = client.post(
            "/message/process",
            json={
                "user_id": "user123",
                "text": "Hello",
                "channel": "unknown-subscriber"
            }
        )

        assert response.status_code == 404
        assert "not found" in response.json()['detail'].lower()

    def test_process_message_with_valid_subscriber(self):
        """Test /message/process with valid subscriber."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        client = TestClient(provider.app)

        # Register subscriber first
        reg_response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "api"}
        )
        subscriber_id = reg_response.json()['subscriber_id']

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
                "channel": subscriber_id
            }
        )

        assert response.status_code == 200
        assert len(received_messages) == 1
        assert received_messages[0]['text'] == "Hello"
        assert received_messages[0]['channel'] == subscriber_id
        assert received_messages[0]['metadata']['provider_id'] == "test:provider"

    def test_authentication_provider_denies_registration(self):
        """Test that authentication_provider can deny registration."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        def auth_provider(user_id, auth_details):
            return {"allowed": False, "reason": "Invalid credentials"}

        provider = FastAPIMessageProvider(
            provider_id="test:provider",
            authentication_provider=auth_provider
        )
        client = TestClient(provider.app)

        response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "api"}
        )

        assert response.status_code == 403
        assert "Invalid credentials" in response.json()['detail']

    def test_authentication_provider_allows_registration(self):
        """Test that authentication_provider can allow registration with session token."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        def auth_provider(user_id, auth_details):
            return {"allowed": True, "session_token": "test-session-token"}

        provider = FastAPIMessageProvider(
            provider_id="test:provider",
            authentication_provider=auth_provider
        )
        client = TestClient(provider.app)

        response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "api"}
        )

        assert response.status_code == 200
        assert response.json()['session_token'] == "test-session-token"

    def test_session_validator_validates_requests(self):
        """Test that session_validator validates requests."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        def session_validator(subscriber_id, session_token):
            return session_token == "valid-token"

        provider = FastAPIMessageProvider(
            provider_id="test:provider",
            session_validator=session_validator
        )
        client = TestClient(provider.app)

        # Register subscriber
        reg_response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "api"}
        )
        subscriber_id = reg_response.json()['subscriber_id']

        # Try to send message without valid session
        response = client.post(
            "/message/process",
            json={
                "user_id": "user123",
                "text": "Hello",
                "channel": subscriber_id
            },
            headers={"Authorization": "Bearer invalid-token"}
        )
        assert response.status_code == 401

        # Try with valid session
        response = client.post(
            "/message/process",
            json={
                "user_id": "user123",
                "text": "Hello",
                "channel": subscriber_id
            },
            headers={"Authorization": "Bearer valid-token"}
        )
        assert response.status_code == 200

    def test_send_message_to_registered_subscriber(self):
        """Test sending message to a registered subscriber (polling mode)."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        client = TestClient(provider.app)

        # Register a subscriber
        reg_response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "api"}
        )
        subscriber_id = reg_response.json()['subscriber_id']

        # Send message to subscriber
        result = provider.send_message(
            message="Test message",
            user_id="user123",
            channel=subscriber_id
        )

        assert result['success'] is True
        assert result['queued'] is True
        assert result['subscriber_id'] == subscriber_id

    def test_retrieve_messages(self):
        """Test retrieving queued messages."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        client = TestClient(provider.app)

        # Register subscriber
        reg_response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "api"}
        )
        subscriber_id = reg_response.json()['subscriber_id']

        # Send message
        provider.send_message("Test message", "user123", channel=subscriber_id)

        # Retrieve messages
        response = client.get(f"/messages/{subscriber_id}")

        assert response.status_code == 200
        assert response.json()['count'] == 1
        assert response.json()['messages'][0]['text'] == "Test message"

    def test_health_check(self):
        """Test health check endpoint."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        client = TestClient(provider.app)

        response = client.get("/health")

        assert response.status_code == 200
        assert response.json()['status'] == "healthy"
        assert response.json()['provider_id'] == "test:provider"

    def test_get_formatting_rules(self):
        """Test get_formatting_rules returns plaintext."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        assert provider.get_formatting_rules() == "plaintext"

    def test_request_status_update(self):
        """Test request_status_update for unknown request."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        result = provider.request_status_update("unknown-request-id")
        assert result['success'] is False

    def test_request_cancellation(self):
        """Test request_cancellation for unknown request."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        result = provider.request_cancellation("unknown-request-id")
        assert result['success'] is False

    def test_register_reaction_listener(self):
        """Test registering a reaction listener."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")

        def handler(reaction):
            pass

        provider.register_reaction_listener(handler)
        assert len(provider.reaction_listeners) == 1

    def test_register_reaction_listener_not_callable(self):
        """Test that non-callable reaction listener raises error."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")

        with pytest.raises(ValueError, match="Callback must be a callable"):
            provider.register_reaction_listener("not_a_function")

    def test_process_reaction_requires_valid_subscriber(self):
        """Test that /reaction/process requires a valid subscriber."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        client = TestClient(provider.app)

        response = client.post(
            "/reaction/process",
            json={
                "message_id": "msg123",
                "reaction": "👍",
                "user_id": "user123",
                "channel": "unknown-subscriber"
            }
        )

        assert response.status_code == 404
        assert "not found" in response.json()['detail'].lower()

    def test_process_reaction_with_valid_subscriber(self):
        """Test /reaction/process with a valid subscriber."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        client = TestClient(provider.app)

        # Register subscriber first
        reg_response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "api"}
        )
        subscriber_id = reg_response.json()['subscriber_id']

        # Register reaction listener
        received_reactions = []
        provider.register_reaction_listener(lambda r: received_reactions.append(r))

        # Send reaction
        response = client.post(
            "/reaction/process",
            json={
                "message_id": "msg_abc123",
                "reaction": "👍",
                "user_id": "user123",
                "channel": subscriber_id
            }
        )

        assert response.status_code == 200
        assert response.json()['status'] == "received"
        assert response.json()['message_id'] == "msg_abc123"
        assert response.json()['reaction'] == "👍"

        assert len(received_reactions) == 1
        assert received_reactions[0]['reaction'] == "👍"
        assert received_reactions[0]['message_id'] == "msg_abc123"
        assert received_reactions[0]['user_id'] == "user123"
        assert received_reactions[0]['channel'] == subscriber_id
        assert received_reactions[0]['metadata']['provider_id'] == "test:provider"

    def test_process_reaction_with_session_validation(self):
        """Test /reaction/process with session validation."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        def session_validator(subscriber_id, session_token):
            return session_token == "valid-token"

        provider = FastAPIMessageProvider(
            provider_id="test:provider",
            session_validator=session_validator
        )
        client = TestClient(provider.app)

        # Register subscriber
        reg_response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "api"}
        )
        subscriber_id = reg_response.json()['subscriber_id']

        # Try without valid session
        response = client.post(
            "/reaction/process",
            json={
                "message_id": "msg123",
                "reaction": "👍",
                "user_id": "user123",
                "channel": subscriber_id
            },
            headers={"Authorization": "Bearer invalid-token"}
        )
        assert response.status_code == 401

        # Try with valid session
        response = client.post(
            "/reaction/process",
            json={
                "message_id": "msg123",
                "reaction": "👍",
                "user_id": "user123",
                "channel": subscriber_id
            },
            headers={"Authorization": "Bearer valid-token"}
        )
        assert response.status_code == 200

    def test_process_reaction_with_metadata(self):
        """Test /reaction/process passes through custom metadata."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        client = TestClient(provider.app)

        # Register subscriber
        reg_response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "api"}
        )
        subscriber_id = reg_response.json()['subscriber_id']

        received_reactions = []
        provider.register_reaction_listener(lambda r: received_reactions.append(r))

        response = client.post(
            "/reaction/process",
            json={
                "message_id": "msg123",
                "reaction": "👍",
                "user_id": "user123",
                "channel": subscriber_id,
                "metadata": {"context": "approval", "priority": "high"}
            }
        )

        assert response.status_code == 200
        assert received_reactions[0]['metadata']['context'] == "approval"
        assert received_reactions[0]['metadata']['priority'] == "high"

    def test_reaction_listener_error_does_not_break_endpoint(self):
        """Test that a failing reaction listener doesn't break the endpoint."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:provider")
        client = TestClient(provider.app)

        # Register subscriber
        reg_response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "api"}
        )
        subscriber_id = reg_response.json()['subscriber_id']

        results = []

        def failing_listener(r):
            raise Exception("Listener failed!")

        def working_listener(r):
            results.append(r)

        provider.register_reaction_listener(failing_listener)
        provider.register_reaction_listener(working_listener)

        response = client.post(
            "/reaction/process",
            json={
                "message_id": "msg123",
                "reaction": "👍",
                "user_id": "user123",
                "channel": subscriber_id
            }
        )

        assert response.status_code == 200
        assert len(results) == 1
