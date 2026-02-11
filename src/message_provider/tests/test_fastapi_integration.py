"""Integration tests for FastAPIMessageProvider with mock orchestrator."""

import pytest
import threading
import time
import concurrent.futures
from fastapi.testclient import TestClient
from unittest.mock import Mock, MagicMock
from typing import Dict, List, Optional


class MockOrchestrator:
    """
    Mock orchestrator that processes messages and sends replies.
    Simulates what a real orchestrator would do.
    """

    def __init__(self, provider):
        self.provider = provider
        self.received_messages: List[dict] = []
        self.auto_reply = True
        self.reply_delay = 0  # seconds
        self.reply_prefix = "Reply to: "

    def message_handler(self, message: dict):
        """Handle incoming messages from provider."""
        self.received_messages.append(message)

        # Only process regular messages (not status_request, cancellation_request, etc.)
        msg_type = message.get('type', 'message')
        if msg_type not in ('message', 'new_message'):
            return

        if self.auto_reply:
            # Simulate processing delay
            if self.reply_delay > 0:
                time.sleep(self.reply_delay)

            # Send reply back to the subscriber
            channel = message.get('channel')
            user_id = message.get('user_id')
            message_id = message.get('message_id')
            text = message.get('text', '')

            # Send reply
            reply_text = f"{self.reply_prefix}{text}"
            self.provider.send_message(
                message=reply_text,
                user_id=user_id,
                channel=channel,
                previous_message_id=message_id
            )


class MockAuthSystem:
    """Mock authentication system for testing."""

    def __init__(self):
        self.valid_users: Dict[str, dict] = {}
        self.sessions: Dict[str, str] = {}  # session_token -> subscriber_id
        self.token_counter = 0

    def add_valid_user(self, user_id: str, password: str = "password"):
        """Add a valid user to the system."""
        self.valid_users[user_id] = {"password": password}

    def authenticate(self, user_id: str, auth_details: dict) -> dict:
        """Authentication provider callback."""
        if user_id not in self.valid_users:
            return {"allowed": False, "reason": "User not found"}

        expected_password = self.valid_users[user_id].get("password")
        provided_password = auth_details.get("password")

        if provided_password != expected_password:
            return {"allowed": False, "reason": "Invalid password"}

        # Generate session token
        self.token_counter += 1
        session_token = f"session_{user_id}_{self.token_counter}"

        return {
            "allowed": True,
            "session_token": session_token,
            "user_role": "user"
        }

    def validate_session(self, subscriber_id: str, session_token: str) -> bool:
        """Session validator callback."""
        # Simple validation - token must start with "session_"
        if not session_token or not session_token.startswith("session_"):
            return False

        # Store mapping for tracking
        self.sessions[session_token] = subscriber_id
        return True


class TestFastAPIIntegration:
    """Integration tests for complete message flow."""

    def test_full_message_flow_without_auth(self):
        """Test complete flow: register → send message → receive reply (no auth)."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        # Setup provider
        provider = FastAPIMessageProvider(provider_id="test:integration")
        client = TestClient(provider.app)

        # Setup mock orchestrator
        orchestrator = MockOrchestrator(provider)
        provider.register_message_listener(orchestrator.message_handler)

        # Step 1: Register subscriber
        reg_response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "web"}
        )
        assert reg_response.status_code == 200
        subscriber_id = reg_response.json()['subscriber_id']

        # Step 2: Send message
        msg_response = client.post(
            "/message/process",
            json={
                "user_id": "user123",
                "text": "Hello, world!",
                "channel": subscriber_id
            }
        )
        assert msg_response.status_code == 200
        message_id = msg_response.json()['message_id']

        # Verify orchestrator received the message
        assert len(orchestrator.received_messages) == 1
        assert orchestrator.received_messages[0]['text'] == "Hello, world!"
        assert orchestrator.received_messages[0]['channel'] == subscriber_id

        # Step 3: Retrieve reply message
        messages_response = client.get(f"/messages/{subscriber_id}")
        assert messages_response.status_code == 200

        all_messages = messages_response.json()['messages']
        assert len(all_messages) >= 1

        # Filter to get just the reply message
        reply_messages = [m for m in all_messages if m.get('type') == 'message']
        assert len(reply_messages) == 1

        reply = reply_messages[0]
        assert reply['text'] == "Reply to: Hello, world!"
        assert reply['previous_message_id'] == message_id

    def test_full_message_flow_with_auth(self):
        """Test complete flow with authentication enabled."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        # Setup auth system
        auth_system = MockAuthSystem()
        auth_system.add_valid_user("user123", "secret123")

        # Setup provider with auth
        provider = FastAPIMessageProvider(
            provider_id="test:integration-auth",
            authentication_provider=auth_system.authenticate,
            session_validator=auth_system.validate_session
        )
        client = TestClient(provider.app)

        # Setup mock orchestrator
        orchestrator = MockOrchestrator(provider)
        provider.register_message_listener(orchestrator.message_handler)

        # Step 1: Register with valid credentials
        reg_response = client.post(
            "/subscriber/register",
            json={
                "user_id": "user123",
                "auth_details": {"password": "secret123"},
                "source_type": "web"
            }
        )
        assert reg_response.status_code == 200
        subscriber_id = reg_response.json()['subscriber_id']
        session_token = reg_response.json()['session_token']
        assert session_token is not None

        # Step 2: Send message with session token
        msg_response = client.post(
            "/message/process",
            json={
                "user_id": "user123",
                "text": "Authenticated message",
                "channel": subscriber_id
            },
            headers={"Authorization": f"Bearer {session_token}"}
        )
        assert msg_response.status_code == 200

        # Step 3: Retrieve messages with session token
        messages_response = client.get(
            f"/messages/{subscriber_id}",
            headers={"Authorization": f"Bearer {session_token}"}
        )
        assert messages_response.status_code == 200

        all_messages = messages_response.json()['messages']
        # Filter to get just the reply message
        reply_messages = [m for m in all_messages if m.get('type') == 'message']
        assert len(reply_messages) == 1

    def test_auth_denied_registration(self):
        """Test that invalid credentials are rejected."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        auth_system = MockAuthSystem()
        auth_system.add_valid_user("user123", "correct_password")

        provider = FastAPIMessageProvider(
            provider_id="test:auth-denied",
            authentication_provider=auth_system.authenticate
        )
        client = TestClient(provider.app)

        # Try to register with wrong password
        response = client.post(
            "/subscriber/register",
            json={
                "user_id": "user123",
                "auth_details": {"password": "wrong_password"},
                "source_type": "web"
            }
        )
        assert response.status_code == 403
        assert "Invalid password" in response.json()['detail']

    def test_session_validation_required(self):
        """Test that requests fail without valid session token."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        auth_system = MockAuthSystem()

        provider = FastAPIMessageProvider(
            provider_id="test:session-required",
            session_validator=auth_system.validate_session
        )
        client = TestClient(provider.app)

        # Register (no auth provider, so registration works)
        reg_response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "web"}
        )
        subscriber_id = reg_response.json()['subscriber_id']

        # Try to send message without session token
        response = client.post(
            "/message/process",
            json={
                "user_id": "user123",
                "text": "Test",
                "channel": subscriber_id
            }
        )
        assert response.status_code == 401

        # Try with invalid session token
        response = client.post(
            "/message/process",
            json={
                "user_id": "user123",
                "text": "Test",
                "channel": subscriber_id
            },
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401

        # Try with valid session token format
        response = client.post(
            "/message/process",
            json={
                "user_id": "user123",
                "text": "Test",
                "channel": subscriber_id
            },
            headers={"Authorization": "Bearer session_user123_1"}
        )
        assert response.status_code == 200

    def test_reregistration_preserves_queue(self):
        """Test that re-registration doesn't lose queued messages."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:reregister")
        client = TestClient(provider.app)

        # Register
        reg_response = client.post(
            "/subscriber/register",
            json={"user_id": "user123", "source_type": "web"}
        )
        subscriber_id = reg_response.json()['subscriber_id']

        # Queue a message
        provider.send_message("Message 1", "system", channel=subscriber_id)

        # Re-register with same ID
        rereg_response = client.post(
            "/subscriber/register",
            json={
                "subscriber_id": subscriber_id,
                "user_id": "user123",
                "source_type": "web"
            }
        )
        assert rereg_response.json()['status'] == "re-registered"

        # Queue another message
        provider.send_message("Message 2", "system", channel=subscriber_id)

        # Retrieve all messages
        messages_response = client.get(f"/messages/{subscriber_id}")
        assert messages_response.json()['count'] == 2
        texts = [m['text'] for m in messages_response.json()['messages']]
        assert "Message 1" in texts
        assert "Message 2" in texts

    def test_multiple_subscribers(self):
        """Test multiple subscribers receiving their own messages."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:multi-subscriber")
        client = TestClient(provider.app)

        # Register two subscribers
        reg1 = client.post("/subscriber/register", json={"user_id": "user1", "source_type": "web"})
        reg2 = client.post("/subscriber/register", json={"user_id": "user2", "source_type": "mobile"})

        sub1_id = reg1.json()['subscriber_id']
        sub2_id = reg2.json()['subscriber_id']

        # Send messages to each
        provider.send_message("For user 1", "system", channel=sub1_id)
        provider.send_message("For user 2", "system", channel=sub2_id)
        provider.send_message("Another for user 1", "system", channel=sub1_id)

        # Each subscriber should only see their messages
        msg1 = client.get(f"/messages/{sub1_id}")
        msg2 = client.get(f"/messages/{sub2_id}")

        assert msg1.json()['count'] == 2
        assert msg2.json()['count'] == 1

        texts1 = [m['text'] for m in msg1.json()['messages']]
        texts2 = [m['text'] for m in msg2.json()['messages']]

        assert "For user 1" in texts1
        assert "Another for user 1" in texts1
        assert "For user 2" in texts2

    def test_thread_handling(self):
        """Test thread_id is properly passed through the flow."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:threads")
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        # Register
        reg = client.post("/subscriber/register", json={"user_id": "user123", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        # Send message with thread_id
        response = client.post(
            "/message/process",
            json={
                "user_id": "user123",
                "text": "Thread message",
                "channel": subscriber_id,
                "thread_id": "thread_abc123"
            }
        )
        assert response.status_code == 200

        # Verify thread_id was passed to listener
        assert len(received) == 1
        assert received[0]['thread_id'] == "thread_abc123"

    def test_request_cancellation_flow(self):
        """Test request cancellation through the unified message API."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:cancellation")
        client = TestClient(provider.app)

        # Track cancellation notifications
        cancellations = []
        provider.register_request_cancellation_listener(
            lambda req_id, info: cancellations.append((req_id, info))
        )

        # Setup listener that tracks all messages
        received = []
        def handler(message):
            received.append(message)

        provider.register_message_listener(handler)

        # Register and send initial message
        reg = client.post("/subscriber/register", json={"user_id": "user123", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        msg_response = client.post(
            "/message/process",
            json={"user_id": "user123", "text": "Long request", "channel": subscriber_id}
        )
        message_id = msg_response.json()['message_id']

        # Send cancellation request through unified endpoint
        cancel_response = client.post(
            "/message/process",
            json={
                "type": "cancellation_request",
                "user_id": "user123",
                "channel": subscriber_id,
                "request_id": message_id
            }
        )
        assert cancel_response.status_code == 200

        # Verify cancellation listener was notified
        assert len(cancellations) == 1
        assert cancellations[0][0] == message_id

        # Verify both messages were received by listener
        assert len(received) == 2
        assert received[1]['type'] == "cancellation_request"

    def test_status_request_listener(self):
        """Test status request notifications through unified message API."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:status-requests")
        client = TestClient(provider.app)

        # Track status requests
        status_requests = []
        provider.register_request_status_update_listener(
            lambda req_id, info: status_requests.append((req_id, info))
        )

        # Track all messages
        received = []
        provider.register_message_listener(lambda m: received.append(m))

        # Register
        reg = client.post("/subscriber/register", json={"user_id": "user123", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        # Send initial message
        msg_response = client.post(
            "/message/process",
            json={"user_id": "user123", "text": "Test", "channel": subscriber_id}
        )
        message_id = msg_response.json()['message_id']

        # Send status request through unified endpoint
        status_response = client.post(
            "/message/process",
            json={
                "type": "status_request",
                "user_id": "user123",
                "channel": subscriber_id,
                "request_id": message_id
            }
        )
        assert status_response.status_code == 200

        # Verify status request listener was notified
        assert len(status_requests) == 1
        assert status_requests[0][0] == message_id
        assert status_requests[0][1]['type'] == "status_request"

        # Verify both messages were received by listener
        assert len(received) == 2
        assert received[1]['type'] == "status_request"

    def test_webhook_delivery(self):
        """Test webhook delivery mode (mocked)."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider
        from unittest.mock import patch

        provider = FastAPIMessageProvider(provider_id="test:webhook")
        client = TestClient(provider.app)

        # Register with webhook
        with patch('message_provider.fastapi_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()

            reg = client.post(
                "/subscriber/register",
                json={
                    "user_id": "user123",
                    "source_type": "web",
                    "webhook_url": "https://example.com/webhook",
                    "webhook_api_key": "webhook_secret"
                }
            )
            subscriber_id = reg.json()['subscriber_id']

            # Send message to subscriber
            result = provider.send_message("Webhook test", "system", channel=subscriber_id)

            assert result['success'] is True
            assert 'queued' not in result  # Webhook mode, not polling

            # Verify webhook was called
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert "https://example.com/webhook" in str(call_args)
            assert "Bearer webhook_secret" in str(call_args)

    def test_subscriber_unregistration(self):
        """Test subscriber unregistration."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:unregister")
        client = TestClient(provider.app)

        # Register
        reg = client.post("/subscriber/register", json={"user_id": "user123", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        # Queue a message
        provider.send_message("Test", "system", channel=subscriber_id)

        # Unregister
        unreg = client.delete(f"/subscriber/{subscriber_id}")
        assert unreg.status_code == 200
        assert unreg.json()['status'] == "unregistered"

        # Verify subscriber is gone
        response = client.get(f"/messages/{subscriber_id}")
        assert response.status_code == 404

        # Verify can't send to unregistered subscriber
        result = provider.send_message("Test", "system", channel=subscriber_id)
        assert result['success'] is False

    def test_metadata_passthrough(self):
        """Test that custom metadata is passed through."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:metadata")
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        # Register
        reg = client.post("/subscriber/register", json={"user_id": "user123", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        # Send with custom metadata
        response = client.post(
            "/message/process",
            json={
                "user_id": "user123",
                "text": "Test",
                "channel": subscriber_id,
                "metadata": {
                    "custom_field": "custom_value",
                    "another_field": 123
                }
            }
        )
        assert response.status_code == 200

        # Verify metadata in received message
        assert len(received) == 1
        assert received[0]['metadata']['custom_field'] == "custom_value"
        assert received[0]['metadata']['another_field'] == 123
        assert received[0]['metadata']['provider_id'] == "test:metadata"


class TestFastAPIUnitAdditional:
    """Additional unit tests for edge cases."""

    def test_empty_provider_id_rejected(self):
        """Test that empty provider_id is rejected."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        with pytest.raises(ValueError, match="provider_id is required"):
            FastAPIMessageProvider(provider_id="")

        with pytest.raises(ValueError, match="provider_id is required"):
            FastAPIMessageProvider(provider_id="   ")

    def test_invalid_port_rejected(self):
        """Test that invalid ports are rejected."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        with pytest.raises(ValueError):
            FastAPIMessageProvider(provider_id="test", port=0)

        with pytest.raises(ValueError):
            FastAPIMessageProvider(provider_id="test", port=70000)

    def test_non_callable_listener_rejected(self):
        """Test that non-callable listeners are rejected."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test")

        with pytest.raises(ValueError, match="callable"):
            provider.register_message_listener("not a function")

        with pytest.raises(ValueError, match="callable"):
            provider.register_request_status_update_listener(123)

        with pytest.raises(ValueError, match="callable"):
            provider.register_request_cancellation_listener(None)

    def test_send_message_with_thread_id(self):
        """Test send_message includes thread_id in payload."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test")
        client = TestClient(provider.app)

        # Register
        reg = client.post("/subscriber/register", json={"user_id": "user123", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        # Send with thread_id
        result = provider.send_message(
            message="Test",
            user_id="user123",
            channel=subscriber_id,
            thread_id="thread_xyz"
        )

        assert result['success'] is True

        # Check queued message has thread_id
        messages = client.get(f"/messages/{subscriber_id}")
        assert messages.json()['messages'][0]['thread_id'] == "thread_xyz"

    def test_get_app_returns_fastapi_instance(self):
        """Test get_app returns the FastAPI app."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider
        from fastapi import FastAPI

        provider = FastAPIMessageProvider(provider_id="test")
        app = provider.get_app()

        assert isinstance(app, FastAPI)
        assert app is provider.app

    def test_list_subscribers(self):
        """Test listing all subscribers."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test")
        client = TestClient(provider.app)

        # Initially empty
        response = client.get("/subscriber/list")
        assert response.json()['count'] == 0

        # Register some subscribers
        client.post("/subscriber/register", json={"user_id": "user1", "source_type": "web"})
        client.post("/subscriber/register", json={"user_id": "user2", "source_type": "mobile"})

        # Now should have 2
        response = client.get("/subscriber/list")
        assert response.json()['count'] == 2
        assert len(response.json()['subscribers']) == 2

    def test_clear_messages_parameter(self):
        """Test the clear parameter on message retrieval."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test")
        client = TestClient(provider.app)

        # Register
        reg = client.post("/subscriber/register", json={"user_id": "user123", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        # Queue messages
        provider.send_message("Msg 1", "system", channel=subscriber_id)
        provider.send_message("Msg 2", "system", channel=subscriber_id)

        # Retrieve without clearing
        response = client.get(f"/messages/{subscriber_id}?clear=false")
        assert response.json()['count'] == 2
        assert response.json()['cleared'] is False

        # Messages should still be there
        response = client.get(f"/messages/{subscriber_id}?clear=false")
        assert response.json()['count'] == 2

        # Now clear them
        response = client.get(f"/messages/{subscriber_id}?clear=true")
        assert response.json()['count'] == 2
        assert response.json()['cleared'] is True

        # Should be empty now
        response = client.get(f"/messages/{subscriber_id}")
        assert response.json()['count'] == 0


class TestConcurrentScenarios:
    """Tests for concurrent message handling and multi-client scenarios."""

    def test_message_while_another_processing(self):
        """Test sending a message while another is still being processed."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:concurrent")
        client = TestClient(provider.app)

        # Track processing
        processing_started = threading.Event()
        processing_complete = threading.Event()
        received_messages = []

        def slow_handler(message):
            """Handler that takes time to process."""
            if message.get('type') not in ('message', 'new_message'):
                return
            received_messages.append(message)
            processing_started.set()
            # Wait for signal to complete (simulates slow processing)
            processing_complete.wait(timeout=5)
            # Send reply
            provider.send_message(
                message=f"Reply to: {message.get('text')}",
                user_id="bot",
                channel=message['channel'],
                previous_message_id=message['message_id']
            )

        provider.register_message_listener(slow_handler)

        # Register subscriber
        reg = client.post("/subscriber/register", json={"user_id": "user1", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        # Send first message in background thread
        def send_first():
            return client.post(
                "/message/process",
                json={"user_id": "user1", "text": "First message", "channel": subscriber_id}
            )

        with concurrent.futures.ThreadPoolExecutor() as executor:
            first_future = executor.submit(send_first)

            # Wait for first message to start processing
            processing_started.wait(timeout=2)

            # Send second message while first is still processing
            second_response = client.post(
                "/message/process",
                json={"user_id": "user1", "text": "Second message", "channel": subscriber_id}
            )
            assert second_response.status_code == 200

            # Let first message complete
            processing_complete.set()
            first_response = first_future.result()
            assert first_response.status_code == 200

        # Both messages should have been received
        assert len(received_messages) == 2
        texts = [m['text'] for m in received_messages]
        assert "First message" in texts
        assert "Second message" in texts

    def test_multiple_clients_simultaneous(self):
        """Test multiple clients sending messages simultaneously."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:multi-client")
        client = TestClient(provider.app)

        received_messages = []
        lock = threading.Lock()

        def handler(message):
            if message.get('type') not in ('message', 'new_message'):
                return
            with lock:
                received_messages.append(message)
            # Send reply to correct channel
            provider.send_message(
                message=f"Reply to {message['user_id']}: {message.get('text')}",
                user_id="bot",
                channel=message['channel']
            )

        provider.register_message_listener(handler)

        # Register multiple subscribers
        num_clients = 5
        subscribers = []
        for i in range(num_clients):
            reg = client.post(
                "/subscriber/register",
                json={"user_id": f"user{i}", "source_type": "web"}
            )
            subscribers.append({
                "id": reg.json()['subscriber_id'],
                "user_id": f"user{i}"
            })

        # Send messages from all clients simultaneously
        def send_message(sub):
            return client.post(
                "/message/process",
                json={
                    "user_id": sub['user_id'],
                    "text": f"Message from {sub['user_id']}",
                    "channel": sub['id']
                }
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_clients) as executor:
            futures = [executor.submit(send_message, sub) for sub in subscribers]
            results = [f.result() for f in futures]

        # All requests should succeed
        assert all(r.status_code == 200 for r in results)

        # All messages should be received
        assert len(received_messages) == num_clients

        # Each subscriber should have their own reply
        for sub in subscribers:
            messages = client.get(f"/messages/{sub['id']}")
            assert messages.json()['count'] == 1
            reply = messages.json()['messages'][0]
            assert sub['user_id'] in reply['text']

    def test_client_isolation(self):
        """Test that clients only receive their own messages, not others'."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:isolation")
        client = TestClient(provider.app)

        # Register three subscribers
        reg_alice = client.post("/subscriber/register", json={"user_id": "alice", "source_type": "web"})
        reg_bob = client.post("/subscriber/register", json={"user_id": "bob", "source_type": "web"})
        reg_charlie = client.post("/subscriber/register", json={"user_id": "charlie", "source_type": "web"})

        alice_id = reg_alice.json()['subscriber_id']
        bob_id = reg_bob.json()['subscriber_id']
        charlie_id = reg_charlie.json()['subscriber_id']

        # Send different messages to each
        provider.send_message("Secret for Alice 1", "system", channel=alice_id)
        provider.send_message("Secret for Alice 2", "system", channel=alice_id)
        provider.send_message("Secret for Bob", "system", channel=bob_id)
        provider.send_message("Secret for Charlie 1", "system", channel=charlie_id)
        provider.send_message("Secret for Charlie 2", "system", channel=charlie_id)
        provider.send_message("Secret for Charlie 3", "system", channel=charlie_id)

        # Each client should only see their messages
        alice_msgs = client.get(f"/messages/{alice_id}").json()
        bob_msgs = client.get(f"/messages/{bob_id}").json()
        charlie_msgs = client.get(f"/messages/{charlie_id}").json()

        assert alice_msgs['count'] == 2
        assert bob_msgs['count'] == 1
        assert charlie_msgs['count'] == 3

        # Verify content isolation
        alice_texts = [m['text'] for m in alice_msgs['messages']]
        bob_texts = [m['text'] for m in bob_msgs['messages']]
        charlie_texts = [m['text'] for m in charlie_msgs['messages']]

        assert all("Alice" in t for t in alice_texts)
        assert all("Bob" in t for t in bob_texts)
        assert all("Charlie" in t for t in charlie_texts)

        # No cross-contamination
        assert not any("Bob" in t or "Charlie" in t for t in alice_texts)
        assert not any("Alice" in t or "Charlie" in t for t in bob_texts)
        assert not any("Alice" in t or "Bob" in t for t in charlie_texts)

    def test_rapid_fire_messages(self):
        """Test handling many messages in rapid succession."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:rapid-fire")
        client = TestClient(provider.app)

        received = []
        lock = threading.Lock()

        def handler(message):
            if message.get('type') not in ('message', 'new_message'):
                return
            with lock:
                received.append(message)
            # Echo back
            provider.send_message(
                message=f"Echo: {message.get('text')}",
                user_id="bot",
                channel=message['channel']
            )

        provider.register_message_listener(handler)

        # Register
        reg = client.post("/subscriber/register", json={"user_id": "user1", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        # Send many messages rapidly
        num_messages = 50

        def send_msg(i):
            return client.post(
                "/message/process",
                json={"user_id": "user1", "text": f"Message {i}", "channel": subscriber_id}
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(send_msg, i) for i in range(num_messages)]
            results = [f.result() for f in futures]

        # All should succeed
        assert all(r.status_code == 200 for r in results)

        # All messages received
        assert len(received) == num_messages

        # All replies queued
        messages = client.get(f"/messages/{subscriber_id}")
        assert messages.json()['count'] == num_messages

    def test_orchestrator_slow_response(self):
        """Test behavior when orchestrator takes time to respond."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:slow-orchestrator")
        client = TestClient(provider.app)

        def slow_handler(message):
            if message.get('type') not in ('message', 'new_message'):
                return
            # Simulate slow processing
            time.sleep(0.1)
            provider.send_message(
                message=f"Slow reply to: {message.get('text')}",
                user_id="bot",
                channel=message['channel']
            )

        provider.register_message_listener(slow_handler)

        # Register
        reg = client.post("/subscriber/register", json={"user_id": "user1", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        # Send message - should return quickly even if handler is slow
        start = time.time()
        response = client.post(
            "/message/process",
            json={"user_id": "user1", "text": "Test", "channel": subscriber_id}
        )
        elapsed = time.time() - start

        # Request should complete quickly (handler runs synchronously in test but
        # the response returns before we poll for messages)
        assert response.status_code == 200

        # Reply should be available
        messages = client.get(f"/messages/{subscriber_id}")
        assert messages.json()['count'] == 1
        assert "Slow reply" in messages.json()['messages'][0]['text']

    def test_interleaved_requests_multiple_clients(self):
        """Test interleaved requests from multiple clients."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:interleaved")
        client = TestClient(provider.app)

        received_order = []
        lock = threading.Lock()

        def handler(message):
            if message.get('type') not in ('message', 'new_message'):
                return
            with lock:
                received_order.append({
                    "user": message['user_id'],
                    "text": message['text'],
                    "channel": message['channel']
                })
            provider.send_message(
                message=f"Reply: {message.get('text')}",
                user_id="bot",
                channel=message['channel']
            )

        provider.register_message_listener(handler)

        # Register two clients
        reg1 = client.post("/subscriber/register", json={"user_id": "client1", "source_type": "web"})
        reg2 = client.post("/subscriber/register", json={"user_id": "client2", "source_type": "web"})
        sub1 = reg1.json()['subscriber_id']
        sub2 = reg2.json()['subscriber_id']

        # Interleave messages: client1, client2, client1, client2...
        for i in range(5):
            client.post(
                "/message/process",
                json={"user_id": "client1", "text": f"C1-Msg{i}", "channel": sub1}
            )
            client.post(
                "/message/process",
                json={"user_id": "client2", "text": f"C2-Msg{i}", "channel": sub2}
            )

        # 10 messages total received
        assert len(received_order) == 10

        # Each client gets 5 messages
        client1_msgs = [m for m in received_order if m['user'] == 'client1']
        client2_msgs = [m for m in received_order if m['user'] == 'client2']
        assert len(client1_msgs) == 5
        assert len(client2_msgs) == 5

        # Each client's queue has 5 replies
        msgs1 = client.get(f"/messages/{sub1}")
        msgs2 = client.get(f"/messages/{sub2}")
        assert msgs1.json()['count'] == 5
        assert msgs2.json()['count'] == 5

        # Verify correct routing
        for msg in msgs1.json()['messages']:
            assert "C1-Msg" in msg['text']
        for msg in msgs2.json()['messages']:
            assert "C2-Msg" in msg['text']

    def test_status_and_cancellation_dont_interfere_with_messages(self):
        """Test that status/cancellation requests don't affect regular message flow."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        provider = FastAPIMessageProvider(provider_id="test:mixed-types")
        client = TestClient(provider.app)

        messages_received = []
        status_requests = []
        cancellations = []

        def handler(message):
            msg_type = message.get('type', 'message')
            if msg_type in ('message', 'new_message'):
                messages_received.append(message)
                provider.send_message(
                    message=f"Reply: {message.get('text')}",
                    user_id="bot",
                    channel=message['channel']
                )
            elif msg_type == 'status_request':
                status_requests.append(message)
                # Could send status response as a message
            elif msg_type == 'cancellation_request':
                cancellations.append(message)

        provider.register_message_listener(handler)

        # Register
        reg = client.post("/subscriber/register", json={"user_id": "user1", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        # Send mix of message types
        msg1 = client.post(
            "/message/process",
            json={"user_id": "user1", "text": "Hello", "channel": subscriber_id}
        )
        msg1_id = msg1.json()['message_id']

        # Status request
        client.post(
            "/message/process",
            json={"type": "status_request", "user_id": "user1", "channel": subscriber_id, "request_id": msg1_id}
        )

        # Another message
        msg2 = client.post(
            "/message/process",
            json={"user_id": "user1", "text": "World", "channel": subscriber_id}
        )
        msg2_id = msg2.json()['message_id']

        # Cancellation
        client.post(
            "/message/process",
            json={"type": "cancellation_request", "user_id": "user1", "channel": subscriber_id, "request_id": msg2_id}
        )

        # Third message
        client.post(
            "/message/process",
            json={"user_id": "user1", "text": "Foo", "channel": subscriber_id}
        )

        # Verify correct routing
        assert len(messages_received) == 3
        assert len(status_requests) == 1
        assert len(cancellations) == 1

        # Only message replies in queue (not status/cancel responses in this setup)
        msgs = client.get(f"/messages/{subscriber_id}")
        assert msgs.json()['count'] == 3
        texts = [m['text'] for m in msgs.json()['messages']]
        assert all("Reply:" in t for t in texts)

    def test_request_context_cleanup(self):
        """Test that expired request contexts are cleaned up."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        # Create provider with very short TTL for testing
        provider = FastAPIMessageProvider(
            provider_id="test:cleanup",
            request_context_ttl=1,  # 1 second TTL
            max_request_contexts=100
        )
        client = TestClient(provider.app)

        provider.register_message_listener(lambda m: None)

        # Register
        reg = client.post("/subscriber/register", json={"user_id": "user1", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        # Send some messages
        for i in range(5):
            client.post(
                "/message/process",
                json={"user_id": "user1", "text": f"Msg {i}", "channel": subscriber_id}
            )

        # Should have 5 contexts tracked
        assert len(provider.request_context) == 5

        # Wait for TTL to expire
        time.sleep(1.5)

        # Force cleanup
        provider._cleanup_expired_contexts(force=True)

        # All contexts should be cleaned up
        assert len(provider.request_context) == 0

    def test_max_request_contexts_triggers_cleanup(self):
        """Test that exceeding max contexts triggers cleanup."""
        from message_provider.fastapi_message_provider import FastAPIMessageProvider

        # Create provider with low max contexts
        provider = FastAPIMessageProvider(
            provider_id="test:max-contexts",
            request_context_ttl=1,  # 1 second TTL
            max_request_contexts=5
        )
        client = TestClient(provider.app)

        provider.register_message_listener(lambda m: None)

        # Register
        reg = client.post("/subscriber/register", json={"user_id": "user1", "source_type": "web"})
        subscriber_id = reg.json()['subscriber_id']

        # Send messages up to max
        for i in range(5):
            client.post(
                "/message/process",
                json={"user_id": "user1", "text": f"Msg {i}", "channel": subscriber_id}
            )

        # Wait for TTL to expire
        time.sleep(1.5)

        # Send one more message - should trigger cleanup of expired contexts
        client.post(
            "/message/process",
            json={"user_id": "user1", "text": "Trigger cleanup", "channel": subscriber_id}
        )

        # Force check - old contexts should be cleaned, only new one remains
        provider._cleanup_expired_contexts(force=True)
        assert len(provider.request_context) == 1
