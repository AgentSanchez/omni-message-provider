"""Tests for HttpSmsMessageProvider."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
import threading


class TestHttpSmsMessageProviderInit:
    """Tests for HttpSmsMessageProvider initialization."""

    def test_init_requires_api_key(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        with pytest.raises(ValueError, match="api_key is required"):
            HttpSmsMessageProvider(api_key="", phone_number="+15551234567")

    def test_init_requires_phone_number(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        with pytest.raises(ValueError, match="phone_number is required"):
            HttpSmsMessageProvider(api_key="test-key", phone_number="")

    def test_init_success_minimal(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        assert provider.api_key == "test-key"
        assert provider.phone_number == "+15551234567"
        assert provider.client_id == "httpsms:default"
        assert provider.message_authenticator is None
        assert provider.host == "0.0.0.0"
        assert provider.port == 9548

    def test_init_success_full_config(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        def my_auth(sender, recipient, content, metadata):
            return {"allowed": True}

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            client_id="httpsms:test",
            message_authenticator=my_auth,
            host="127.0.0.1",
            port=8080
        )

        assert provider.api_key == "test-key"
        assert provider.phone_number == "+15551234567"
        assert provider.client_id == "httpsms:test"
        assert provider.message_authenticator == my_auth
        assert provider.host == "127.0.0.1"
        assert provider.port == 8080


class TestHttpSmsMessageProviderListeners:
    """Tests for message listener registration."""

    def test_register_message_listener(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        assert len(provider.message_listeners) == 1

    def test_register_multiple_listeners(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        provider.register_message_listener(lambda m: None)
        provider.register_message_listener(lambda m: None)
        provider.register_message_listener(lambda m: None)

        assert len(provider.message_listeners) == 3

    def test_non_callable_listener_rejected(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        with pytest.raises(ValueError, match="callable"):
            provider.register_message_listener("not a function")

    def test_listener_error_does_not_break_others(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        results = []

        def failing_listener(m):
            raise Exception("Listener failed!")

        def working_listener(m):
            results.append(m)

        provider.register_message_listener(failing_listener)
        provider.register_message_listener(working_listener)

        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": "Hello!"
        })

        assert response.status_code == 200
        assert len(results) == 1


class TestHttpSmsWebhook:
    """Tests for webhook message reception."""

    def test_webhook_receives_message(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": "Hello!"
        })

        assert response.status_code == 200
        assert len(received) == 1
        assert received[0]['text'] == "Hello!"
        assert received[0]['user_id'] == "+15559876543"
        assert received[0]['channel'] == "+15559876543"
        assert received[0]['type'] == "message"
        assert received[0]['thread_id'] == "sms_default"
        assert "timestamp" in received[0]
        assert received[0]['metadata']['client_id'] == "httpsms:default"

    def test_webhook_wrong_recipient_rejected(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15550000000",
            "content": "Hello!"
        })

        assert response.status_code == 403
        assert len(received) == 0

    def test_webhook_authentication_rejected(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        def reject_all(sender, recipient, content, metadata):
            return {"allowed": False, "reason": "Not authorized"}

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            message_authenticator=reject_all
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": "Hello!"
        })

        assert response.status_code == 403
        assert len(received) == 0

    def test_webhook_authentication_accepted(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        def allow_specific(sender, recipient, content, metadata):
            if sender == "+15559876543":
                return {"allowed": True}
            return {"allowed": False}

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            message_authenticator=allow_specific
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": "Hello!"
        })

        assert response.status_code == 200
        assert len(received) == 1

    def test_webhook_authentication_with_metadata(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        auth_calls = []

        def track_auth(sender, recipient, content, metadata):
            auth_calls.append({
                "sender": sender,
                "recipient": recipient,
                "content": content,
                "metadata": metadata
            })
            return {"allowed": True}

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            message_authenticator=track_auth
        )
        client = TestClient(provider.app)

        client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": "Hello!",
            "metadata": {"carrier": "verizon"}
        })

        assert len(auth_calls) == 1
        assert auth_calls[0]["sender"] == "+15559876543"
        assert auth_calls[0]["content"] == "Hello!"
        assert auth_calls[0]["metadata"]["carrier"] == "verizon"

    def test_webhook_no_authenticator_allows_all(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
            # No message_authenticator
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        # Any sender should be allowed
        response = client.post("/webhook", json={
            "sender": "+15559999999",
            "recipient": "+15551234567",
            "content": "From anyone"
        })

        assert response.status_code == 200
        assert len(received) == 1

    def test_webhook_message_id_from_timestamp(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": "Hello!",
            "timestamp": "2024-01-15T10:30:00.123456Z"
        })

        # Message ID should be based on timestamp
        assert received[0]['message_id'].startswith("sms_")
        assert "20240115" in received[0]['message_id']

    def test_webhook_generates_timestamp_if_missing(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": "Hello!"
        })

        assert received[0]['message_id'].startswith("sms_")
        assert "timestamp" in received[0]

    def test_metadata_passthrough(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": "Hello!",
            "metadata": {"carrier": "verizon", "signal": -75}
        })

        assert received[0]['metadata']['carrier'] == "verizon"
        assert received[0]['metadata']['signal'] == -75
        assert received[0]['metadata']['client_id'] == "httpsms:default"


class TestHttpSmsCommands:
    """Tests for built-in commands (/help, /clear) and initial_text."""

    def test_help_command_sends_default_help_text(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            response = client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "/help"
            })

            assert response.status_code == 200
            assert response.json()["action"] == "help"
            # Should NOT forward /help to listeners
            assert len(received) == 0
            # Should have sent help text
            mock_post.assert_called()
            payload = mock_post.call_args[1]['json']
            assert "help" in payload['content'].lower() or "/clear" in payload['content'].lower()

    def test_help_command_sends_custom_help_text(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            help_text="Custom help: Type anything to chat!"
        )
        client = TestClient(provider.app)

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "/help"
            })

            payload = mock_post.call_args[1]['json']
            assert payload['content'] == "Custom help: Type anything to chat!"

    def test_help_command_case_insensitive(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            response = client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "/HELP"
            })

            assert response.json()["action"] == "help"

    def test_clear_command_triggers_thread_clear(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        cleared = []
        provider.register_thread_clear_listener(lambda c, m: cleared.append((c, m)))

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": "/clear"
        })

        assert response.status_code == 200
        assert response.json()["action"] == "clear"
        # Should NOT forward /clear to listeners
        assert len(received) == 0
        # Should have triggered clear
        assert len(cleared) == 1
        assert cleared[0][0] == "+15559876543"
        assert cleared[0][1]["reason"] == "user_cleared"

    def test_clear_command_case_insensitive(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        cleared = []
        provider.register_thread_clear_listener(lambda c, m: cleared.append((c, m)))

        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": "/CLEAR"
        })

        assert response.json()["action"] == "clear"
        assert len(cleared) == 1

    def test_initial_text_sent_to_new_sender(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            initial_text="Welcome! Type /help for commands."
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            # First message from sender
            client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "Hello!"
            })

            # Should have sent initial_text
            assert mock_post.called
            payload = mock_post.call_args[1]['json']
            assert payload['content'] == "Welcome! Type /help for commands."

            # Message should still be forwarded
            assert len(received) == 1
            assert received[0]['metadata']['is_new_sender'] is True

    def test_initial_text_not_sent_to_returning_sender(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            initial_text="Welcome!"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            # First message
            client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "First"
            })

            mock_post.reset_mock()

            # Second message from same sender
            client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "Second"
            })

            # Should NOT have sent initial_text again
            assert not mock_post.called
            assert received[1]['metadata']['is_new_sender'] is False

    def test_initial_text_sent_again_after_clear(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            initial_text="Welcome!"
        )
        client = TestClient(provider.app)

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            # First message
            client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "Hello"
            })

            # Clear thread via /clear command
            client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "/clear"
            })

            mock_post.reset_mock()

            # Message after clear - should get initial_text again
            client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "Hello again"
            })

            assert mock_post.called
            payload = mock_post.call_args[1]['json']
            assert payload['content'] == "Welcome!"

    def test_no_initial_text_when_not_configured(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
            # No initial_text
        )
        client = TestClient(provider.app)

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "Hello"
            })

            # Should NOT have sent any message
            assert not mock_post.called

    def test_default_help_text_constant(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        assert provider.help_text == HttpSmsMessageProvider.DEFAULT_HELP_TEXT
        assert "/help" in provider.help_text
        assert "/clear" in provider.help_text


class TestHttpSmsThreadClear:
    """Tests for thread clear functionality."""

    def test_register_thread_clear_listener(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        cleared = []
        provider.register_thread_clear_listener(lambda c, m: cleared.append((c, m)))

        assert len(provider.thread_clear_listeners) == 1

    def test_register_thread_clear_listener_not_callable(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        with pytest.raises(ValueError, match="callable"):
            provider.register_thread_clear_listener("not a function")

    def test_clear_thread_notifies_listeners(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        cleared = []
        provider.register_thread_clear_listener(lambda c, m: cleared.append((c, m)))

        result = provider.clear_thread("+15559876543")

        assert result['success'] is True
        assert result['channel'] == "+15559876543"
        assert len(cleared) == 1
        assert cleared[0][0] == "+15559876543"
        assert cleared[0][1] == {}

    def test_clear_thread_with_metadata(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        cleared = []
        provider.register_thread_clear_listener(lambda c, m: cleared.append((c, m)))

        result = provider.clear_thread(
            "+15559876543",
            metadata={"reason": "user_ended", "summary": "Conversation complete"}
        )

        assert result['success'] is True
        assert cleared[0][1]['reason'] == "user_ended"
        assert cleared[0][1]['summary'] == "Conversation complete"

    def test_clear_thread_requires_channel(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        result = provider.clear_thread("")

        assert result['success'] is False
        assert "channel" in result['error']

    def test_clear_thread_multiple_listeners(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        results1 = []
        results2 = []
        provider.register_thread_clear_listener(lambda c, m: results1.append(c))
        provider.register_thread_clear_listener(lambda c, m: results2.append(c))

        provider.clear_thread("+15559876543")

        assert len(results1) == 1
        assert len(results2) == 1

    def test_clear_thread_listener_error_does_not_break_others(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        results = []

        def failing_listener(c, m):
            raise Exception("Listener failed!")

        def working_listener(c, m):
            results.append(c)

        provider.register_thread_clear_listener(failing_listener)
        provider.register_thread_clear_listener(working_listener)

        result = provider.clear_thread("+15559876543")

        assert result['success'] is True
        assert len(results) == 1


class TestHttpSmsSendMessage:
    """Tests for sending messages via httpSMS API."""

    def test_send_message_requires_channel(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        result = provider.send_message("Hello", "bot", channel=None)
        assert result['success'] is False
        assert "channel" in result['error']

    def test_send_message_success(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {
                "data": {"id": "msg123"},
                "status": "success"
            }

            result = provider.send_message("Hello!", "bot", channel="+15559876543")

            assert result['success'] is True
            assert result['message_id'] == "msg123"
            assert result['channel'] == "+15559876543"

    def test_send_message_correct_api_call(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider, HTTPSMS_API_URL

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            provider.send_message("Hello!", "bot", channel="+15559876543")

            mock_post.assert_called_once()
            call_args = mock_post.call_args

            # Verify URL
            assert call_args[0][0] == HTTPSMS_API_URL

            # Verify headers
            headers = call_args[1]['headers']
            assert headers['x-api-key'] == "test-key"
            assert headers['Content-Type'] == "application/json"

            # Verify payload
            payload = call_args[1]['json']
            assert payload['content'] == "Hello!"
            assert payload['from'] == "+15551234567"
            assert payload['to'] == "+15559876543"

    def test_send_message_generates_timestamp_id_without_api_id(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"status": "success"}  # No ID

            result = provider.send_message("Hello!", "bot", channel="+15559876543")

            assert result['success'] is True
            assert result['message_id'].startswith("sms_")

    def test_send_message_api_error(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider
        import requests

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.side_effect = requests.exceptions.RequestException("API Error")

            result = provider.send_message("Hello!", "bot", channel="+15559876543")

            assert result['success'] is False
            assert "API Error" in result['error']
            assert result['channel'] == "+15559876543"

    def test_send_message_timeout(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider
        import requests

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

            result = provider.send_message("Hello!", "bot", channel="+15559876543")

            assert result['success'] is False
            assert "timed out" in result['error'].lower()

    def test_send_message_http_error(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider
        import requests

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_response = Mock()
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("401 Unauthorized")
            mock_post.return_value = mock_response

            result = provider.send_message("Hello!", "bot", channel="+15559876543")

            assert result['success'] is False
            assert "401" in result['error'] or "Unauthorized" in result['error']


class TestHttpSmsReactionAndUpdate:
    """Tests for reaction and update message methods."""

    def test_send_reaction_sends_text(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            provider.send_reaction("msg123", "thumbsup", channel="+15559876543")

            payload = mock_post.call_args[1]['json']
            assert "[thumbsup]" in payload['content']

    def test_send_reaction_requires_channel(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        result = provider.send_reaction("msg123", "thumbsup", channel=None)
        assert result['success'] is False
        assert "channel" in result['error']

    def test_update_message_sends_text(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            provider.update_message("msg123", "New text", channel="+15559876543")

            payload = mock_post.call_args[1]['json']
            assert "[Update]" in payload['content']
            assert "New text" in payload['content']

    def test_update_message_requires_channel(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        result = provider.update_message("msg123", "New text", channel=None)
        assert result['success'] is False
        assert "channel" in result['error']


class TestHttpSmsHealthAndMisc:
    """Tests for health check and miscellaneous methods."""

    def test_health_check(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            client_id="httpsms:test"
        )
        client = TestClient(provider.app)

        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == "healthy"
        assert data['client_id'] == "httpsms:test"
        assert "timestamp" in data

    def test_get_formatting_rules(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        assert provider.get_formatting_rules() == "plaintext"

    def test_get_app(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider
        from fastapi import FastAPI

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        assert isinstance(provider.get_app(), FastAPI)

    def test_request_status_update_not_supported(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        result = provider.request_status_update("req123")
        assert result['success'] is False
        assert "Not supported" in result['error']

    def test_request_cancellation_not_supported(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        result = provider.request_cancellation("req123")
        assert result['success'] is False
        assert "Not supported" in result['error']

    def test_register_reaction_listener_noop(self):
        """Test that register_reaction_listener is a no-op for SMS."""
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        # Should not raise, just silently ignore
        provider.register_reaction_listener(lambda r: None)

        # httpSMS doesn't store reaction listeners (no-op)
        assert not hasattr(provider, 'reaction_listeners') or len(getattr(provider, 'reaction_listeners', [])) == 0

    def test_default_thread_id_constant(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )

        assert provider.DEFAULT_THREAD_ID == "sms_default"


class TestHttpSmsConcurrency:
    """Tests for concurrent message handling."""

    def test_concurrent_webhook_messages(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        lock = threading.Lock()

        def listener(m):
            with lock:
                received.append(m)

        provider.register_message_listener(listener)

        # Send multiple messages concurrently
        threads = []
        for i in range(10):
            def send_message(idx=i):
                client.post("/webhook", json={
                    "sender": f"+1555000000{idx}",
                    "recipient": "+15551234567",
                    "content": f"Message {idx}"
                })
            t = threading.Thread(target=send_message)
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(received) == 10

    def test_rapid_fire_messages(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        # Send 50 messages in rapid succession
        for i in range(50):
            response = client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": f"Rapid message {i}"
            })
            assert response.status_code == 200

        assert len(received) == 50

    def test_multiple_senders_isolation(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        # Messages from different senders
        senders = ["+15551111111", "+15552222222", "+15553333333"]
        for sender in senders:
            for i in range(3):
                client.post("/webhook", json={
                    "sender": sender,
                    "recipient": "+15551234567",
                    "content": f"From {sender[-4:]}: Message {i}"
                })

        assert len(received) == 9

        # Verify each sender's messages are attributed correctly
        for sender in senders:
            sender_messages = [m for m in received if m['user_id'] == sender]
            assert len(sender_messages) == 3
            for m in sender_messages:
                assert m['channel'] == sender


class TestHttpSmsIntegration:
    """Integration tests with real HTTP server."""

    def test_full_conversation_flow(self):
        """Test a complete conversation: initial text, messages, help, clear."""
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            initial_text="Welcome! Type /help for commands.",
            help_text="Available commands: /help, /clear"
        )
        client = TestClient(provider.app)

        messages_received = []
        threads_cleared = []

        provider.register_message_listener(lambda m: messages_received.append(m))
        provider.register_thread_clear_listener(lambda c, m: threads_cleared.append((c, m)))

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            # Step 1: First message from new user - should send initial text
            response = client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "Hello!"
            })
            assert response.status_code == 200
            assert len(messages_received) == 1
            assert messages_received[0]['text'] == "Hello!"
            assert messages_received[0]['metadata']['is_new_sender'] is True

            # Verify initial text was sent
            assert mock_post.called
            initial_call = mock_post.call_args_list[0]
            assert initial_call[1]['json']['content'] == "Welcome! Type /help for commands."

            mock_post.reset_mock()

            # Step 2: Second message - no initial text
            response = client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "How are you?"
            })
            assert len(messages_received) == 2
            assert messages_received[1]['metadata']['is_new_sender'] is False
            assert not mock_post.called  # No initial text sent

            # Step 3: User requests help
            response = client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "/help"
            })
            assert response.json()["action"] == "help"
            assert len(messages_received) == 2  # /help not forwarded
            assert mock_post.called
            help_call = mock_post.call_args
            assert help_call[1]['json']['content'] == "Available commands: /help, /clear"

            mock_post.reset_mock()

            # Step 4: User clears thread
            response = client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "/clear"
            })
            assert response.json()["action"] == "clear"
            assert len(threads_cleared) == 1
            assert threads_cleared[0][0] == "+15559876543"
            assert threads_cleared[0][1]["reason"] == "user_cleared"

            # Step 5: New message after clear - should get initial text again
            response = client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "I'm back!"
            })
            assert len(messages_received) == 3
            assert messages_received[2]['metadata']['is_new_sender'] is True
            assert mock_post.called
            welcome_back_call = mock_post.call_args
            assert welcome_back_call[1]['json']['content'] == "Welcome! Type /help for commands."

    def test_multiple_users_isolation(self):
        """Test that multiple users are isolated properly."""
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            initial_text="Welcome!"
        )
        client = TestClient(provider.app)

        messages = []
        clears = []

        provider.register_message_listener(lambda m: messages.append(m))
        provider.register_thread_clear_listener(lambda c, m: clears.append(c))

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            # User 1 first message
            client.post("/webhook", json={
                "sender": "+15551111111",
                "recipient": "+15551234567",
                "content": "User 1 here"
            })

            # User 2 first message
            client.post("/webhook", json={
                "sender": "+15552222222",
                "recipient": "+15551234567",
                "content": "User 2 here"
            })

            # Both should have received initial text
            assert mock_post.call_count == 2

            mock_post.reset_mock()

            # User 1 clears
            client.post("/webhook", json={
                "sender": "+15551111111",
                "recipient": "+15551234567",
                "content": "/clear"
            })

            assert len(clears) == 1
            assert clears[0] == "+15551111111"

            # User 2 messages again - no initial text (not cleared)
            client.post("/webhook", json={
                "sender": "+15552222222",
                "recipient": "+15551234567",
                "content": "User 2 again"
            })
            assert not mock_post.called

            # User 1 messages again - should get initial text (was cleared)
            client.post("/webhook", json={
                "sender": "+15551111111",
                "recipient": "+15551234567",
                "content": "User 1 back"
            })
            assert mock_post.called

    def test_send_and_receive_round_trip(self):
        """Test sending a reply back to a user."""
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        def message_handler(message):
            # Echo the message back
            provider.send_message(
                f"Echo: {message['text']}",
                "bot",
                channel=message['channel']
            )

        provider.register_message_listener(message_handler)

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            response = client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "Hello!"
            })

            assert response.status_code == 200
            assert mock_post.called
            payload = mock_post.call_args[1]['json']
            assert payload['content'] == "Echo: Hello!"
            assert payload['to'] == "+15559876543"
            assert payload['from'] == "+15551234567"

    def test_authentication_flow(self):
        """Test authentication callback is called correctly."""
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        auth_log = []

        def authenticator(sender, recipient, content, metadata):
            auth_log.append({
                "sender": sender,
                "recipient": recipient,
                "content": content,
                "metadata": metadata
            })
            # Allow only specific prefix
            if content.lower().startswith("secret:"):
                return {"allowed": True}
            return {"allowed": False, "reason": "Missing secret prefix"}

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            message_authenticator=authenticator
        )
        client = TestClient(provider.app)

        messages = []
        provider.register_message_listener(lambda m: messages.append(m))

        # Message without secret - rejected
        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": "Hello!"
        })
        assert response.status_code == 403
        assert len(messages) == 0
        assert len(auth_log) == 1

        # Message with secret - accepted
        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": "secret: Hello!"
        })
        assert response.status_code == 200
        assert len(messages) == 1
        assert len(auth_log) == 2

    def test_programmatic_clear_thread(self):
        """Test clearing thread programmatically (not via /clear command)."""
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            initial_text="Welcome!"
        )
        client = TestClient(provider.app)

        clears = []
        provider.register_thread_clear_listener(lambda c, m: clears.append((c, m)))

        with patch('message_provider.httpsms_message_provider.requests.post') as mock_post:
            mock_post.return_value.raise_for_status = Mock()
            mock_post.return_value.json.return_value = {"data": {"id": "msg123"}}

            # First message
            client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "Hello"
            })
            assert mock_post.called  # Initial text sent
            mock_post.reset_mock()

            # Programmatic clear with custom metadata
            result = provider.clear_thread(
                "+15559876543",
                metadata={"reason": "task_complete", "tokens_used": 150}
            )
            assert result['success'] is True
            assert len(clears) == 1
            assert clears[0][0] == "+15559876543"
            assert clears[0][1]["reason"] == "task_complete"
            assert clears[0][1]["tokens_used"] == 150

            # Next message should trigger initial text again
            client.post("/webhook", json={
                "sender": "+15559876543",
                "recipient": "+15551234567",
                "content": "Hello again"
            })
            assert mock_post.called

    def test_health_endpoint(self):
        """Test the health check endpoint."""
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567",
            client_id="httpsms:integration-test"
        )
        client = TestClient(provider.app)

        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["client_id"] == "httpsms:integration-test"
        assert "timestamp" in data


class TestHttpSmsEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_message_content(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": ""
        })

        assert response.status_code == 200
        assert len(received) == 1
        assert received[0]['text'] == ""

    def test_very_long_message(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        long_content = "A" * 10000

        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": long_content
        })

        assert response.status_code == 200
        assert len(received) == 1
        assert received[0]['text'] == long_content

    def test_unicode_message(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        unicode_content = "Hello! \U0001F600 \u4E2D\u6587 \u0420\u0443\u0441\u0441\u043A\u0438\u0439"

        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": unicode_content
        })

        assert response.status_code == 200
        assert received[0]['text'] == unicode_content

    def test_special_characters_in_message(self):
        from message_provider.httpsms_message_provider import HttpSmsMessageProvider

        provider = HttpSmsMessageProvider(
            api_key="test-key",
            phone_number="+15551234567"
        )
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        special_content = "Test with special chars: <>&\"'\\n\\t{}[]|"

        response = client.post("/webhook", json={
            "sender": "+15559876543",
            "recipient": "+15551234567",
            "content": special_content
        })

        assert response.status_code == 200
        assert received[0]['text'] == special_content
