"""Tests for SlackMessageProvider."""

import pytest
from unittest.mock import Mock, MagicMock, patch


class TestSlackMessageProvider:
    """Test cases for SlackMessageProvider."""

    def test_init_requires_bot_token(self):
        """Test that bot_token is required."""
        from message_provider.slack_message_provider import SlackMessageProvider

        with pytest.raises(ValueError, match="bot_token is required"):
            SlackMessageProvider(
                bot_token="",
                client_id="slack:test"
            )

    def test_init_requires_client_id(self):
        """Test that client_id is required."""
        from message_provider.slack_message_provider import SlackMessageProvider

        with pytest.raises(ValueError, match="client_id is required"):
            SlackMessageProvider(
                bot_token="xoxb-test",
                client_id=""
            )

    def test_init_socket_mode_requires_app_token(self):
        """Test that app_token is required for Socket Mode."""
        from message_provider.slack_message_provider import SlackMessageProvider

        with pytest.raises(ValueError, match="app_token is required for Socket Mode"):
            SlackMessageProvider(
                bot_token="xoxb-test",
                client_id="slack:test",
                use_socket_mode=True
            )

    def test_init_http_mode_requires_signing_secret(self):
        """Test that signing_secret is required for HTTP mode."""
        from message_provider.slack_message_provider import SlackMessageProvider

        with pytest.raises(ValueError, match="signing_secret is required for HTTP mode"):
            SlackMessageProvider(
                bot_token="xoxb-test",
                client_id="slack:test",
                use_socket_mode=False
            )

    def test_init_socket_mode_success(self):
        """Test successful initialization in Socket Mode."""
        from message_provider.slack_message_provider import SlackMessageProvider

        provider = SlackMessageProvider(
            bot_token="xoxb-test",
            client_id="slack:test",
            app_token="xapp-test",
            use_socket_mode=True
        )

        assert provider.bot_token == "xoxb-test"
        assert provider.client_id == "slack:test"
        assert provider.app_token == "xapp-test"
        assert provider.use_socket_mode is True
        assert provider.app is not None
        assert len(provider.message_listeners) == 0

    def test_init_http_mode_success(self):
        """Test successful initialization in HTTP mode."""
        from message_provider.slack_message_provider import SlackMessageProvider

        provider = SlackMessageProvider(
            bot_token="xoxb-test",
            client_id="slack:test",
            signing_secret="secret123",
            use_socket_mode=False
        )

        assert provider.bot_token == "xoxb-test"
        assert provider.client_id == "slack:test"
        assert provider.signing_secret == "secret123"
        assert provider.use_socket_mode is False

    def test_register_message_listener(self):
        """Test registering a message listener."""
        from message_provider.slack_message_provider import SlackMessageProvider

        provider = SlackMessageProvider(
            bot_token="xoxb-test",
            client_id="slack:test",
            app_token="xapp-test"
        )

        def handler(message):
            pass

        provider.register_message_listener(handler)
        assert len(provider.message_listeners) == 1

    def test_send_message(self):
        """Test sending a message."""
        from message_provider.slack_message_provider import SlackMessageProvider

        provider = SlackMessageProvider(
            bot_token="xoxb-test",
            client_id="slack:test",
            app_token="xapp-test"
        )

        # Mock the Slack client
        mock_response = {
            'ok': True,
            'ts': '1234567890.123456',
            'channel': 'C123456'
        }
        provider.app.client.chat_postMessage = Mock(return_value=mock_response)

        result = provider.send_message(
            message="Test message",
            user_id="U123456",
            channel="C123456"
        )

        assert result['success'] is True
        assert result['message_id'] == '1234567890.123456'
        assert result['channel'] == 'C123456'

    def test_send_reaction(self):
        """Test adding a reaction."""
        from message_provider.slack_message_provider import SlackMessageProvider

        provider = SlackMessageProvider(
            bot_token="xoxb-test",
            client_id="slack:test",
            app_token="xapp-test"
        )

        # Mock the Slack client
        provider.app.client.reactions_add = Mock(return_value={'ok': True})

        result = provider.send_reaction(
            message_id='1234567890.123456',
            reaction='thumbsup',
            channel='C123456'
        )

        assert result['success'] is True
        assert result['reaction'] == 'thumbsup'

    def test_register_reaction_listener(self):
        """Test registering a reaction listener."""
        from message_provider.slack_message_provider import SlackMessageProvider

        provider = SlackMessageProvider(
            bot_token="xoxb-test",
            client_id="slack:test",
            app_token="xapp-test"
        )

        def handler(reaction):
            pass

        provider.register_reaction_listener(handler)
        assert len(provider.reaction_listeners) == 1

    def test_register_reaction_listener_not_callable(self):
        """Test that non-callable reaction listener raises error."""
        from message_provider.slack_message_provider import SlackMessageProvider

        provider = SlackMessageProvider(
            bot_token="xoxb-test",
            client_id="slack:test",
            app_token="xapp-test"
        )

        with pytest.raises(ValueError, match="Callback must be a callable"):
            provider.register_reaction_listener("not_a_function")

    def test_notify_reaction_listeners(self):
        """Test that reaction listeners are notified with correct data."""
        from message_provider.slack_message_provider import SlackMessageProvider

        provider = SlackMessageProvider(
            bot_token="xoxb-test",
            client_id="slack:test",
            app_token="xapp-test"
        )

        received_reactions = []
        provider.register_reaction_listener(lambda r: received_reactions.append(r))

        reaction_data = {
            "message_id": "1234567890.123456",
            "reaction": "thumbsup",
            "user_id": "U123456",
            "channel": "C123456",
            "metadata": {"client_id": "slack:test"}
        }

        provider._notify_reaction_listeners(reaction_data)

        assert len(received_reactions) == 1
        assert received_reactions[0]["reaction"] == "thumbsup"
        assert received_reactions[0]["message_id"] == "1234567890.123456"
        assert received_reactions[0]["user_id"] == "U123456"
        assert received_reactions[0]["channel"] == "C123456"

    def test_reaction_listener_error_does_not_break_others(self):
        """Test that a failing reaction listener doesn't prevent other listeners."""
        from message_provider.slack_message_provider import SlackMessageProvider

        provider = SlackMessageProvider(
            bot_token="xoxb-test",
            client_id="slack:test",
            app_token="xapp-test"
        )

        results = []

        def failing_listener(r):
            raise Exception("Listener failed!")

        def working_listener(r):
            results.append(r)

        provider.register_reaction_listener(failing_listener)
        provider.register_reaction_listener(working_listener)

        provider._notify_reaction_listeners({"reaction": "thumbsup"})

        assert len(results) == 1

    def test_notify_reaction_listeners_with_full_data(self):
        """Test that _notify_reaction_listeners dispatches complete reaction data."""
        from message_provider.slack_message_provider import SlackMessageProvider

        provider = SlackMessageProvider(
            bot_token="xoxb-test",
            client_id="slack:test",
            app_token="xapp-test"
        )

        received_reactions = []
        provider.register_reaction_listener(lambda r: received_reactions.append(r))

        reaction_data = {
            "message_id": "1234567890.123456",
            "reaction": "thumbsup",
            "user_id": "U123456",
            "channel": "C123456",
            "metadata": {
                "client_id": "slack:test",
                "user_email": "user@example.com",
                "event_ts": "1234567891.000000",
            }
        }

        provider._notify_reaction_listeners(reaction_data)

        assert len(received_reactions) == 1
        assert received_reactions[0]["reaction"] == "thumbsup"
        assert received_reactions[0]["message_id"] == "1234567890.123456"
        assert received_reactions[0]["user_id"] == "U123456"
        assert received_reactions[0]["channel"] == "C123456"
        assert received_reactions[0]["metadata"]["user_email"] == "user@example.com"
        assert received_reactions[0]["metadata"]["client_id"] == "slack:test"

    def test_multiple_reaction_listeners(self):
        """Test registering and notifying multiple reaction listeners."""
        from message_provider.slack_message_provider import SlackMessageProvider

        provider = SlackMessageProvider(
            bot_token="xoxb-test",
            client_id="slack:test",
            app_token="xapp-test"
        )

        results1 = []
        results2 = []

        provider.register_reaction_listener(lambda r: results1.append(r))
        provider.register_reaction_listener(lambda r: results2.append(r))

        assert len(provider.reaction_listeners) == 2

        provider._notify_reaction_listeners({"reaction": "heart"})

        assert len(results1) == 1
        assert len(results2) == 1
        assert results1[0]["reaction"] == "heart"
