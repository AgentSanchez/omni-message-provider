"""Tests for DiscordMessageProvider."""

import pytest
from unittest.mock import Mock, AsyncMock, MagicMock, patch
import discord


@pytest.fixture
def mock_discord_intents():
    """Fixture for Discord intents."""
    intents = discord.Intents.default()
    intents.message_content = True
    return intents


@pytest.mark.asyncio
class TestDiscordMessageProvider:
    """Test cases for DiscordMessageProvider."""

    def test_init_requires_bot_token(self):
        """Test that bot_token is required."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        with pytest.raises(ValueError, match="bot_token is required"):
            DiscordMessageProvider(
                bot_token="",
                client_id="discord:test"
            )

    def test_init_requires_client_id(self):
        """Test that client_id is required."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        with pytest.raises(ValueError, match="client_id is required"):
            DiscordMessageProvider(
                bot_token="test_token",
                client_id=""
            )

    def test_init_success(self, mock_discord_intents):
        """Test successful initialization."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        provider = DiscordMessageProvider(
            bot_token="test_token",
            client_id="discord:test",
            intents=mock_discord_intents
        )

        assert provider.bot_token == "test_token"
        assert provider.client_id == "discord:test"
        assert provider.bot is not None
        assert len(provider.message_listeners) == 0

    def test_register_message_listener(self, mock_discord_intents):
        """Test registering a message listener."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        provider = DiscordMessageProvider(
            bot_token="test_token",
            client_id="discord:test",
            intents=mock_discord_intents
        )

        def handler(message):
            pass

        provider.register_message_listener(handler)
        assert len(provider.message_listeners) == 1

    def test_register_message_listener_not_callable(self, mock_discord_intents):
        """Test that non-callable listener raises error."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        provider = DiscordMessageProvider(
            bot_token="test_token",
            client_id="discord:test",
            intents=mock_discord_intents
        )

        with pytest.raises(ValueError, match="Callback must be a callable"):
            provider.register_message_listener("not_a_function")

    @pytest.mark.asyncio
    async def test_send_message_async(self, mock_discord_intents):
        """Test async message sending."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        provider = DiscordMessageProvider(
            bot_token="test_token",
            client_id="discord:test",
            intents=mock_discord_intents
        )

        # Mock the Discord channel
        mock_channel = AsyncMock()
        mock_sent_message = MagicMock()
        mock_sent_message.id = 123456789
        mock_sent_message.channel.id = 987654321
        mock_channel.send = AsyncMock(return_value=mock_sent_message)

        provider._get_channel = AsyncMock(return_value=mock_channel)

        result = await provider._send_message_async(
            message="Test message",
            user_id="123",
            channel="987654321"
        )

        assert result['success'] is True
        assert result['message_id'] == '123456789'
        mock_channel.send.assert_called_once_with("Test message")

    @pytest.mark.asyncio
    async def test_on_message_sets_is_mention(self, mock_discord_intents):
        """Test that is_mention is set when bot is mentioned."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        provider = DiscordMessageProvider(
            bot_token="test_token",
            client_id="discord:test",
            intents=mock_discord_intents
        )

        bot_user = MagicMock()
        provider.bot._connection.user = bot_user
        provider.bot.process_commands = AsyncMock()

        mock_author = MagicMock()
        mock_author.bot = False
        mock_author.id = 123
        mock_author.discriminator = "0001"
        mock_author.__str__.return_value = "User#0001"

        mock_channel = MagicMock()
        mock_channel.id = 456
        mock_channel.name = "general"

        mock_guild = MagicMock()
        mock_guild.id = 789
        mock_guild.name = "Test Guild"

        mock_message = MagicMock()
        mock_message.author = mock_author
        mock_message.content = "hello"
        mock_message.channel = mock_channel
        mock_message.id = 999
        mock_message.guild = mock_guild
        mock_message.reference = None
        mock_message.mentions = [bot_user]

        provider._notify_listeners = Mock()

        await provider.bot.on_message(mock_message)

        provider._notify_listeners.assert_called_once()
        message_data = provider._notify_listeners.call_args[0][0]
        assert message_data["metadata"]["is_mention"] is True
