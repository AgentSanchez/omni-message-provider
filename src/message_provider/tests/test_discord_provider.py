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
        mock_channel.send.assert_called_once_with("Test message", reference=None)

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

    def test_register_reaction_listener(self, mock_discord_intents):
        """Test registering a reaction listener."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        provider = DiscordMessageProvider(
            bot_token="test_token",
            client_id="discord:test",
            intents=mock_discord_intents
        )

        def handler(reaction):
            pass

        provider.register_reaction_listener(handler)
        assert len(provider.reaction_listeners) == 1

    def test_register_reaction_listener_not_callable(self, mock_discord_intents):
        """Test that non-callable reaction listener raises error."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        provider = DiscordMessageProvider(
            bot_token="test_token",
            client_id="discord:test",
            intents=mock_discord_intents
        )

        with pytest.raises(ValueError, match="Callback must be a callable"):
            provider.register_reaction_listener("not_a_function")

    def test_notify_reaction_listeners(self, mock_discord_intents):
        """Test that reaction listeners are notified with correct data."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        provider = DiscordMessageProvider(
            bot_token="test_token",
            client_id="discord:test",
            intents=mock_discord_intents
        )

        received_reactions = []
        provider.register_reaction_listener(lambda r: received_reactions.append(r))

        # Mock bot.loop as not running so _call_listener is called directly
        provider.bot.loop = None

        reaction_data = {
            "message_id": "123",
            "reaction": "👍",
            "user_id": "456",
            "channel": "789",
            "metadata": {"client_id": "discord:test"}
        }

        provider._notify_reaction_listeners(reaction_data)

        assert len(received_reactions) == 1
        assert received_reactions[0]["reaction"] == "👍"
        assert received_reactions[0]["message_id"] == "123"
        assert received_reactions[0]["user_id"] == "456"
        assert received_reactions[0]["channel"] == "789"

    def test_reaction_listener_error_does_not_break_others(self, mock_discord_intents):
        """Test that a failing reaction listener doesn't prevent other listeners from being called."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        provider = DiscordMessageProvider(
            bot_token="test_token",
            client_id="discord:test",
            intents=mock_discord_intents
        )

        results = []

        def failing_listener(r):
            raise Exception("Listener failed!")

        def working_listener(r):
            results.append(r)

        provider.register_reaction_listener(failing_listener)
        provider.register_reaction_listener(working_listener)

        provider.bot.loop = None

        provider._notify_reaction_listeners({"reaction": "👍"})

        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_on_reaction_add_event(self, mock_discord_intents):
        """Test the on_reaction_add event handler."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        provider = DiscordMessageProvider(
            bot_token="test_token",
            client_id="discord:test",
            intents=mock_discord_intents
        )

        bot_user = MagicMock()
        bot_user.id = 999
        provider.bot._connection.user = bot_user

        # Mock user (not a bot)
        mock_user = MagicMock()
        mock_user.bot = False
        mock_user.id = 123
        mock_user.__str__.return_value = "TestUser#0001"
        mock_user.__eq__ = lambda self, other: self.id == other.id

        # Mock message
        mock_message = MagicMock()
        mock_message.id = 456
        mock_message.channel = MagicMock()
        mock_message.channel.id = 789
        mock_message.channel.name = "general"
        mock_message.channel.__class__ = type("TextChannel", (), {})
        mock_message.guild = MagicMock()
        mock_message.guild.id = 101
        mock_message.guild.name = "Test Guild"
        mock_message.author = MagicMock()
        mock_message.author.id = 555

        # Mock reaction with string emoji
        mock_reaction = MagicMock()
        mock_reaction.emoji = "👍"
        mock_reaction.message = mock_message

        provider._notify_reaction_listeners = Mock()

        await provider.bot.on_reaction_add(mock_reaction, mock_user)

        provider._notify_reaction_listeners.assert_called_once()
        reaction_data = provider._notify_reaction_listeners.call_args[0][0]
        assert reaction_data["message_id"] == "456"
        assert reaction_data["reaction"] == "👍"
        assert reaction_data["user_id"] == "123"
        assert reaction_data["channel"] == "789"
        assert reaction_data["metadata"]["client_id"] == "discord:test"
        assert reaction_data["metadata"]["user_name"] == "TestUser#0001"

    @pytest.mark.asyncio
    async def test_on_reaction_add_ignores_bot(self, mock_discord_intents):
        """Test that bot's own reactions are ignored."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        provider = DiscordMessageProvider(
            bot_token="test_token",
            client_id="discord:test",
            intents=mock_discord_intents
        )

        bot_user = MagicMock()
        bot_user.id = 999
        provider.bot._connection.user = bot_user

        # User is the bot itself
        mock_user = MagicMock()
        mock_user.id = 999
        mock_user.__eq__ = lambda self, other: self.id == other.id

        mock_reaction = MagicMock()
        mock_reaction.emoji = "👍"

        provider._notify_reaction_listeners = Mock()

        await provider.bot.on_reaction_add(mock_reaction, mock_user)

        provider._notify_reaction_listeners.assert_not_called()

    @pytest.mark.asyncio
    async def test_on_reaction_add_ignores_other_bots(self, mock_discord_intents):
        """Test that other bots' reactions are ignored."""
        from message_provider.discord_message_provider import DiscordMessageProvider

        provider = DiscordMessageProvider(
            bot_token="test_token",
            client_id="discord:test",
            intents=mock_discord_intents
        )

        bot_user = MagicMock()
        bot_user.id = 999
        provider.bot._connection.user = bot_user

        # Another bot user
        mock_user = MagicMock()
        mock_user.bot = True
        mock_user.id = 888
        mock_user.__eq__ = lambda self, other: self.id == other.id

        mock_reaction = MagicMock()
        mock_reaction.emoji = "👍"

        provider._notify_reaction_listeners = Mock()

        await provider.bot.on_reaction_add(mock_reaction, mock_user)

        provider._notify_reaction_listeners.assert_not_called()
