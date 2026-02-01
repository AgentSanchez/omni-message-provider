#!/usr/bin/env python3
"""
Example usage of DiscordMessageProvider.

Setup Instructions:
1. Create a Discord Application at https://discord.com/developers/applications
2. Go to the "Bot" section and create a bot
3. Enable these Privileged Gateway Intents:
   - MESSAGE CONTENT INTENT (required to read message content)
   - SERVER MEMBERS INTENT (optional, for member info)
   - PRESENCE INTENT (optional, for user status)

4. Get your bot token from the Bot section
5. Invite bot to your server:
   - Go to OAuth2 > URL Generator
   - Select scopes: "bot"
   - Select bot permissions:
     * Read Messages/View Channels
     * Send Messages
     * Add Reactions
     * Read Message History
   - Copy the generated URL and open it in browser to invite the bot

6. Set environment variables:
   export DISCORD_BOT_TOKEN="your-bot-token-here"
   export DISCORD_TRIGGER_MODE="both"  # "mention", "chat", "command", "both"
   export DISCORD_COMMAND_PREFIXES="!support,!cq"  # Optional, used when trigger_mode="command"

Usage:
    python -m message_provider.discord_example
"""

import os
import discord
from message_provider.discord_message_provider import DiscordMessageProvider
from logzero import logger as log


def create_message_handler(provider):
    """
    Create a message handler with access to the provider instance.

    Args:
        provider: DiscordMessageProvider instance

    Returns:
        Callable message handler function
    """
    def message_handler(message):
        """
        Handle incoming messages from Discord.

        Args:
            message: Dictionary containing:
                - message_id: Discord message ID
                - text: Message text
                - user_id: Discord user ID
                - channel: Discord channel ID
                - metadata: Additional Discord-specific data
        """
        log.info(f"Received message from {message['user_id']}: {message['text']}")

        # Extract message data
        user_id = message.get('user_id')
        channel = message.get('channel')
        text = message.get('text', '')
        message_id = message.get('message_id')
        author_name = message.get('metadata', {}).get('author_name', 'unknown')

        # Example: Respond to messages containing "ping"
        if 'ping' in text.lower():
            result = provider.send_message(
                message=f"Pong, {author_name}! 🏓",
                user_id=user_id,
                channel=channel,
                previous_message_id=message_id  # This will reply to the message
            )

            if result.get('success'):
                sent_message_id = result['message_id']

                # Add a reaction to the original message
                provider.send_reaction(message_id, "👋")

        # Example: Respond to messages containing "hello"
        elif 'hello' in text.lower():
            result = provider.send_message(
                message=f"Hello, {author_name}! How can I help you?",
                user_id=user_id,
                channel=channel,
                previous_message_id=message_id
            )

            if result.get('success'):
                # Add a wave reaction
                provider.send_reaction(message_id, "👋")

        # Example: Respond to "update test"
        elif 'update test' in text.lower():
            result = provider.send_message(
                message="This message will be updated...",
                user_id=user_id,
                channel=channel
            )

            if result.get('success'):
                sent_message_id = result['message_id']

                # Update the message after a short delay
                import time
                time.sleep(2)
                provider.update_message(sent_message_id, "Message updated! ✅")

    return message_handler


def main():
    """Main function to run the Discord bot."""
    try:
        # Load configuration from environment variables
        bot_token = os.getenv("DISCORD_BOT_TOKEN")

        # Validate required configuration
        if not bot_token:
            log.error("DISCORD_BOT_TOKEN environment variable is required")
            log.error("\nTo get a bot token:")
            log.error("1. Go to https://discord.com/developers/applications")
            log.error("2. Create a new application or select an existing one")
            log.error("3. Go to the 'Bot' section")
            log.error("4. Click 'Reset Token' to get your bot token")
            log.error("5. Enable 'MESSAGE CONTENT INTENT' under Privileged Gateway Intents")
            return 1

        # Configure Discord intents
        intents = discord.Intents.default()
        intents.message_content = True  # Required to read message content
        intents.guilds = True
        intents.messages = True

        trigger_mode = os.getenv("DISCORD_TRIGGER_MODE", "both")
        command_prefixes_raw = os.getenv("DISCORD_COMMAND_PREFIXES", "")
        command_prefixes = [p.strip() for p in command_prefixes_raw.split(",") if p.strip()]

        # Initialize Discord message provider
        provider = DiscordMessageProvider(
            bot_token=bot_token,
            command_prefix="!",
            intents=intents,
            client_id="discord-test",
            trigger_mode=trigger_mode,
            command_prefixes=command_prefixes or None
        )

        # Register message handler
        handler = create_message_handler(provider)
        provider.register_message_listener(handler)

        log.info("Discord bot is starting...")
        log.info("Try sending 'ping' or 'hello' in a channel where the bot is present!")
        log.info("Try sending 'update test' to see message editing in action!")

        # Start the provider (blocking)
        provider.start()

    except ValueError as e:
        log.error(f"Configuration error: {e}")
        return 1
    except discord.LoginFailure:
        log.error("Invalid bot token. Please check your DISCORD_BOT_TOKEN")
        return 1
    except KeyboardInterrupt:
        log.info("Shutting down...")
        return 0


if __name__ == "__main__":
    exit(main())
