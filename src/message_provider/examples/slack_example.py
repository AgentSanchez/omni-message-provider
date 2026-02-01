#!/usr/bin/env python3
"""
Example usage of SlackMessageProvider.

Setup Instructions:
1. Create a Slack App at https://api.slack.com/apps
2. Add Bot Token Scopes:
   - chat:write (send messages)
   - reactions:write (add reactions)
   - chat:update (edit messages)
   - channels:history (read channel messages)
   - groups:history (read private channel messages)
   - im:history (read DM messages)
   - mpim:history (read group DM messages)

3. Install app to workspace and get Bot User OAuth Token (starts with xoxb-)

4. For Socket Mode (recommended for development):
   - Enable Socket Mode in app settings
   - Generate App-Level Token with connections:write scope (starts with xapp-)

5. Set environment variables (you choose the names):
   export SLACK_BOT_TOKEN="xoxb-your-bot-token"
   export SLACK_APP_TOKEN="xapp-your-app-token"  # For Socket Mode
   export SLACK_SIGNING_SECRET="your-signing-secret"  # For HTTP mode
   export SLACK_TRIGGER_MODE="both"  # "mention", "chat", or "both"
   export SLACK_ALLOWED_CHANNELS="#general,#support"  # Optional, names or IDs

Usage:
    python -m message_provider.slack_example
"""

import os
from message_provider.slack_message_provider import SlackMessageProvider
from logzero import logger as log


def create_message_handler(provider):
    """
    Create a message handler with access to the provider instance.

    Args:
        provider: SlackMessageProvider instance

    Returns:
        Callable message handler function
    """
    def message_handler(message):
        """
        Handle incoming messages from Slack.

        Args:
            message: Dictionary containing:
                - message_id: Slack timestamp (ts)
                - text: Message text
                - user_id: Slack user ID
                - channel: Slack channel ID
                - metadata: Additional Slack-specific data
        """
        log.info(f"Received message from {message['user_id']}: {message['text']}")

        # Example: Echo the message back
        user_id = message.get('user_id')
        channel = message.get('channel')
        text = message.get('text', '')
        message_id = message.get('message_id')

        # Send a reply
        result = provider.send_message(
            message=f"You said: {text}",
            user_id=user_id,
            channel=channel,
            previous_message_id=message_id  # This will thread the reply
        )

        if result.get('success'):
            sent_message_id = result['message_id']

            # Add a reaction to the original message
            reaction_result = provider.send_reaction(message_id, "thumbsup")
            if not reaction_result.get("success"):
                log.warning(f"Reaction failed: {reaction_result.get('error')}")

            # Optionally update our reply after 2 seconds
            import time
            time.sleep(2)
            provider.update_message(sent_message_id, f"You said: {text} (edited)")

    return message_handler


def main():
    """Main function to run the Slack bot."""
    try:
        # Load configuration from environment variables
        # (You can use any ENV var names you want)
        bot_token = os.getenv("SLACK_BOT_TOKEN")
        app_token = os.getenv("SLACK_APP_TOKEN")
        signing_secret = os.getenv("SLACK_SIGNING_SECRET")
        use_socket_mode = os.getenv("SLACK_USE_SOCKET_MODE", "true").lower() == "true"
        trigger_mode = os.getenv("SLACK_TRIGGER_MODE", "both")
        allowed_channels_raw = os.getenv("SLACK_ALLOWED_CHANNELS", "")
        allowed_channels = [c.strip() for c in allowed_channels_raw.split(",") if c.strip()]

        # Validate required configuration
        if not bot_token:
            log.error("SLACK_BOT_TOKEN environment variable is required")
            return 1

        if use_socket_mode and not app_token:
            log.error("SLACK_APP_TOKEN environment variable is required for Socket Mode")
            log.error("Either set SLACK_APP_TOKEN or set SLACK_USE_SOCKET_MODE=false")
            return 1

        if not use_socket_mode and not signing_secret:
            log.error("SLACK_SIGNING_SECRET environment variable is required for HTTP mode")
            return 1

        # Initialize Slack message provider with explicit parameters
        provider = SlackMessageProvider(
            bot_token=bot_token,
            app_token=app_token,
            signing_secret=signing_secret,
            use_socket_mode=use_socket_mode,
            client_id="slack-example-bot",
            trigger_mode=trigger_mode,
            allowed_channels=allowed_channels or None,
        )

        # Register message handler (pass provider to handler)
        handler = create_message_handler(provider)
        provider.register_message_listener(handler)

        log.info("Slack bot is starting...")
        log.info("Send a message in Slack to test!")

        # Start the provider (blocking)
        provider.start()

    except ValueError as e:
        log.error(f"Configuration error: {e}")
        return 1
    except KeyboardInterrupt:
        log.info("Shutting down...")
        return 0


if __name__ == "__main__":
    exit(main())
