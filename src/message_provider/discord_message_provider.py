from typing import Optional, Callable, Dict, Any, Union, List
import logging
import asyncio
from message_provider.message_provider import MessageProvider

log = logging.getLogger(__name__)

try:
    import discord
    from discord.ext import commands
    _DISCORD_AVAILABLE = True
except ImportError:
    discord = None
    commands = None
    _DISCORD_AVAILABLE = False


class DiscordMessageProvider(MessageProvider):
    """
    Discord implementation of MessageProvider using discord.py.

    Args:
        bot_token: Discord bot token (required)
        client_id: Unique identifier for this instance (e.g., "discord:guild-123456").
                   Required for distributed relay routing to maintain consistency across restarts.
        command_prefix: Bot command prefix. Default: "!"
        intents: Discord intents. If None, uses default intents with message_content enabled

    Usage:
        import os
        import discord

        # Configure intents
        intents = discord.Intents.default()
        intents.message_content = True

        provider = DiscordMessageProvider(
            bot_token=os.getenv("DISCORD_BOT_TOKEN"),
            client_id="discord:my-bot",  # Stable identifier
            intents=intents
        )
        provider.register_message_listener(my_handler)
        provider.start()
    """

    def __init__(
        self,
        bot_token: str,
        client_id: str,
        command_prefix: str = "!",
        intents: Optional[Any] = None,  # discord.Intents when available
        trigger_mode: str = "both",
        command_prefixes: Optional[List[str]] = None
    ):
        super().__init__()

        if not _DISCORD_AVAILABLE:
            raise ImportError(
                "discord.py library is required for DiscordMessageProvider. "
                "Install with: pip install omni-message-provider[discord]"
            )

        if not bot_token:
            raise ValueError("bot_token is required")
        if not client_id:
            raise ValueError("client_id is required for distributed relay routing")

        self.bot_token = bot_token
        self.client_id = client_id
        self.trigger_mode = trigger_mode.lower().strip()
        if self.trigger_mode not in {"mention", "chat", "command", "both"}:
            raise ValueError("trigger_mode must be one of: 'mention', 'chat', 'command', 'both'")
        self.command_prefixes = command_prefixes if command_prefixes else [command_prefix]

        # Setup intents
        if intents is None:
            intents = discord.Intents.default()
            intents.message_content = True

        # Create bot instance
        self.bot = commands.Bot(command_prefix=command_prefix, intents=intents)

        # Message listeners
        self.message_listeners = []

        # Cache for message objects (needed for reactions/updates)
        self.message_cache: Dict[str, discord.Message] = {}

        # Setup event handlers
        self._setup_handlers()

        log.info(f"[DiscordMessageProvider] Initialized with client_id: {client_id}")

    def _setup_handlers(self):
        """Setup Discord event handlers."""

        @self.bot.event
        async def on_ready():
            """Called when the bot is ready."""
            log.info(f"[DiscordMessageProvider] Bot logged in as {self.bot.user}")

        @self.bot.event
        async def on_message(message: discord.Message):
            """Handle incoming Discord messages."""
            # Ignore bot's own messages
            if message.author == self.bot.user:
                return

            # Ignore other bots (optional - can be configured)
            if message.author.bot:
                return

            # Filter by trigger mode
            if self.trigger_mode == "mention":
                if not message.mentions or self.bot.user not in message.mentions:
                    await self.bot.process_commands(message)
                    return
            elif self.trigger_mode == "command":
                if not any(message.content.startswith(prefix) for prefix in self.command_prefixes):
                    await self.bot.process_commands(message)
                    return
            elif self.trigger_mode == "chat":
                pass

            # Extract message data
            user_id = str(message.author.id)
            text = message.content
            channel_id = str(message.channel.id)
            message_id = str(message.id)

            # Determine if this is in a thread
            is_thread = isinstance(message.channel, discord.Thread)
            thread_id = str(message.channel.id) if is_thread else None

            # Build message data compatible with MessageProvider interface
            message_data = {
                "message_id": message_id,
                "text": text,
                "user_id": user_id,
                "channel": channel_id,
                "metadata": {
                    "client_id": self.client_id,
                    "author_name": str(message.author),
                    "author_discriminator": message.author.discriminator,
                    "guild_id": str(message.guild.id) if message.guild else None,
                    "guild_name": message.guild.name if message.guild else None,
                    "channel_name": message.channel.name if hasattr(message.channel, 'name') else None,
                    "is_thread": is_thread,
                    "thread_id": thread_id,
                    "reference_message_id": str(message.reference.message_id) if message.reference else None,
                    "is_mention": bool(message.mentions and self.bot.user in message.mentions),
                }
            }

            # Cache the message object for later use
            self.message_cache[message_id] = message

            log.info(f"[DiscordMessageProvider] Received message from {user_id} in {channel_id}: {text}")

            # Notify all registered listeners
            self._notify_listeners(message_data)

            # Process bot commands
            await self.bot.process_commands(message)

    def _call_listener(self, listener: Callable, message_data: dict):
        try:
            listener(message_data)
        except Exception as e:
            log.error(f"[DiscordMessageProvider] Listener error: {str(e)}")

    def _notify_listeners(self, message_data: dict):
        """Notify all registered message listeners without blocking the event loop."""
        loop = self.bot.loop
        for listener in self.message_listeners:
            try:
                if loop and loop.is_running():
                    loop.run_in_executor(None, self._call_listener, listener, message_data)
                else:
                    self._call_listener(listener, message_data)
            except Exception as e:
                log.error(f"[DiscordMessageProvider] Listener dispatch error: {str(e)}")

    async def _get_channel(self, channel_id: Union[str, int]) -> Optional[discord.TextChannel]:
        """Get a Discord channel by ID."""
        try:
            channel = self.bot.get_channel(int(channel_id))
            if channel is None:
                channel = await self.bot.fetch_channel(int(channel_id))
            return channel
        except Exception as e:
            log.error(f"[DiscordMessageProvider] Failed to get channel {channel_id}: {str(e)}")
            return None

    async def _send_message_async(
        self,
        message: str,
        user_id: str,
        channel: Optional[str] = None,
        previous_message_id: Optional[str] = None
    ) -> dict:
        """Internal async method to send messages."""
        try:
            # Determine target channel
            target_channel_id = channel or user_id

            # Get the channel
            discord_channel = await self._get_channel(target_channel_id)
            if discord_channel is None:
                return {
                    "success": False,
                    "error": f"Channel {target_channel_id} not found"
                }

            # Check if we should reply to a previous message
            reference = None
            if previous_message_id and previous_message_id in self.message_cache:
                reference = self.message_cache[previous_message_id]

            # Send message
            if reference:
                sent_message = await reference.reply(message)
            else:
                sent_message = await discord_channel.send(message)

            # Cache the sent message
            message_id = str(sent_message.id)
            self.message_cache[message_id] = sent_message

            log.info(f"[DiscordMessageProvider] Sent message to {target_channel_id}: {message[:50]}...")

            return {
                "success": True,
                "message_id": message_id,
                "channel": str(sent_message.channel.id)
            }

        except discord.Forbidden:
            log.error(f"[DiscordMessageProvider] No permission to send message to {target_channel_id}")
            return {
                "success": False,
                "error": "No permission to send message"
            }
        except Exception as e:
            log.error(f"[DiscordMessageProvider] Failed to send message: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def send_message(
        self,
        message: str,
        user_id: str,
        channel: Optional[str] = None,
        previous_message_id: Optional[str] = None
    ) -> dict:
        """
        Send a message to Discord.

        Args:
            message: Text to send
            user_id: Discord user ID or channel ID
            channel: Optional channel override (channel ID)
            previous_message_id: If provided, reply to this message

        Returns:
            Dict with message metadata including message_id
        """
        # Since this is a sync method but Discord is async, we need to schedule it
        try:
            loop = self.bot.loop
            if loop and loop.is_running():
                try:
                    running_loop = asyncio.get_running_loop()
                except RuntimeError:
                    running_loop = None
                if running_loop is loop:
                    loop.create_task(
                        self._send_message_async(message, user_id, channel, previous_message_id)
                    )
                    return {"success": True, "status": "scheduled"}
                future = asyncio.run_coroutine_threadsafe(
                    self._send_message_async(message, user_id, channel, previous_message_id),
                    loop
                )
                return future.result(timeout=30)
            return asyncio.run(
                self._send_message_async(message, user_id, channel, previous_message_id)
            )
        except Exception as e:
            log.error(f"[DiscordMessageProvider] Error in send_message: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    async def _send_reaction_async(self, message_id: str, reaction: str) -> dict:
        """Internal async method to add reactions."""
        try:
            # Get message from cache
            if message_id not in self.message_cache:
                return {
                    "success": False,
                    "error": "Message not found in cache"
                }

            message = self.message_cache[message_id]

            # Add reaction
            await message.add_reaction(reaction)

            log.info(f"[DiscordMessageProvider] Added reaction {reaction} to message {message_id}")

            return {
                "success": True,
                "message_id": message_id,
                "reaction": reaction
            }

        except discord.Forbidden:
            log.error(f"[DiscordMessageProvider] No permission to add reaction")
            return {
                "success": False,
                "error": "No permission to add reaction"
            }
        except discord.HTTPException as e:
            log.error(f"[DiscordMessageProvider] Failed to add reaction: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def send_reaction(self, message_id: str, reaction: str) -> dict:
        """
        Add a reaction to a Discord message.

        Args:
            message_id: Discord message ID
            reaction: Emoji to react with (e.g., "👍", "❤️", or custom emoji like "<:name:id>")

        Returns:
            Dict with success status
        """
        try:
            loop = self.bot.loop
            if loop and loop.is_running():
                try:
                    running_loop = asyncio.get_running_loop()
                except RuntimeError:
                    running_loop = None
                if running_loop is loop:
                    loop.create_task(self._send_reaction_async(message_id, reaction))
                    return {"success": True, "status": "scheduled"}
                future = asyncio.run_coroutine_threadsafe(
                    self._send_reaction_async(message_id, reaction),
                    loop
                )
                return future.result(timeout=30)
            return asyncio.run(self._send_reaction_async(message_id, reaction))
        except Exception as e:
            log.error(f"[DiscordMessageProvider] Error in send_reaction: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    async def _update_message_async(self, message_id: str, new_text: str) -> dict:
        """Internal async method to update messages."""
        try:
            # Get message from cache
            if message_id not in self.message_cache:
                return {
                    "success": False,
                    "error": "Message not found in cache"
                }

            message = self.message_cache[message_id]

            # Update message
            await message.edit(content=new_text)

            log.info(f"[DiscordMessageProvider] Updated message {message_id}")

            return {
                "success": True,
                "message_id": message_id
            }

        except discord.Forbidden:
            log.error(f"[DiscordMessageProvider] No permission to edit message")
            return {
                "success": False,
                "error": "No permission to edit message"
            }
        except discord.HTTPException as e:
            log.error(f"[DiscordMessageProvider] Failed to update message: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def update_message(self, message_id: str, new_text: str) -> dict:
        """
        Update an existing Discord message.

        Args:
            message_id: Discord message ID
            new_text: New message text

        Returns:
            Dict with success status
        """
        try:
            loop = self.bot.loop
            if loop and loop.is_running():
                try:
                    running_loop = asyncio.get_running_loop()
                except RuntimeError:
                    running_loop = None
                if running_loop is loop:
                    loop.create_task(self._update_message_async(message_id, new_text))
                    return {"success": True, "status": "scheduled"}
                future = asyncio.run_coroutine_threadsafe(
                    self._update_message_async(message_id, new_text),
                    loop
                )
                return future.result(timeout=30)
            return asyncio.run(self._update_message_async(message_id, new_text))
        except Exception as e:
            log.error(f"[DiscordMessageProvider] Error in update_message: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def register_message_listener(self, callback: Callable):
        """
        Register a callback function to be called when messages are received.

        Args:
            callback: Function that takes a message dict as parameter
        """
        if not callable(callback):
            raise ValueError("Callback must be a callable function")

        self.message_listeners.append(callback)
        log.info(f"[DiscordMessageProvider] Registered message listener")

    def start(self):
        """
        Start the Discord bot.

        This is a blocking call that runs the bot until stopped.
        """
        log.info("[DiscordMessageProvider] Starting Discord bot...")
        try:
            self.bot.run(self.bot_token)
        except discord.LoginFailure:
            log.error("[DiscordMessageProvider] Invalid bot token")
            raise
        except Exception as e:
            log.error(f"[DiscordMessageProvider] Failed to start bot: {str(e)}")
            raise
