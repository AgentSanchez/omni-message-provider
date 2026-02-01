"""Omni Message Provider - Unified messaging interface for Discord, Slack, Jira, and more."""

__version__ = "0.2.0"

# Import base classes and components without optional dependencies
from message_provider.message_provider import MessageProvider
from message_provider.fastapi_message_provider import FastAPIMessageProvider
from message_provider.relay.relay_hub import RelayHub
from message_provider.relay.relay_message_provider import RelayMessageProvider
from message_provider.relay.relay_client import RelayClient

__all__ = [
    "MessageProvider",
    "FastAPIMessageProvider",
    "SlackMessageProvider",
    "DiscordMessageProvider",
    "JiraMessageProvider",
    "RelayHub",
    "RelayMessageProvider",
    "RelayClient",
]


def __getattr__(name):
    """Lazy import providers with optional dependencies."""
    if name == "SlackMessageProvider":
        from message_provider.slack_message_provider import SlackMessageProvider
        globals()[name] = SlackMessageProvider  # Cache it in module namespace
        return SlackMessageProvider
    elif name == "DiscordMessageProvider":
        from message_provider.discord_message_provider import DiscordMessageProvider
        globals()[name] = DiscordMessageProvider  # Cache it in module namespace
        return DiscordMessageProvider
    elif name == "JiraMessageProvider":
        from message_provider.jira_message_provider import JiraMessageProvider
        globals()[name] = JiraMessageProvider  # Cache it in module namespace
        return JiraMessageProvider
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    """Include lazy-loaded attributes in dir() for better IDE support."""
    return list(globals().keys()) + [
        "SlackMessageProvider",
        "DiscordMessageProvider",
        "JiraMessageProvider",
    ]
