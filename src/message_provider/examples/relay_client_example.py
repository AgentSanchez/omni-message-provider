#!/usr/bin/env python3
"""
Example of using RelayClient to connect message providers to RelayHub.

This shows how to run individual message provider services (Discord, Slack, Jira)
and connect them to a centralized RelayHub for distributed architecture.

Architecture:
    [Discord Pod]                    [RelayHub Pod]              [Orchestrator Pods]
      DiscordMessageProvider    ←→   RelayHub (WS server)   ←→   RelayMessageProvider
      RelayClient (connects)         (Routes by user/channel)    (Multiple pods)

    [Slack Pod]
      SlackMessageProvider      ←→
      RelayClient (connects)

    [Jira Pod]
      JiraMessageProvider       ←→
      RelayClient (connects)

Usage:
    # Terminal 1: Start RelayHub
    python -m message_provider.relay.relay_example --mode mp

    # Terminal 2: Start Discord provider with relay
    python -m message_provider.relay.relay_client_example --provider discord

    # Terminal 3: Start Slack provider with relay
    python -m message_provider.relay.relay_client_example --provider slack

    # Terminal 4: Start orchestrator
    python -m message_provider.relay.relay_example --mode orchestrator
"""

import argparse
import asyncio
import os
import threading
import logging

log = logging.getLogger(__name__)


def run_discord_with_relay():
    """Run Discord message provider with relay client."""
    import discord
    from message_provider.discord_message_provider import DiscordMessageProvider
    from message_provider.relay.relay_client import RelayClient

    # Load configuration
    bot_token = os.getenv("DISCORD_BOT_TOKEN")
    relay_hub_url = os.getenv("RELAY_HUB_URL", "ws://localhost:8765")
    client_id = os.getenv("DISCORD_CLIENT_ID", "discord:main")

    if not bot_token:
        log.error("DISCORD_BOT_TOKEN environment variable is required")
        return 1

    log.info("=" * 60)
    log.info("Discord Message Provider with Relay")
    log.info("=" * 60)
    log.info(f"Client ID: {client_id}")
    log.info(f"RelayHub URL: {relay_hub_url}")
    log.info("=" * 60)

    # Configure intents
    intents = discord.Intents.default()
    intents.message_content = True

    # Create Discord provider
    discord_provider = DiscordMessageProvider(
        bot_token=bot_token,
        client_id=client_id,
        intents=intents,
        trigger_mode="mention",
        command_prefixes=["!support", "!cq"]
    )

    # Create relay client
    relay_client = RelayClient(
        local_provider=discord_provider,
        relay_hub_url=relay_hub_url,
        client_id=client_id
    )

    log.info("Starting Discord provider and relay client...")

    # Start relay client in background thread
    relay_thread = threading.Thread(target=relay_client.start_blocking, daemon=True)
    relay_thread.start()

    # Start Discord provider (blocking)
    try:
        discord_provider.start()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        relay_client.stop()

    return 0


def run_slack_with_relay():
    """Run Slack message provider with relay client."""
    from message_provider.slack_message_provider import SlackMessageProvider
    from message_provider.relay.relay_client import RelayClient

    # Load configuration
    bot_token = os.getenv("SLACK_BOT_TOKEN")
    app_token = os.getenv("SLACK_APP_TOKEN")
    relay_hub_url = os.getenv("RELAY_HUB_URL", "ws://localhost:8765")
    client_id = os.getenv("SLACK_CLIENT_ID", "slack:main")

    if not bot_token:
        log.error("SLACK_BOT_TOKEN environment variable is required")
        return 1
    if not app_token:
        log.error("SLACK_APP_TOKEN environment variable is required")
        return 1

    log.info("=" * 60)
    log.info("Slack Message Provider with Relay")
    log.info("=" * 60)
    log.info(f"Client ID: {client_id}")
    log.info(f"RelayHub URL: {relay_hub_url}")
    log.info("=" * 60)

    # Create Slack provider
    slack_provider = SlackMessageProvider(
        bot_token=bot_token,
        client_id=client_id,
        app_token=app_token,
        use_socket_mode=True,
        trigger_mode="mention",
        allowed_channels=["#support"]
    )

    # Create relay client
    relay_client = RelayClient(
        local_provider=slack_provider,
        relay_hub_url=relay_hub_url,
        client_id=client_id
    )

    log.info("Starting Slack provider and relay client...")

    # Start relay client in background thread
    relay_thread = threading.Thread(target=relay_client.start_blocking, daemon=True)
    relay_thread.start()

    # Start Slack provider (blocking)
    try:
        slack_provider.start()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        relay_client.stop()

    return 0


def run_jira_with_relay():
    """Run Jira message provider with relay client."""
    from message_provider.jira_message_provider import JiraMessageProvider
    from message_provider.relay.relay_client import RelayClient

    # Load configuration
    server = os.getenv("JIRA_SERVER")
    email = os.getenv("JIRA_EMAIL")
    api_token = os.getenv("JIRA_API_TOKEN")
    project_keys_str = os.getenv("JIRA_PROJECT_KEYS", "")
    watch_labels_str = os.getenv("JIRA_WATCH_LABELS", "")
    trigger_phrases_str = os.getenv("JIRA_TRIGGER_PHRASES", "")
    relay_hub_url = os.getenv("RELAY_HUB_URL", "ws://localhost:8765")
    client_id = os.getenv("JIRA_CLIENT_ID", "jira:main")

    if not all([server, email, api_token, project_keys_str]):
        log.error("JIRA_SERVER, JIRA_EMAIL, JIRA_API_TOKEN, and JIRA_PROJECT_KEYS are required")
        return 1

    # Parse configuration
    project_keys = [k.strip() for k in project_keys_str.split(',') if k.strip()]
    watch_labels = [l.strip() for l in watch_labels_str.split(',') if l.strip()] if watch_labels_str else []
    trigger_phrases = [p.strip() for p in trigger_phrases_str.split(',') if p.strip()] if trigger_phrases_str else []

    log.info("=" * 60)
    log.info("Jira Message Provider with Relay")
    log.info("=" * 60)
    log.info(f"Client ID: {client_id}")
    log.info(f"RelayHub URL: {relay_hub_url}")
    log.info(f"Projects: {', '.join(project_keys)}")
    log.info("=" * 60)

    # Create Jira provider
    jira_provider = JiraMessageProvider(
        server=server,
        email=email,
        api_token=api_token,
        project_keys=project_keys,
        client_id=client_id,
        watch_labels=watch_labels,
        trigger_phrases=trigger_phrases
    )

    # Create relay client
    relay_client = RelayClient(
        local_provider=jira_provider,
        relay_hub_url=relay_hub_url,
        client_id=client_id
    )

    log.info("Starting Jira provider and relay client...")

    # Start relay client in background thread
    relay_thread = threading.Thread(target=relay_client.start_blocking, daemon=True)
    relay_thread.start()

    # Start Jira provider (blocking)
    try:
        jira_provider.start()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        relay_client.stop()

    return 0


def run_fastapi_with_relay():
    """Run FastAPI message provider with relay client."""
    from message_provider.fastapi_message_provider import FastAPIMessageProvider
    from message_provider.relay.relay_client import RelayClient
    import uvicorn

    # Load configuration
    api_key = os.getenv("MESSAGE_API_KEY")
    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", "9547"))
    relay_hub_url = os.getenv("RELAY_HUB_URL", "ws://localhost:8765")
    client_id = os.getenv("FASTAPI_CLIENT_ID", "api:main")

    log.info("=" * 60)
    log.info("FastAPI Message Provider with Relay")
    log.info("=" * 60)
    log.info(f"Client ID: {client_id}")
    log.info(f"RelayHub URL: {relay_hub_url}")
    log.info(f"API: http://{host}:{port}")
    log.info("=" * 60)

    # Create FastAPI provider
    fastapi_provider = FastAPIMessageProvider(
        api_key=api_key,
        host=host,
        port=port
    )

    # Create relay client
    relay_client = RelayClient(
        local_provider=fastapi_provider,
        relay_hub_url=relay_hub_url,
        client_id=client_id
    )

    log.info("Starting FastAPI provider and relay client...")

    # Start relay client in background thread
    relay_thread = threading.Thread(target=relay_client.start_blocking, daemon=True)
    relay_thread.start()

    # Start FastAPI (blocking)
    try:
        uvicorn.run(fastapi_provider.app, host=host, port=port)
    except KeyboardInterrupt:
        log.info("Shutting down...")
        relay_client.stop()

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Run message provider with relay client",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--provider",
        choices=["discord", "slack", "jira", "fastapi"],
        required=True,
        help="Message provider type to run"
    )

    args = parser.parse_args()

    if args.provider == "discord":
        return run_discord_with_relay()
    elif args.provider == "slack":
        return run_slack_with_relay()
    elif args.provider == "jira":
        return run_jira_with_relay()
    elif args.provider == "fastapi":
        return run_fastapi_with_relay()


if __name__ == "__main__":
    exit(main())
