#!/usr/bin/env python3
"""
Example of using RelayHub and RelayMessageProvider for distributed architecture.

Architecture:
    [MP Service Pod]                    [Orchestrator Pods (multiple)]
    - Discord/Slack bots                - OmniOrchestrator
    - FastAPIMessageProvider            - RelayMessageProvider
    - RelayHub (WebSocket server)       - Connect to RelayHub

Setup:
    1. Run MP Service (this file with --mode mp)
    2. Run Orchestrators (this file with --mode orchestrator, multiple instances)
    3. Send Discord/Slack message
    4. MP routes to orchestrator based on (user, channel, client_id)
    5. Same user always goes to same orchestrator

Usage:
    # Terminal 1: Start MP Service
    python -m message_provider.relay_example --mode mp

    # Terminal 2: Start Orchestrator 1
    python -m message_provider.relay_example --mode orchestrator --name orch-1

    # Terminal 3: Start Orchestrator 2
    python -m message_provider.relay_example --mode orchestrator --name orch-2

    # Now send messages through the FastAPI message provider
    # Messages will be load-balanced to orchestrators
"""

import argparse
import asyncio
import os
import logging

log = logging.getLogger(__name__)


def run_mp_service():
    """Run the MP Service with RelayHub."""
    from message_provider.fastapi_message_provider import FastAPIMessageProvider
    from message_provider.relay.relay_hub import RelayHub

    log.info("=" * 60)
    log.info("Starting MP Service with RelayHub")
    log.info("=" * 60)

    # Create FastAPI message provider (handles Discord/Slack clients)
    mp_provider = FastAPIMessageProvider(
        api_key=os.getenv("MESSAGE_API_KEY"),
        host="0.0.0.0",
        port=9547
    )

    log.info("FastAPI Message Provider initialized on port 9547")
    log.info("  - Send messages: POST http://localhost:9547/message/process")
    log.info("  - Register clients: POST http://localhost:9547/client/register")

    # Create RelayHub (WebSocket server for orchestrators)
    hub = RelayHub(
        local_provider=mp_provider,
        host="0.0.0.0",
        port=8765
    )

    log.info("RelayHub WebSocket server will start on ws://0.0.0.0:8765")
    log.info("Orchestrators should connect to this endpoint")
    log.info("")
    log.info("Starting servers...")
    log.info("")

    # Start both in parallel
    async def run_both():
        # Start FastAPI in thread
        import threading
        import uvicorn

        def run_fastapi():
            uvicorn.run(mp_provider.app, host="0.0.0.0", port=9547)

        fastapi_thread = threading.Thread(target=run_fastapi, daemon=True)
        fastapi_thread.start()

        # Start RelayHub (async)
        await hub.start()

    try:
        asyncio.run(run_both())
    except KeyboardInterrupt:
        log.info("Shutting down MP Service...")


def run_orchestrator(orchestrator_name: str):
    """Run an Orchestrator with RelayMessageProvider."""
    from message_provider.relay.relay_message_provider import RelayMessageProvider

    log.info("=" * 60)
    log.info(f"Starting Orchestrator: {orchestrator_name}")
    log.info("=" * 60)

    # WebSocket URL to MP service
    ws_url = os.getenv("RELAY_HUB_URL", "ws://localhost:8765")

    # Create relay message provider
    provider = RelayMessageProvider(
        websocket_url=ws_url,
        reconnect_interval=5
    )

    # Define message handler (orchestrator's brain)
    def message_handler(message):
        """Handle incoming messages from users."""
        log.info("")
        log.info(f"[{orchestrator_name}] Received message:")
        log.info(f"  User: {message.get('user_id')}")
        log.info(f"  Channel: {message.get('channel')}")
        log.info(f"  Text: {message.get('text')}")
        log.info(f"  Message ID: {message.get('message_id')}")

        # Example: Echo the message back
        user_id = message.get('user_id')
        channel = message.get('channel')
        text = message.get('text', '')
        message_id = message.get('message_id')

        # Send reply
        log.info(f"[{orchestrator_name}] Sending reply...")
        provider.send_message(
            message=f"[{orchestrator_name}] You said: {text}",
            user_id=user_id,
            channel=channel,
            previous_message_id=message_id
        )

        # Add reaction
        log.info(f"[{orchestrator_name}] Adding reaction...")
        provider.send_reaction(message_id, "👍")

    # Register handler
    provider.register_message_listener(message_handler)

    log.info(f"Connecting to RelayHub at {ws_url}...")
    log.info("")

    # Start provider (blocking)
    try:
        provider.start()
    except KeyboardInterrupt:
        log.info(f"Shutting down {orchestrator_name}...")
        provider.stop()


def main():
    parser = argparse.ArgumentParser(
        description="Relay example for distributed message provider architecture",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "--mode",
        choices=["mp", "orchestrator"],
        required=True,
        help="Run mode: 'mp' for MP Service with RelayHub, 'orchestrator' for Orchestrator"
    )

    parser.add_argument(
        "--name",
        default="orchestrator-1",
        help="Orchestrator name (only used in orchestrator mode)"
    )

    args = parser.parse_args()

    if args.mode == "mp":
        run_mp_service()
    else:
        run_orchestrator(args.name)


if __name__ == "__main__":
    main()
