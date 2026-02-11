#!/usr/bin/env python3
"""
Example polling client for the Message Provider API. This was created by AI with human direction and design.

Usage:
    python -m message_provider.polling_client_example --user-id <user_id> [options]

Examples:
    python -m message_provider.polling_client_example --user-id user123 --api-key mykey

    # With authentication
    python -m message_provider.polling_client_example --user-id alice --password secret123

    # Using environment variables
    export POLLING_CLIENT_USER_ID=alice
    export POLLING_CLIENT_API_URL=http://localhost:9547
    export POLLING_CLIENT_PASSWORD=secret123
    python -m message_provider.polling_client_example
"""

import argparse
import requests
import time
import threading
import sys
import os
from typing import Optional
from datetime import datetime


# ANSI color codes
class Colors:
    RESET = '\033[0m'
    GREEN = '\033[92m'       # User messages
    ORANGE = '\033[38;5;208m'  # Claude-themed (incoming replies)
    CYAN = '\033[96m'        # Info messages
    RED = '\033[91m'         # Errors
    YELLOW = '\033[93m'      # Warnings
    MAGENTA = '\033[95m'     # Status updates
    BOLD = '\033[1m'
    DIM = '\033[2m'


class PollingClient:
    def __init__(
        self,
        user_id: str,
        api_url: str = "http://localhost:9547",
        api_key: Optional[str] = None,
        password: Optional[str] = None,
        poll_interval: int = 2,
        retry_interval: int = 10
    ):
        self.user_id = user_id
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.password = password
        self.poll_interval = poll_interval
        self.retry_interval = retry_interval
        self.subscriber_id: Optional[str] = None
        self.session_token: Optional[str] = None
        self.running = False
        self.connected = False
        self.waiting_for_reply = False
        self.current_request_id: Optional[str] = None
        self.reply_lock = threading.Lock()

    def _get_headers(self) -> dict:
        """Get headers including session token or API key if provided."""
        headers = {"Content-Type": "application/json"}
        # Prefer session token from auth, fall back to API key
        if self.session_token:
            headers["Authorization"] = f"Bearer {self.session_token}"
        elif self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def register(self) -> bool:
        """Register this client as a subscriber with the message provider."""
        try:
            # Build registration payload
            payload = {
                "user_id": self.user_id,
                "source_type": "polling_client"
            }

            # Add auth details if password provided
            if self.password:
                payload["auth_details"] = {"password": self.password}

            # Include existing subscriber_id for re-registration
            if self.subscriber_id:
                payload["subscriber_id"] = self.subscriber_id

            response = requests.post(
                f"{self.api_url}/subscriber/register",
                json=payload,
                headers=self._get_headers(),
                timeout=5
            )

            if response.status_code == 403:
                data = response.json()
                print(f"{Colors.RED}✗ Authentication failed: {data.get('detail', 'Access denied')}{Colors.RESET}")
                return False

            response.raise_for_status()
            data = response.json()

            self.subscriber_id = data["subscriber_id"]

            # Store session token if provided
            if "session_token" in data:
                self.session_token = data["session_token"]
                print(f"{Colors.CYAN}✓ Authenticated successfully!{Colors.RESET}")

            print(f"{Colors.CYAN}✓ Registered successfully! Subscriber ID: {self.subscriber_id}{Colors.RESET}")
            self.connected = True
            return True

        except requests.exceptions.ConnectionError:
            print(f"{Colors.RED}✗ Cannot connect to {self.api_url}. Will retry in {self.retry_interval} seconds...{Colors.RESET}")
            self.connected = False
            return False
        except Exception as e:
            print(f"{Colors.RED}✗ Registration failed: {str(e)}{Colors.RESET}")
            self.connected = False
            return False

    def poll_messages(self):
        """Poll for new messages continuously."""
        while self.running:
            if not self.connected:
                time.sleep(self.retry_interval)
                if not self.register():
                    continue

            try:
                response = requests.get(
                    f"{self.api_url}/messages/{self.subscriber_id}",
                    params={"clear": True},
                    headers=self._get_headers(),
                    timeout=5
                )

                if response.status_code == 401:
                    print(f"\n{Colors.RED}✗ Session expired. Re-registering...{Colors.RESET}")
                    self.connected = False
                    continue

                response.raise_for_status()
                data = response.json()

                if data["count"] > 0:
                    print(f"\n{Colors.ORANGE}{'='*60}")
                    print(f"   Received {data['count']} message(s):")
                    for msg in data["messages"]:
                        timestamp = msg.get("timestamp", "")
                        msg_type = msg.get("type", "message")

                        if msg_type == "reaction":
                            # Handle reaction
                            message_id = msg.get("message_id", "unknown")
                            reaction = msg.get("reaction", "")
                            print(f"\n  {Colors.DIM}[{timestamp}]{Colors.RESET}{Colors.YELLOW} Reaction on message {message_id}: {reaction}{Colors.RESET}")
                        elif msg_type == "update":
                            # Handle message update
                            message_id = msg.get("message_id", "unknown")
                            new_text = msg.get("text", "")
                            print(f"\n  {Colors.DIM}[{timestamp}]{Colors.RESET}{Colors.CYAN} Message {message_id} updated:{Colors.RESET}")
                            print(f"{Colors.CYAN}     {new_text}{Colors.RESET}")
                        elif msg_type == "status_update":
                            # Handle status update
                            request_id = msg.get("request_id", "unknown")
                            status = msg.get("status", "unknown")
                            details = msg.get("details", {})
                            print(f"\n  {Colors.DIM}[{timestamp}]{Colors.RESET}{Colors.MAGENTA} Status update for {request_id}: {status}{Colors.RESET}")
                            if details:
                                print(f"{Colors.MAGENTA}     Details: {details}{Colors.RESET}")
                        else:
                            # Handle regular message
                            user = msg.get("user_id", "unknown")
                            text = msg.get("text", "")
                            thread_id = msg.get("thread_id", "")
                            print(f"\n  {Colors.DIM}[{timestamp}]{Colors.RESET}{Colors.ORANGE} From: {Colors.BOLD}{user}{Colors.RESET}")
                            if thread_id:
                                print(f"{Colors.DIM}  Thread: {thread_id}{Colors.RESET}")
                            print(f"{Colors.ORANGE}     {text}{Colors.RESET}")
                    print(f"{Colors.ORANGE}{'='*60}{Colors.RESET}")

                    # Clear waiting state when reply received
                    with self.reply_lock:
                        if self.waiting_for_reply:
                            self.waiting_for_reply = False
                            self.current_request_id = None

                    print(f"\n{Colors.GREEN}You ({self.user_id})>{Colors.RESET} ", end='', flush=True)

                self.connected = True

            except requests.exceptions.ConnectionError:
                if self.connected:
                    print(f"\n{Colors.RED}✗ Lost connection to {self.api_url}. Will retry in {self.retry_interval} seconds...{Colors.RESET}")
                self.connected = False
            except Exception as e:
                print(f"\n{Colors.RED}✗ Error polling messages: {str(e)}{Colors.RESET}")
                self.connected = False

            time.sleep(self.poll_interval)

    def send_message(self, text: str) -> bool:
        """Send a message through the message provider."""
        if not self.subscriber_id:
            print(f"{Colors.RED}✗ Not registered. Cannot send message.{Colors.RESET}")
            return False

        try:
            response = requests.post(
                f"{self.api_url}/message/process",
                json={
                    "text": text,
                    "user_id": self.user_id,
                    "channel": self.subscriber_id,  # Required for routing replies
                    "metadata": {"sent_at": datetime.utcnow().isoformat()}
                },
                headers=self._get_headers(),
                timeout=5
            )

            if response.status_code == 401:
                print(f"{Colors.RED}✗ Session expired. Please wait for re-registration...{Colors.RESET}")
                self.connected = False
                return False

            response.raise_for_status()
            data = response.json()

            request_id = data.get("message_id", "unknown")
            print(f"{Colors.DIM}✓ Sent (request_id: {request_id}){Colors.RESET}")

            # Set waiting state and store request ID
            with self.reply_lock:
                self.waiting_for_reply = True
                self.current_request_id = request_id
            print(f"{Colors.YELLOW}   Waiting for reply...{Colors.RESET}")

            return True
        except requests.exceptions.ConnectionError:
            print(f"{Colors.RED}✗ Cannot connect to {self.api_url}. Message not sent.{Colors.RESET}")
            self.connected = False
            return False
        except Exception as e:
            print(f"{Colors.RED}✗ Failed to send message: {str(e)}{Colors.RESET}")
            return False

    def check_status(self, request_id: Optional[str] = None) -> bool:
        """Request status update for a request (via unified message API)."""
        req_id = request_id or self.current_request_id
        if not req_id:
            print(f"{Colors.RED}✗ No request ID to check status for.{Colors.RESET}")
            return False

        if not self.subscriber_id:
            print(f"{Colors.RED}✗ Not registered. Cannot request status.{Colors.RESET}")
            return False

        try:
            response = requests.post(
                f"{self.api_url}/message/process",
                json={
                    "type": "status_request",
                    "user_id": self.user_id,
                    "channel": self.subscriber_id,
                    "request_id": req_id
                },
                headers=self._get_headers(),
                timeout=5
            )

            response.raise_for_status()
            print(f"{Colors.MAGENTA}✓ Status request sent for {req_id}{Colors.RESET}")
            return True
        except Exception as e:
            print(f"{Colors.RED}✗ Failed to request status: {str(e)}{Colors.RESET}")
            return False

    def cancel_request(self, request_id: Optional[str] = None) -> bool:
        """Request cancellation of an active request (via unified message API)."""
        req_id = request_id or self.current_request_id
        if not req_id:
            print(f"{Colors.RED}✗ No request ID to cancel.{Colors.RESET}")
            return False

        if not self.subscriber_id:
            print(f"{Colors.RED}✗ Not registered. Cannot request cancellation.{Colors.RESET}")
            return False

        try:
            response = requests.post(
                f"{self.api_url}/message/process",
                json={
                    "type": "cancellation_request",
                    "user_id": self.user_id,
                    "channel": self.subscriber_id,
                    "request_id": req_id
                },
                headers=self._get_headers(),
                timeout=5
            )

            response.raise_for_status()
            print(f"{Colors.CYAN}✓ Cancellation requested for {req_id}{Colors.RESET}")
            with self.reply_lock:
                if self.current_request_id == req_id:
                    self.waiting_for_reply = False
                    self.current_request_id = None
            return True
        except Exception as e:
            print(f"{Colors.RED}✗ Failed to cancel request: {str(e)}{Colors.RESET}")
            return False

    def start(self):
        """Start the polling client."""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}")
        print(f"  Message Provider Polling Client")
        print(f"{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}User ID: {Colors.BOLD}{self.user_id}{Colors.RESET}")
        print(f"{Colors.CYAN}API URL: {self.api_url}{Colors.RESET}")
        print(f"{Colors.CYAN}Poll Interval: {self.poll_interval}s{Colors.RESET}")
        if self.password:
            print(f"{Colors.CYAN}Authentication: Enabled{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")

        # Register initially
        if not self.register():
            print(f"{Colors.YELLOW}Initial registration failed. Will retry in {self.retry_interval} seconds...{Colors.RESET}")

        # Start polling thread
        self.running = True
        poll_thread = threading.Thread(target=self.poll_messages, daemon=True)
        poll_thread.start()

        print(f"\n{Colors.DIM}Commands:")
        print("  - Type a message and press Enter to send")
        print("  - Type '/status' to check current request status")
        print("  - Type '/status <request_id>' to check specific request")
        print("  - Type '/cancel' to cancel current request")
        print("  - Type '/cancel <request_id>' to cancel specific request")
        print(f"  - Type 'quit' or 'exit' to stop{Colors.RESET}")
        print(f"\n{Colors.GREEN}You ({self.user_id})>{Colors.RESET} ", end='', flush=True)

        # Main loop for user input
        try:
            while self.running:
                try:
                    # Wait while reply is pending
                    while self.waiting_for_reply and self.running:
                        time.sleep(0.1)

                    if not self.running:
                        break

                    user_input = input()

                    # Handle commands
                    if user_input.lower() in ['quit', 'exit']:
                        print(f"\n{Colors.CYAN}Shutting down...{Colors.RESET}")
                        self.running = False
                        break
                    elif user_input.lower().startswith('/status'):
                        parts = user_input.split(maxsplit=1)
                        req_id = parts[1] if len(parts) > 1 else None
                        self.check_status(req_id)
                        print(f"{Colors.GREEN}You ({self.user_id})>{Colors.RESET} ", end='', flush=True)
                    elif user_input.lower().startswith('/cancel'):
                        parts = user_input.split(maxsplit=1)
                        req_id = parts[1] if len(parts) > 1 else None
                        self.cancel_request(req_id)
                        print(f"{Colors.GREEN}You ({self.user_id})>{Colors.RESET} ", end='', flush=True)
                    elif user_input.strip():
                        self.send_message(user_input)
                    else:
                        # If empty input and not waiting, show prompt again
                        print(f"{Colors.GREEN}You ({self.user_id})>{Colors.RESET} ", end='', flush=True)

                except EOFError:
                    break

        except KeyboardInterrupt:
            print(f"\n\n{Colors.CYAN}Shutting down...{Colors.RESET}")
            self.running = False

        # Wait for polling thread to finish
        poll_thread.join(timeout=2)
        print(f"{Colors.CYAN}Goodbye!{Colors.RESET}")


def main():
    # Environment variable defaults
    default_user_id = os.getenv("POLLING_CLIENT_USER_ID")
    default_api_url = os.getenv("POLLING_CLIENT_API_URL", "http://localhost:9547")
    default_api_key = os.getenv("POLLING_CLIENT_API_KEY")
    default_password = os.getenv("POLLING_CLIENT_PASSWORD")

    parser = argparse.ArgumentParser(
        description="Example polling client for Message Provider API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m message_provider.polling_client_example --user-id alice
  python -m message_provider.polling_client_example --user-id bob --api-url http://localhost:9547 --password secret

Environment Variables:
  POLLING_CLIENT_USER_ID    - Default user ID
  POLLING_CLIENT_API_URL    - Default API URL (default: http://localhost:9547)
  POLLING_CLIENT_API_KEY    - Default API key (server-level)
  POLLING_CLIENT_PASSWORD   - Default password for authentication
        """
    )

    parser.add_argument(
        "--user-id",
        default=default_user_id,
        required=default_user_id is None,
        help=f"User ID for this client (env: POLLING_CLIENT_USER_ID){' [current: ' + default_user_id + ']' if default_user_id else ''}"
    )
    parser.add_argument(
        "--api-url",
        default=default_api_url,
        help=f"Message Provider API URL (env: POLLING_CLIENT_API_URL) [current: {default_api_url}]"
    )
    parser.add_argument(
        "--api-key",
        default=default_api_key,
        help=f"API key for server-level authentication (env: POLLING_CLIENT_API_KEY){' [set]' if default_api_key else ' [not set]'}"
    )
    parser.add_argument(
        "--password",
        default=default_password,
        help=f"Password for user authentication (env: POLLING_CLIENT_PASSWORD){' [set]' if default_password else ' [not set]'}"
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=2,
        help="Polling interval in seconds (default: 2)"
    )
    parser.add_argument(
        "--retry-interval",
        type=int,
        default=10,
        help="Retry interval on connection failure in seconds (default: 10)"
    )

    args = parser.parse_args()

    client = PollingClient(
        user_id=args.user_id,
        api_url=args.api_url,
        api_key=args.api_key,
        password=args.password,
        poll_interval=args.poll_interval,
        retry_interval=args.retry_interval
    )

    client.start()


if __name__ == "__main__":
    main()
