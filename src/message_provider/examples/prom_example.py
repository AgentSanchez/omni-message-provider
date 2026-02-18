#!/usr/bin/env python3
"""
Example: Prometheus Alertmanager webhook listener.

Starts a PrometheusWebhookProvider that listens for incoming Alertmanager
webhook POSTs and handles them with basic routing logic.

Usage:
    python -m message_provider.examples.prom_example
    python -m message_provider.examples.prom_example --port 8080
    python -m message_provider.examples.prom_example --api-key my-secret --parse-mode raw

Environment variables (all optional):
    WEBHOOK_API_KEY   - Require this Bearer token on incoming webhooks
    WEBHOOK_PORT      - Port to listen on (default: 9549)

Then fire a test alert from another terminal:
    python -m message_provider.examples.test_prom_alert localhost:9549
"""

import argparse
import logging
import os
import sys

from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ANSI colors for terminal output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

SEVERITY_COLORS = {
    "critical": RED,
    "warning": YELLOW,
    "info": CYAN,
}


def alert_handler(alert):
    """
    Handle an incoming alert with basic routing logic.

    Demonstrates how to inspect normalized alert fields and take action
    based on status, severity, and labels.
    """
    status = alert.get("status", "unknown")
    labels = alert.get("labels", {})
    alertname = labels.get("alertname", "unknown")
    severity = labels.get("severity", "info")
    text = alert.get("text", "(no summary)")
    alert_id = alert.get("alert_id", "?")
    starts_at = alert.get("starts_at", "")
    ends_at = alert.get("ends_at", "")
    channel = alert.get("channel", "")

    color = SEVERITY_COLORS.get(severity, RESET)
    status_icon = f"{RED}FIRING{RESET}" if status == "firing" else f"{GREEN}RESOLVED{RESET}"

    print()
    print(f"  {BOLD}--- Alert Received ---{RESET}")
    print(f"  Status:    {status_icon}")
    print(f"  Name:      {BOLD}{alertname}{RESET}")
    print(f"  Severity:  {color}{severity}{RESET}")
    print(f"  Summary:   {text}")
    print(f"  Alert ID:  {alert_id}")
    print(f"  Channel:   {channel}")
    if starts_at:
        print(f"  Started:   {starts_at}")
    if ends_at and not ends_at.startswith("0001"):
        print(f"  Ended:     {ends_at}")

    # --- Example routing logic ---
    if status == "firing" and severity == "critical":
        print(f"  {RED}{BOLD}>> ACTION: Would page on-call engineer!{RESET}")
    elif status == "firing" and severity == "warning":
        print(f"  {YELLOW}>> ACTION: Would post to #alerts Slack channel{RESET}")
    elif status == "resolved":
        print(f"  {GREEN}>> ACTION: Would close incident for {alertname}{RESET}")
    else:
        print(f"  >> ACTION: Logged (no special handling)")

    # Show extra metadata
    metadata = alert.get("metadata", {})
    receiver = metadata.get("receiver", "")
    if receiver:
        print(f"  Receiver:  {receiver}")

    print(f"  {BOLD}--- End Alert ---{RESET}")
    print()


def raw_handler(data):
    """Handle raw-mode payloads (entire JSON body)."""
    payload = data.get("metadata", {}).get("raw_payload", {})
    alert_count = len(payload.get("alerts", []))

    print()
    print(f"  {BOLD}--- Raw Payload Received ---{RESET}")
    print(f"  Alerts in payload: {alert_count}")
    print(f"  Receiver: {payload.get('receiver', 'unknown')}")
    print(f"  Status:   {payload.get('status', 'unknown')}")
    print(f"  Timestamp: {data.get('timestamp', '')}")
    print(f"  {BOLD}--- End Raw ---{RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Prometheus Alertmanager webhook listener",
    )
    parser.add_argument(
        "--port", type=int,
        default=int(os.getenv("WEBHOOK_PORT", "9549")),
        help="Port to listen on (default: 9549)",
    )
    parser.add_argument(
        "--host", default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--api-key", default=os.getenv("WEBHOOK_API_KEY"),
        help="Require this Bearer token on incoming webhooks",
    )
    parser.add_argument(
        "--parse-mode", choices=["alertmanager", "raw"], default="alertmanager",
        help="Parse mode: 'alertmanager' normalizes per-alert, 'raw' passes full payload (default: alertmanager)",
    )
    parser.add_argument(
        "--webhook-path", default="/webhook",
        help="Path for the webhook endpoint (default: /webhook)",
    )
    parser.add_argument(
        "--client-id", default="prometheus:example",
        help="Client ID for this provider instance",
    )

    args = parser.parse_args()

    provider = PrometheusWebhookProvider(
        client_id=args.client_id,
        parse_mode=args.parse_mode,
        api_key=args.api_key,
        host=args.host,
        port=args.port,
        webhook_path=args.webhook_path,
    )

    handler = alert_handler if args.parse_mode == "alertmanager" else raw_handler
    provider.register_message_listener(handler)

    print(f"{BOLD}Prometheus Webhook Provider{RESET}")
    print(f"  Listening on  http://{args.host}:{args.port}{args.webhook_path}")
    print(f"  Health check  http://{args.host}:{args.port}/health")
    print(f"  Parse mode    {args.parse_mode}")
    print(f"  Auth          {'Bearer token required' if args.api_key else 'disabled'}")
    print()
    print("Waiting for alerts... (Ctrl+C to stop)")
    print()

    try:
        provider.start()
    except KeyboardInterrupt:
        print("\nShutting down.")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
