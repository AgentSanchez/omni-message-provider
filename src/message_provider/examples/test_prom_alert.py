#!/usr/bin/env python3
"""
Fire a test Prometheus Alertmanager alert at a running webhook provider.

Usage:
    python -m message_provider.examples.test_prom_alert localhost:9549
    python -m message_provider.examples.test_prom_alert localhost:9549 --resolved
    python -m message_provider.examples.test_prom_alert localhost:9549 --severity warning
    python -m message_provider.examples.test_prom_alert localhost:9549 --api-key my-secret
    python -m message_provider.examples.test_prom_alert localhost:9549 --alert-name DiskFull
    python -m message_provider.examples.test_prom_alert localhost:9549 --count 3
    python -m message_provider.examples.test_prom_alert localhost:9549 --raw

Examples:
    # Fire a critical firing alert (default)
    ./test_prom_alert.py localhost:9549

    # Fire a resolved alert
    ./test_prom_alert.py localhost:9549 --resolved

    # Fire 5 alerts in one payload
    ./test_prom_alert.py localhost:9549 --count 5

    # Send a raw (non-Alertmanager) JSON payload
    ./test_prom_alert.py localhost:9549 --raw
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone


def build_alert(alertname, severity, status, instance="server-1:9090"):
    """Build a single alert entry for an Alertmanager payload."""
    now = datetime.now(timezone.utc).isoformat()

    alert = {
        "status": status,
        "labels": {
            "alertname": alertname,
            "severity": severity,
            "instance": instance,
            "job": "node-exporter",
        },
        "annotations": {
            "summary": f"{alertname} on {instance}",
            "description": f"{alertname} has been detected on {instance}. Severity: {severity}.",
        },
        "startsAt": now,
        "endsAt": "0001-01-01T00:00:00Z" if status == "firing" else now,
        "generatorURL": f"http://prometheus:9090/graph?g0.expr={alertname.lower()}",
        "fingerprint": f"{alertname.lower()}_{instance.replace(':', '_')}",
    }
    return alert


def build_alertmanager_payload(alerts, receiver="test-webhook"):
    """Wrap alert(s) in a full Alertmanager envelope."""
    first = alerts[0] if alerts else {}
    alertname = first.get("labels", {}).get("alertname", "unknown")
    status = first.get("status", "firing")

    payload = {
        "receiver": receiver,
        "status": status,
        "alerts": alerts,
        "groupLabels": {"alertname": alertname},
        "commonLabels": {
            "job": "node-exporter",
        },
        "commonAnnotations": {},
        "externalURL": "http://alertmanager:9093",
        "groupKey": f"{{}}:{{alertname=\"{alertname}\"}}",
    }
    return payload


def send_webhook(url, payload, api_key=None):
    """POST a JSON payload to the given URL. Uses only stdlib."""
    data = json.dumps(payload).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8") if e.fp else ""
        return e.code, body
    except urllib.error.URLError as e:
        return None, str(e.reason)


def main():
    parser = argparse.ArgumentParser(
        description="Fire a test Prometheus Alertmanager alert",
    )
    parser.add_argument(
        "target",
        help="Host:port of the webhook provider (e.g. localhost:9549)",
    )
    parser.add_argument(
        "--resolved", action="store_true",
        help="Send a resolved alert instead of firing",
    )
    parser.add_argument(
        "--severity", default="critical",
        choices=["critical", "warning", "info"],
        help="Alert severity (default: critical)",
    )
    parser.add_argument(
        "--alert-name", default="HighMemoryUsage",
        help="Alert name (default: HighMemoryUsage)",
    )
    parser.add_argument(
        "--instance", default="server-1:9090",
        help="Instance label (default: server-1:9090)",
    )
    parser.add_argument(
        "--count", type=int, default=1,
        help="Number of alerts to include in one payload (default: 1)",
    )
    parser.add_argument(
        "--webhook-path", default="/webhook",
        help="Webhook endpoint path (default: /webhook)",
    )
    parser.add_argument(
        "--api-key", default=None,
        help="API key to include as Bearer token",
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="Send a minimal non-Alertmanager JSON payload (for raw mode testing)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print the payload without sending it",
    )

    args = parser.parse_args()

    # Normalize target
    target = args.target
    if not target.startswith("http"):
        target = f"http://{target}"
    url = f"{target.rstrip('/')}{args.webhook_path}"

    status = "resolved" if args.resolved else "firing"

    if args.raw:
        payload = {
            "source": "test_prom_alert",
            "message": f"Test raw payload ({status})",
            "severity": args.severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    else:
        alerts = []
        for i in range(args.count):
            instance = args.instance if args.count == 1 else f"server-{i + 1}:9090"
            name = args.alert_name if args.count == 1 else f"{args.alert_name}_{i + 1}"
            alerts.append(build_alert(name, args.severity, status, instance))
        payload = build_alertmanager_payload(alerts)

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Sending {status} alert to {url}")
    if args.count > 1:
        print(f"  Alerts in payload: {args.count}")
    if args.api_key:
        print(f"  Auth: Bearer ***{args.api_key[-4:]}")

    code, body = send_webhook(url, payload, api_key=args.api_key)

    if code is None:
        print(f"  Connection failed: {body}")
        return 1
    elif 200 <= code < 300:
        print(f"  OK ({code}): {body}")
        return 0
    else:
        print(f"  Failed ({code}): {body}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
