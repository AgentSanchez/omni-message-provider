"""Tests for PrometheusWebhookProvider."""

import pytest
from fastapi.testclient import TestClient


# Sample Alertmanager payload with two alerts
SAMPLE_ALERTMANAGER_PAYLOAD = {
    "receiver": "webhook-test",
    "status": "firing",
    "alerts": [
        {
            "status": "firing",
            "labels": {
                "alertname": "HighMemoryUsage",
                "severity": "critical",
                "instance": "server-1:9090",
            },
            "annotations": {
                "summary": "Memory usage is above 90%",
                "description": "Server-1 memory usage has exceeded 90% for 5 minutes.",
            },
            "startsAt": "2026-02-18T10:00:00.000Z",
            "endsAt": "0001-01-01T00:00:00Z",
            "generatorURL": "http://prometheus:9090/graph?g0.expr=mem_usage",
            "fingerprint": "abc123",
        },
        {
            "status": "resolved",
            "labels": {
                "alertname": "HighCPUUsage",
                "severity": "warning",
                "instance": "server-2:9090",
            },
            "annotations": {
                "summary": "CPU usage is back to normal",
            },
            "startsAt": "2026-02-18T09:00:00.000Z",
            "endsAt": "2026-02-18T10:00:00.000Z",
            "generatorURL": "http://prometheus:9090/graph?g0.expr=cpu_usage",
            "fingerprint": "def456",
        },
    ],
    "groupLabels": {"alertname": "HighMemoryUsage"},
    "commonLabels": {"team": "infra"},
    "commonAnnotations": {},
    "externalURL": "http://alertmanager:9093",
    "groupKey": "{}:{alertname=\"HighMemoryUsage\"}",
}

# Minimal single alert payload
SINGLE_ALERT_PAYLOAD = {
    "receiver": "default",
    "status": "firing",
    "alerts": [
        {
            "status": "firing",
            "labels": {"alertname": "DiskFull", "severity": "critical"},
            "annotations": {"summary": "Disk is full"},
            "startsAt": "2026-02-18T12:00:00.000Z",
            "endsAt": "0001-01-01T00:00:00Z",
            "generatorURL": "http://prometheus:9090/graph",
            "fingerprint": "disk123",
        }
    ],
    "groupLabels": {},
    "commonLabels": {},
    "commonAnnotations": {},
    "externalURL": "http://alertmanager:9093",
    "groupKey": "{}:{alertname=\"DiskFull\"}",
}


class TestPrometheusWebhookProviderInit:
    """Tests for provider initialization."""

    def test_init_defaults(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()

        assert provider.client_id == "prometheus:default"
        assert provider.parse_mode == "alertmanager"
        assert provider.api_key is None
        assert provider.host == "0.0.0.0"
        assert provider.port == 9549
        assert provider.webhook_path == "/webhook"

    def test_init_custom_config(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider(
            client_id="prometheus:prod",
            parse_mode="raw",
            api_key="secret-key",
            host="127.0.0.1",
            port=8080,
            webhook_path="/alerts",
        )

        assert provider.client_id == "prometheus:prod"
        assert provider.parse_mode == "raw"
        assert provider.api_key == "secret-key"
        assert provider.host == "127.0.0.1"
        assert provider.port == 8080
        assert provider.webhook_path == "/alerts"

    def test_init_invalid_parse_mode(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        with pytest.raises(ValueError, match="parse_mode"):
            PrometheusWebhookProvider(parse_mode="invalid")

    def test_init_empty_client_id(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        with pytest.raises(ValueError, match="client_id"):
            PrometheusWebhookProvider(client_id="")

    def test_is_webhook_provider_subclass(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider
        from message_provider.webhook_provider import WebhookProvider

        assert issubclass(PrometheusWebhookProvider, WebhookProvider)

    def test_is_not_message_provider_subclass(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider
        from message_provider.message_provider import MessageProvider

        assert not issubclass(PrometheusWebhookProvider, MessageProvider)


class TestPrometheusWebhookProviderListeners:
    """Tests for listener registration."""

    def test_register_listener(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        provider.register_message_listener(lambda m: None)

        assert len(provider.message_listeners) == 1

    def test_register_multiple_listeners(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        provider.register_message_listener(lambda m: None)
        provider.register_message_listener(lambda m: None)
        provider.register_message_listener(lambda m: None)

        assert len(provider.message_listeners) == 3

    def test_non_callable_listener_rejected(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()

        with pytest.raises(ValueError, match="callable"):
            provider.register_message_listener("not a function")


class TestPrometheusAlertmanagerMode:
    """Tests for alertmanager parse mode (default)."""

    def test_single_alert_dispatched(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post("/webhook", json=SINGLE_ALERT_PAYLOAD)

        assert response.status_code == 200
        assert len(received) == 1

        alert = received[0]
        assert alert["type"] == "alert"
        assert alert["alert_id"] == "disk123"
        assert alert["status"] == "firing"
        assert alert["text"] == "Disk is full"
        assert alert["labels"]["alertname"] == "DiskFull"
        assert alert["labels"]["severity"] == "critical"
        assert alert["annotations"]["summary"] == "Disk is full"
        assert alert["starts_at"] == "2026-02-18T12:00:00.000Z"
        assert alert["generator_url"] == "http://prometheus:9090/graph"
        assert "timestamp" in alert
        assert alert["metadata"]["client_id"] == "prometheus:default"

    def test_multiple_alerts_in_single_payload(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post("/webhook", json=SAMPLE_ALERTMANAGER_PAYLOAD)

        assert response.status_code == 200
        assert len(received) == 2

        # First alert: firing
        assert received[0]["alert_id"] == "abc123"
        assert received[0]["status"] == "firing"
        assert received[0]["text"] == "Memory usage is above 90%"
        assert received[0]["labels"]["alertname"] == "HighMemoryUsage"

        # Second alert: resolved
        assert received[1]["alert_id"] == "def456"
        assert received[1]["status"] == "resolved"
        assert received[1]["text"] == "CPU usage is back to normal"
        assert received[1]["labels"]["alertname"] == "HighCPUUsage"

    def test_firing_vs_resolved_status(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        client.post("/webhook", json=SAMPLE_ALERTMANAGER_PAYLOAD)

        statuses = [a["status"] for a in received]
        assert "firing" in statuses
        assert "resolved" in statuses

    def test_envelope_metadata(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider(client_id="prometheus:test")
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        client.post("/webhook", json=SAMPLE_ALERTMANAGER_PAYLOAD)

        meta = received[0]["metadata"]
        assert meta["client_id"] == "prometheus:test"
        assert meta["receiver"] == "webhook-test"
        assert meta["external_url"] == "http://alertmanager:9093"
        assert meta["group_labels"] == {"alertname": "HighMemoryUsage"}
        assert meta["common_labels"] == {"team": "infra"}
        assert meta["common_annotations"] == {}
        assert meta["raw_payload"] == SAMPLE_ALERTMANAGER_PAYLOAD

    def test_channel_uses_group_key(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        client.post("/webhook", json=SAMPLE_ALERTMANAGER_PAYLOAD)

        assert received[0]["channel"] == "{}:{alertname=\"HighMemoryUsage\"}"

    def test_channel_falls_back_to_alertname(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        payload = {
            "receiver": "default",
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "TestAlert"},
                    "annotations": {"summary": "Test"},
                    "startsAt": "2026-02-18T10:00:00Z",
                    "endsAt": "",
                    "generatorURL": "",
                    "fingerprint": "fp1",
                }
            ],
            "groupLabels": {},
            "commonLabels": {},
            "commonAnnotations": {},
            "externalURL": "",
            "groupKey": "",
        }

        client.post("/webhook", json=payload)

        assert received[0]["channel"] == "TestAlert"

    def test_text_prefers_summary_over_description(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        client.post("/webhook", json=SAMPLE_ALERTMANAGER_PAYLOAD)

        # First alert has both summary and description
        assert received[0]["text"] == "Memory usage is above 90%"

    def test_text_falls_back_to_description(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        payload = {
            "receiver": "default",
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "Test"},
                    "annotations": {"description": "Only description here"},
                    "startsAt": "",
                    "endsAt": "",
                    "generatorURL": "",
                    "fingerprint": "fp1",
                }
            ],
            "groupLabels": {},
            "commonLabels": {},
            "commonAnnotations": {},
            "externalURL": "",
            "groupKey": "",
        }

        client.post("/webhook", json=payload)

        assert received[0]["text"] == "Only description here"

    def test_missing_annotations_gives_empty_text(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        payload = {
            "receiver": "default",
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "NoAnnotations"},
                    "annotations": {},
                    "startsAt": "",
                    "endsAt": "",
                    "generatorURL": "",
                    "fingerprint": "fp1",
                }
            ],
            "groupLabels": {},
            "commonLabels": {},
            "commonAnnotations": {},
            "externalURL": "",
            "groupKey": "",
        }

        client.post("/webhook", json=payload)

        assert received[0]["text"] == ""

    def test_empty_alerts_array(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        payload = {
            "receiver": "default",
            "alerts": [],
            "groupLabels": {},
            "commonLabels": {},
            "commonAnnotations": {},
            "externalURL": "",
            "groupKey": "",
        }

        response = client.post("/webhook", json=payload)

        assert response.status_code == 200
        assert len(received) == 0

    def test_missing_fingerprint_generates_alert_id(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        payload = {
            "receiver": "default",
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "Test"},
                    "annotations": {},
                    "startsAt": "",
                    "endsAt": "",
                    "generatorURL": "",
                    # No fingerprint
                }
            ],
            "groupLabels": {},
            "commonLabels": {},
            "commonAnnotations": {},
            "externalURL": "",
            "groupKey": "",
        }

        client.post("/webhook", json=payload)

        # Should have a UUID-style alert_id
        assert received[0]["alert_id"]
        assert len(received[0]["alert_id"]) > 0

    def test_missing_optional_fields_handled(self):
        """Test that alerts with minimal fields are handled gracefully."""
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        # Minimal alert - missing many optional fields
        payload = {
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "Minimal"},
                }
            ],
        }

        response = client.post("/webhook", json=payload)

        assert response.status_code == 200
        assert len(received) == 1
        alert = received[0]
        assert alert["status"] == "firing"
        assert alert["labels"]["alertname"] == "Minimal"
        assert alert["annotations"] == {}
        assert alert["starts_at"] == ""
        assert alert["ends_at"] == ""
        assert alert["generator_url"] == ""
        assert alert["text"] == ""


class TestPrometheusRawMode:
    """Tests for raw parse mode."""

    def test_raw_mode_passes_full_payload(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider(parse_mode="raw")
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post("/webhook", json=SAMPLE_ALERTMANAGER_PAYLOAD)

        assert response.status_code == 200
        assert len(received) == 1

        msg = received[0]
        assert msg["type"] == "alert"
        assert msg["channel"] == "prometheus:default"
        assert msg["metadata"]["raw_payload"] == SAMPLE_ALERTMANAGER_PAYLOAD
        assert msg["metadata"]["client_id"] == "prometheus:default"
        assert "timestamp" in msg

    def test_raw_mode_single_call_for_multiple_alerts(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider(parse_mode="raw")
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        client.post("/webhook", json=SAMPLE_ALERTMANAGER_PAYLOAD)

        # Raw mode should dispatch once, not per alert
        assert len(received) == 1

    def test_raw_mode_arbitrary_json(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider(parse_mode="raw")
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        arbitrary_payload = {"custom": "data", "count": 42}
        response = client.post("/webhook", json=arbitrary_payload)

        assert response.status_code == 200
        assert len(received) == 1
        assert received[0]["metadata"]["raw_payload"] == arbitrary_payload


class TestPrometheusAPIKeyAuth:
    """Tests for API key authentication."""

    def test_no_api_key_configured_allows_all(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()  # No api_key
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post("/webhook", json=SINGLE_ALERT_PAYLOAD)

        assert response.status_code == 200
        assert len(received) == 1

    def test_valid_api_key_accepted(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider(api_key="my-secret")
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post(
            "/webhook",
            json=SINGLE_ALERT_PAYLOAD,
            headers={"Authorization": "Bearer my-secret"},
        )

        assert response.status_code == 200
        assert len(received) == 1

    def test_invalid_api_key_rejected(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider(api_key="my-secret")
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post(
            "/webhook",
            json=SINGLE_ALERT_PAYLOAD,
            headers={"Authorization": "Bearer wrong-key"},
        )

        assert response.status_code == 401
        assert len(received) == 0

    def test_missing_api_key_rejected(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider(api_key="my-secret")
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post("/webhook", json=SINGLE_ALERT_PAYLOAD)

        assert response.status_code == 401
        assert len(received) == 0

    def test_raw_api_key_accepted(self):
        """Test that raw key (without Bearer prefix) also works."""
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider(api_key="my-secret")
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        response = client.post(
            "/webhook",
            json=SINGLE_ALERT_PAYLOAD,
            headers={"Authorization": "my-secret"},
        )

        assert response.status_code == 200
        assert len(received) == 1


class TestPrometheusHealthEndpoint:
    """Tests for the health check endpoint."""

    def test_health_check(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider(client_id="prometheus:test")
        client = TestClient(provider.app)

        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["client_id"] == "prometheus:test"
        assert data["parse_mode"] == "alertmanager"
        assert "timestamp" in data

    def test_health_check_no_auth_required(self):
        """Health check should work even when api_key is configured."""
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider(api_key="my-secret")
        client = TestClient(provider.app)

        response = client.get("/health")

        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


class TestPrometheusListenerIsolation:
    """Tests for error isolation between listeners."""

    def test_failing_listener_does_not_break_others(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        results = []

        def failing_listener(m):
            raise Exception("Listener crashed!")

        def working_listener(m):
            results.append(m)

        provider.register_message_listener(failing_listener)
        provider.register_message_listener(working_listener)

        response = client.post("/webhook", json=SINGLE_ALERT_PAYLOAD)

        assert response.status_code == 200
        assert len(results) == 1

    def test_multiple_listeners_all_called(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        results1 = []
        results2 = []
        results3 = []

        provider.register_message_listener(lambda m: results1.append(m))
        provider.register_message_listener(lambda m: results2.append(m))
        provider.register_message_listener(lambda m: results3.append(m))

        client.post("/webhook", json=SINGLE_ALERT_PAYLOAD)

        assert len(results1) == 1
        assert len(results2) == 1
        assert len(results3) == 1

    def test_multiple_listeners_with_multiple_alerts(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        results1 = []
        results2 = []

        provider.register_message_listener(lambda m: results1.append(m))
        provider.register_message_listener(lambda m: results2.append(m))

        client.post("/webhook", json=SAMPLE_ALERTMANAGER_PAYLOAD)

        # 2 alerts, 2 listeners = each listener gets 2 calls
        assert len(results1) == 2
        assert len(results2) == 2


class TestPrometheusMisc:
    """Tests for miscellaneous methods."""

    def test_get_formatting_rules(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        assert provider.get_formatting_rules() == "plaintext"

    def test_get_app_returns_fastapi(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider
        from fastapi import FastAPI

        provider = PrometheusWebhookProvider()
        assert isinstance(provider.get_app(), FastAPI)

    def test_custom_webhook_path(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider(webhook_path="/alerts")
        client = TestClient(provider.app)

        received = []
        provider.register_message_listener(lambda m: received.append(m))

        # Default path should 404
        response = client.post("/webhook", json=SINGLE_ALERT_PAYLOAD)
        assert response.status_code in (404, 405)

        # Custom path should work
        response = client.post("/alerts", json=SINGLE_ALERT_PAYLOAD)
        assert response.status_code == 200
        assert len(received) == 1

    def test_invalid_json_returns_400(self):
        from message_provider.prometheus_webhook_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        client = TestClient(provider.app)

        response = client.post(
            "/webhook",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 400


class TestPrometheusImport:
    """Tests for package-level imports."""

    def test_import_from_package(self):
        from message_provider import PrometheusWebhookProvider

        provider = PrometheusWebhookProvider()
        assert provider.client_id == "prometheus:default"

    def test_import_webhook_provider_from_package(self):
        from message_provider import WebhookProvider

        assert hasattr(WebhookProvider, "register_message_listener")
