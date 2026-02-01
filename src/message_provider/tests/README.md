# Tests

This directory contains tests for the message_provider package.

## Running Tests

Install test dependencies:

```bash
pip install -e ".[dev]"
```

Run all tests:

```bash
pytest
```

Run tests with coverage:

```bash
pytest --cov=message_provider --cov-report=html
```

Run specific test file:

```bash
pytest src/message_provider/tests/test_discord_provider.py
```

Run specific test:

```bash
pytest src/message_provider/tests/test_discord_provider.py::TestDiscordMessageProvider::test_init_success
```

## Test Structure

- `test_message_provider.py` - Tests for abstract base class
- `test_discord_provider.py` - Tests for Discord implementation
- `test_slack_provider.py` - Tests for Slack implementation
- `test_jira_provider.py` - Tests for Jira implementation
- `test_fastapi_provider.py` - Tests for FastAPI implementation
- `test_relay.py` - Tests for relay components (RelayHub, RelayMessageProvider, RelayClient)
- `conftest.py` - Shared fixtures and pytest configuration

## Writing Tests

Tests use pytest and follow these conventions:

- Mock external dependencies (Discord API, Slack API, Jira API, WebSocket connections)
- Test both success and error cases
- Use async fixtures for async tests with `@pytest.mark.asyncio`
- Use the `mock_message_data` fixture for consistent test data
