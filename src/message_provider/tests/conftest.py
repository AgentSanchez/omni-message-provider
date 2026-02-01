"""Pytest configuration and shared fixtures."""

import pytest
import logging


@pytest.fixture(autouse=True)
def setup_logging():
    """Setup logging for tests."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


@pytest.fixture
def mock_message_data():
    """Fixture for mock message data."""
    return {
        'message_id': 'test_msg_123',
        'text': 'Test message',
        'user_id': 'user_123',
        'channel': 'channel_456',
        'metadata': {
            'client_id': 'test:client',
            'timestamp': '2024-01-01T00:00:00Z'
        }
    }
