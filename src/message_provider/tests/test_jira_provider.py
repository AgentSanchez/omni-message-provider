"""Tests for JiraMessageProvider."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime


class TestJiraMessageProvider:
    """Test cases for JiraMessageProvider."""

    def test_init_requires_server(self):
        """Test that server is required."""
        from message_provider.jira_message_provider import JiraMessageProvider

        with pytest.raises(ValueError, match="server is required"):
            JiraMessageProvider(
                server="",
                email="test@example.com",
                api_token="token123",
                project_keys=["PROJECT"],
                client_id="jira:test"
            )

    def test_init_requires_email(self):
        """Test that email is required."""
        from message_provider.jira_message_provider import JiraMessageProvider

        with pytest.raises(ValueError, match="email is required"):
            JiraMessageProvider(
                server="https://jira.example.com",
                email="",
                api_token="token123",
                project_keys=["PROJECT"],
                client_id="jira:test"
            )

    def test_init_requires_api_token(self):
        """Test that api_token is required."""
        from message_provider.jira_message_provider import JiraMessageProvider

        with pytest.raises(ValueError, match="api_token is required"):
            JiraMessageProvider(
                server="https://jira.example.com",
                email="test@example.com",
                api_token="",
                project_keys=["PROJECT"],
                client_id="jira:test"
            )

    def test_init_requires_project_keys(self):
        """Test that project_keys is required."""
        from message_provider.jira_message_provider import JiraMessageProvider

        with pytest.raises(ValueError, match="At least one project_key is required"):
            JiraMessageProvider(
                server="https://jira.example.com",
                email="test@example.com",
                api_token="token123",
                project_keys=[],
                client_id="jira:test"
            )

    def test_init_requires_client_id(self):
        """Test that client_id is required."""
        from message_provider.jira_message_provider import JiraMessageProvider

        with pytest.raises(ValueError, match="client_id is required"):
            JiraMessageProvider(
                server="https://jira.example.com",
                email="test@example.com",
                api_token="token123",
                project_keys=["PROJECT"],
                client_id=""
            )

    @patch('message_provider.jira_message_provider.JIRA')
    def test_init_success(self, mock_jira_class):
        """Test successful initialization."""
        from message_provider.jira_message_provider import JiraMessageProvider

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test",
            watch_labels=["bot-watching"],
            trigger_phrases=["@bot"]
        )

        assert provider.server == "https://jira.example.com"
        assert provider.email == "test@example.com"
        assert provider.client_id == "jira:test"
        assert provider.project_keys == ["PROJECT"]
        assert provider.watch_labels == ["bot-watching"]
        assert provider.trigger_phrases == ["@bot"]
        assert provider.poll_interval == 60

    @patch('message_provider.jira_message_provider.JIRA')
    def test_register_message_listener(self, mock_jira_class):
        """Test registering a message listener."""
        from message_provider.jira_message_provider import JiraMessageProvider

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test"
        )

        def handler(message):
            pass

        provider.register_message_listener(handler)
        assert len(provider.message_listeners) == 1

    @patch('message_provider.jira_message_provider.JIRA')
    def test_send_message_adds_comment(self, mock_jira_class):
        """Test that send_message adds a comment to a Jira issue."""
        from message_provider.jira_message_provider import JiraMessageProvider

        mock_jira = MagicMock()
        mock_jira_class.return_value = mock_jira
        mock_jira.add_comment.return_value = MagicMock(id='12345')

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test"
        )

        result = provider.send_message(
            message="Test comment",
            user_id="user123",
            channel="PROJECT-123"
        )

        assert result['success'] is True
        mock_jira.add_comment.assert_called_once_with("PROJECT-123", "Test comment")

    @patch('message_provider.jira_message_provider.JIRA')
    def test_send_reaction_adds_label(self, mock_jira_class):
        """Test that send_reaction adds a label to a Jira issue."""
        from message_provider.jira_message_provider import JiraMessageProvider

        mock_jira = MagicMock()
        mock_jira_class.return_value = mock_jira
        mock_issue = MagicMock()
        mock_issue.fields.labels = []
        mock_jira.issue.return_value = mock_issue

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test"
        )

        result = provider.send_reaction(
            message_id="PROJECT-123",
            reaction="approved"
        )

        assert result['success'] is True
        mock_issue.update.assert_called_once()

    @patch('message_provider.jira_message_provider.JIRA')
    def test_update_message_changes_status(self, mock_jira_class):
        """Test that update_message changes issue status."""
        from message_provider.jira_message_provider import JiraMessageProvider

        mock_jira = MagicMock()
        mock_jira_class.return_value = mock_jira

        # Mock the issue object
        mock_issue = MagicMock()
        mock_jira.issue.return_value = mock_issue

        # Mock transitions to include "In Progress"
        mock_jira.transitions.return_value = [
            {'id': '21', 'name': 'In Progress'},
            {'id': '31', 'name': 'Done'}
        ]

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test"
        )

        result = provider.update_message(
            message_id="PROJECT-123",
            new_text="In Progress"
        )

        assert result['success'] is True
        mock_jira.issue.assert_called_once_with("PROJECT-123")
        mock_jira.transitions.assert_called_once_with(mock_issue)
        mock_jira.transition_issue.assert_called_once_with(mock_issue, '21')
