"""Tests for JiraMessageProvider."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timezone


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

    @patch('message_provider.jira_message_provider.JIRA')
    def test_register_reaction_listener_noop(self, mock_jira_class):
        """Test that register_reaction_listener is a no-op for Jira."""
        from message_provider.jira_message_provider import JiraMessageProvider

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test"
        )

        # Should not raise, just silently ignore
        provider.register_reaction_listener(lambda r: None)

        # Jira doesn't store reaction listeners (no-op)
        assert not hasattr(provider, 'reaction_listeners') or len(getattr(provider, 'reaction_listeners', [])) == 0

    @patch('message_provider.jira_message_provider.JIRA')
    def test_startup_delay_param_stored(self, mock_jira_class):
        """Test that startup_delay param is accepted and stored."""
        from message_provider.jira_message_provider import JiraMessageProvider

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test",
            startup_delay=300
        )
        assert provider.startup_delay == 300

    @patch('message_provider.jira_message_provider.JIRA')
    def test_startup_delay_default(self, mock_jira_class):
        """Test that startup_delay defaults to 120."""
        from message_provider.jira_message_provider import JiraMessageProvider

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test"
        )
        assert provider.startup_delay == 120

    @patch('message_provider.jira_message_provider.JIRA')
    def test_seen_issue_ids_prevent_redispatch(self, mock_jira_class):
        """Test that seen issue IDs prevent re-dispatch."""
        from message_provider.jira_message_provider import JiraMessageProvider

        mock_jira = MagicMock()
        mock_jira_class.return_value = mock_jira

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test",
            ignore_existing_on_startup=False,
            startup_delay=0
        )

        # Create a mock issue
        mock_issue = MagicMock()
        mock_issue.key = "PROJECT-1"
        mock_issue.fields.created = "2099-01-01T00:00:01.000+0000"
        mock_issue.fields.summary = "Test"
        mock_issue.fields.description = "Desc"
        mock_issue.fields.reporter = MagicMock(accountId="u1", displayName="User", emailAddress="u@e.com")
        mock_issue.fields.project = MagicMock(key="PROJECT", name="Project")
        mock_issue.fields.issuetype = MagicMock(name="Bug")
        mock_issue.fields.priority = MagicMock(name="Medium")
        mock_issue.fields.status = MagicMock(name="Open")
        mock_issue.fields.labels = []

        mock_jira.search_issues.return_value = [mock_issue]

        listener = MagicMock()
        provider.register_message_listener(listener)

        # First poll: should dispatch
        provider._poll_issues(None)
        assert listener.call_count == 1
        assert "PROJECT-1" in provider._seen_issue_ids

        # Second poll: same issue should be skipped
        provider._poll_issues(None)
        assert listener.call_count == 1  # still 1

    @patch('message_provider.jira_message_provider.JIRA')
    def test_seen_comment_ids_prevent_redispatch(self, mock_jira_class):
        """Test that seen comment IDs prevent re-dispatch."""
        from message_provider.jira_message_provider import JiraMessageProvider

        mock_jira = MagicMock()
        mock_jira_class.return_value = mock_jira

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test",
            watch_labels=["bot-watching"],
            ignore_existing_on_startup=False,
            startup_delay=0
        )

        # Create mock issue with label
        mock_issue = MagicMock()
        mock_issue.key = "PROJECT-1"
        mock_issue.fields.labels = ["bot-watching"]
        mock_issue.fields.summary = "Test"
        mock_issue.fields.project = MagicMock(key="PROJECT")

        mock_comment = MagicMock()
        mock_comment.id = "99"
        mock_comment.created = "2099-01-01T00:00:01.000+0000"
        mock_comment.body = "Hello"
        mock_comment.author = MagicMock(accountId="u1", displayName="User")

        mock_jira.search_issues.return_value = [mock_issue]
        mock_jira.comments.return_value = [mock_comment]

        listener = MagicMock()
        provider.register_message_listener(listener)

        # First poll
        provider._poll_comments(None)
        assert listener.call_count == 1
        assert "PROJECT-1#comment-99" in provider._seen_comment_ids

        # Second poll: same comment should be skipped
        provider._poll_comments(None)
        assert listener.call_count == 1

    def test_init_invalid_trigger_mode(self):
        """Test that invalid trigger_mode raises ValueError."""
        from message_provider.jira_message_provider import JiraMessageProvider

        with pytest.raises(ValueError, match="trigger_mode must be"):
            JiraMessageProvider(
                server="https://jira.example.com",
                email="test@example.com",
                api_token="token123",
                project_keys=["PROJECT"],
                client_id="jira:test",
                trigger_mode="invalid"
            )

    @patch('message_provider.jira_message_provider.JIRA')
    def test_trigger_mode_stored(self, mock_jira_class):
        """Test that trigger_mode is stored correctly."""
        from message_provider.jira_message_provider import JiraMessageProvider

        for mode in ("mention", "chat", "both"):
            provider = JiraMessageProvider(
                server="https://jira.example.com",
                email="test@example.com",
                api_token="token123",
                project_keys=["PROJECT"],
                client_id="jira:test",
                trigger_mode=mode
            )
            assert provider.trigger_mode == mode

    @patch('message_provider.jira_message_provider.JIRA')
    def test_trigger_mode_default(self, mock_jira_class):
        """Test that trigger_mode defaults to 'both'."""
        from message_provider.jira_message_provider import JiraMessageProvider

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test"
        )
        assert provider.trigger_mode == "both"

    @patch('message_provider.jira_message_provider.JIRA')
    def test_mention_mode_skips_issues_without_trigger_phrase(self, mock_jira_class):
        """Test that mention mode skips issues without trigger phrases."""
        from message_provider.jira_message_provider import JiraMessageProvider

        mock_jira = MagicMock()
        mock_jira_class.return_value = mock_jira

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test",
            trigger_phrases=["@bot"],
            trigger_mode="mention",
            ignore_existing_on_startup=False,
            startup_delay=0
        )

        mock_issue = MagicMock()
        mock_issue.key = "PROJECT-1"
        mock_issue.fields.created = "2099-01-01T00:00:01.000+0000"
        mock_issue.fields.summary = "Normal issue"
        mock_issue.fields.description = "No trigger here"
        mock_issue.fields.reporter = MagicMock(accountId="u1", displayName="User", emailAddress="u@e.com")
        mock_issue.fields.project = MagicMock(key="PROJECT", name="Project")
        mock_issue.fields.issuetype = MagicMock(name="Bug")
        mock_issue.fields.priority = MagicMock(name="Medium")
        mock_issue.fields.status = MagicMock(name="Open")
        mock_issue.fields.labels = []

        mock_jira.search_issues.return_value = [mock_issue]

        listener = MagicMock()
        provider.register_message_listener(listener)

        provider._poll_issues(None)
        assert listener.call_count == 0

    @patch('message_provider.jira_message_provider.JIRA')
    def test_mention_mode_dispatches_issues_with_trigger_phrase(self, mock_jira_class):
        """Test that mention mode dispatches issues with trigger phrase in summary."""
        from message_provider.jira_message_provider import JiraMessageProvider

        mock_jira = MagicMock()
        mock_jira_class.return_value = mock_jira

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test",
            trigger_phrases=["@bot"],
            trigger_mode="mention",
            ignore_existing_on_startup=False,
            startup_delay=0
        )

        mock_issue = MagicMock()
        mock_issue.key = "PROJECT-2"
        mock_issue.fields.created = "2099-01-01T00:00:01.000+0000"
        mock_issue.fields.summary = "Hey @bot please help"
        mock_issue.fields.description = "Some description"
        mock_issue.fields.reporter = MagicMock(accountId="u1", displayName="User", emailAddress="u@e.com")
        mock_issue.fields.project = MagicMock(key="PROJECT", name="Project")
        mock_issue.fields.issuetype = MagicMock(name="Bug")
        mock_issue.fields.priority = MagicMock(name="Medium")
        mock_issue.fields.status = MagicMock(name="Open")
        mock_issue.fields.labels = []

        mock_jira.search_issues.return_value = [mock_issue]

        listener = MagicMock()
        provider.register_message_listener(listener)

        provider._poll_issues(None)
        assert listener.call_count == 1

    @patch('message_provider.jira_message_provider.JIRA')
    def test_mention_mode_skips_label_only_comments(self, mock_jira_class):
        """Test that mention mode skips comments matched only by label (no phrase)."""
        from message_provider.jira_message_provider import JiraMessageProvider

        mock_jira = MagicMock()
        mock_jira_class.return_value = mock_jira

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test",
            watch_labels=["bot-watching"],
            trigger_phrases=["@bot"],
            trigger_mode="mention",
            ignore_existing_on_startup=False,
            startup_delay=0
        )

        mock_issue = MagicMock()
        mock_issue.key = "PROJECT-1"
        mock_issue.fields.labels = ["bot-watching"]
        mock_issue.fields.summary = "Test"
        mock_issue.fields.project = MagicMock(key="PROJECT")

        mock_comment = MagicMock()
        mock_comment.id = "100"
        mock_comment.created = "2099-01-01T00:00:01.000+0000"
        mock_comment.body = "Just a regular comment"
        mock_comment.author = MagicMock(accountId="u1", displayName="User")

        mock_jira.search_issues.return_value = [mock_issue]
        mock_jira.comments.return_value = [mock_comment]

        listener = MagicMock()
        provider.register_message_listener(listener)

        provider._poll_comments(None)
        assert listener.call_count == 0

    @patch('message_provider.jira_message_provider.JIRA')
    def test_mention_mode_dispatches_comments_with_trigger_phrase(self, mock_jira_class):
        """Test that mention mode dispatches comments containing a trigger phrase."""
        from message_provider.jira_message_provider import JiraMessageProvider

        mock_jira = MagicMock()
        mock_jira_class.return_value = mock_jira

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test",
            watch_labels=["bot-watching"],
            trigger_phrases=["@bot"],
            trigger_mode="mention",
            ignore_existing_on_startup=False,
            startup_delay=0
        )

        mock_issue = MagicMock()
        mock_issue.key = "PROJECT-1"
        mock_issue.fields.labels = ["bot-watching"]
        mock_issue.fields.summary = "Test"
        mock_issue.fields.project = MagicMock(key="PROJECT")

        mock_comment = MagicMock()
        mock_comment.id = "101"
        mock_comment.created = "2099-01-01T00:00:01.000+0000"
        mock_comment.body = "Hey @bot can you help?"
        mock_comment.author = MagicMock(accountId="u1", displayName="User")

        mock_jira.search_issues.return_value = [mock_issue]
        mock_jira.comments.return_value = [mock_comment]

        listener = MagicMock()
        provider.register_message_listener(listener)

        provider._poll_comments(None)
        assert listener.call_count == 1

    @patch('message_provider.jira_message_provider.JIRA')
    def test_seen_set_capping(self, mock_jira_class):
        """Test that seen sets are capped at 10,000 entries."""
        from message_provider.jira_message_provider import JiraMessageProvider

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT"],
            client_id="jira:test",
            startup_delay=0
        )

        # Fill beyond cap
        for i in range(10_500):
            provider._seen_issue_ids.add(f"PROJECT-{i}")

        assert len(provider._seen_issue_ids) == 10_500

        provider._cap_seen_sets()

        assert len(provider._seen_issue_ids) <= 10_000


class TestJiraTriggerModeIntegration:
    """Scenario-style integration tests exercising the full trigger_mode matrix."""

    @staticmethod
    def _make_issue(key, summary, description, labels=None):
        issue = MagicMock()
        issue.key = key
        issue.fields.created = "2099-01-01T00:00:01.000+0000"
        issue.fields.summary = summary
        issue.fields.description = description
        issue.fields.reporter = MagicMock(
            accountId="u1", displayName="User", emailAddress="u@e.com"
        )
        project_key = key.split("-")[0]
        issue.fields.project = MagicMock(key=project_key, name=project_key)
        issue.fields.issuetype = MagicMock(name="Task")
        issue.fields.priority = MagicMock(name="Medium")
        issue.fields.status = MagicMock(name="Open")
        issue.fields.labels = labels or []
        return issue

    @staticmethod
    def _make_comment(comment_id, body):
        comment = MagicMock()
        comment.id = comment_id
        comment.created = "2099-01-01T00:00:02.000+0000"
        comment.body = body
        comment.author = MagicMock(accountId="u1", displayName="User")
        return comment

    @patch('message_provider.jira_message_provider.JIRA')
    def _make_provider(self, trigger_mode, mock_jira_class):
        from message_provider.jira_message_provider import JiraMessageProvider

        mock_jira = MagicMock()
        mock_jira_class.return_value = mock_jira

        provider = JiraMessageProvider(
            server="https://jira.example.com",
            email="test@example.com",
            api_token="token123",
            project_keys=["PROJECT", "SUPPORT"],
            client_id="jira:test",
            watch_labels=["bot-watching"],
            trigger_phrases=["@bot", "escalate"],
            trigger_mode=trigger_mode,
            ignore_existing_on_startup=False,
            startup_delay=0,
        )

        listener = MagicMock()
        provider.register_message_listener(listener)

        # -- Fake issues across two project keys --
        issues = [
            self._make_issue("PROJECT-1", "Hey @bot check this", "Some desc"),
            self._make_issue("PROJECT-2", "Plain summary", "No trigger here"),
            self._make_issue("SUPPORT-3", "Need help", "Please escalate this"),
            self._make_issue("SUPPORT-4", "Regular ticket", "Nothing special"),
        ]

        # -- Fake comments keyed by issue --
        comment_1a = self._make_comment("201", "just an update")
        comment_1b = self._make_comment("202", "hey @bot help")
        comment_3 = self._make_comment("203", "escalate this please")
        comment_4 = self._make_comment("204", "nothing special")

        # Issues for comment polling include label-bearing and project-bearing
        comment_issues = [
            self._make_issue("PROJECT-1", "Hey @bot check this", "Some desc",
                             labels=["bot-watching"]),
            self._make_issue("SUPPORT-3", "Need help", "Please escalate this"),
            self._make_issue("SUPPORT-4", "Regular ticket", "Nothing special"),
        ]

        comments_map = {
            "PROJECT-1": [comment_1a, comment_1b],
            "SUPPORT-3": [comment_3],
            "SUPPORT-4": [comment_4],
        }
        mock_jira.comments.side_effect = lambda key: comments_map.get(key, [])

        return provider, listener, mock_jira, issues, comment_issues

    def test_mention_mode_scenario(self):
        """mention: only phrase-matched issues (2) and phrase-matched comments (2)."""
        provider, listener, mock_jira, issues, comment_issues = self._make_provider("mention")

        # Poll issues — only phrase-matched ones dispatched
        mock_jira.search_issues.return_value = issues
        provider._poll_issues(None)
        assert listener.call_count == 2
        dispatched_keys = [call.args[0]["message_id"] for call in listener.call_args_list]
        assert dispatched_keys == ["PROJECT-1", "SUPPORT-3"]  # order matches input
        # Verify non-phrase issues were excluded
        assert "PROJECT-2" not in dispatched_keys
        assert "SUPPORT-4" not in dispatched_keys

        listener.reset_mock()

        # Poll comments — only phrase-containing comments, labels ignored
        mock_jira.search_issues.return_value = comment_issues
        provider._poll_comments(None)
        assert listener.call_count == 2
        dispatched_bodies = [call.args[0]["text"] for call in listener.call_args_list]
        assert dispatched_bodies == ["hey @bot help", "escalate this please"]
        # Verify label-only comment was excluded
        assert "just an update" not in dispatched_bodies
        # Verify no-match comment was excluded
        assert "nothing special" not in dispatched_bodies

    def test_chat_mode_scenario(self):
        """chat: all 4 issues dispatched; comments = 3 (label + phrase matches)."""
        provider, listener, mock_jira, issues, comment_issues = self._make_provider("chat")

        # Poll issues — all dispatched regardless of phrases
        mock_jira.search_issues.return_value = issues
        provider._poll_issues(None)
        assert listener.call_count == 4
        dispatched_keys = [call.args[0]["message_id"] for call in listener.call_args_list]
        assert dispatched_keys == ["PROJECT-1", "PROJECT-2", "SUPPORT-3", "SUPPORT-4"]

        listener.reset_mock()

        # Poll comments — label matches + phrase matches, but not "nothing special"
        mock_jira.search_issues.return_value = comment_issues
        provider._poll_comments(None)
        assert listener.call_count == 3
        dispatched_bodies = [call.args[0]["text"] for call in listener.call_args_list]
        assert dispatched_bodies == ["just an update", "hey @bot help", "escalate this please"]
        # Verify no-match comment was excluded
        assert "nothing special" not in dispatched_bodies

    def test_both_mode_scenario(self):
        """both (default): same as chat — all 4 issues, 3 comments."""
        provider, listener, mock_jira, issues, comment_issues = self._make_provider("both")

        # Poll issues — all dispatched
        mock_jira.search_issues.return_value = issues
        provider._poll_issues(None)
        assert listener.call_count == 4
        dispatched_keys = [call.args[0]["message_id"] for call in listener.call_args_list]
        assert dispatched_keys == ["PROJECT-1", "PROJECT-2", "SUPPORT-3", "SUPPORT-4"]

        listener.reset_mock()

        # Poll comments — label + phrase, excluding no-match
        mock_jira.search_issues.return_value = comment_issues
        provider._poll_comments(None)
        assert listener.call_count == 3
        dispatched_bodies = [call.args[0]["text"] for call in listener.call_args_list]
        assert dispatched_bodies == ["just an update", "hey @bot help", "escalate this please"]
        assert "nothing special" not in dispatched_bodies

    def test_mention_mode_dedup_across_polls(self):
        """mention: second poll does not re-dispatch already-seen items."""
        provider, listener, mock_jira, issues, comment_issues = self._make_provider("mention")

        # First poll
        mock_jira.search_issues.return_value = issues
        provider._poll_issues(None)
        assert listener.call_count == 2

        # Second poll with same data — nothing new
        provider._poll_issues(None)
        assert listener.call_count == 2  # unchanged

        listener.reset_mock()

        # First comment poll
        mock_jira.search_issues.return_value = comment_issues
        provider._poll_comments(None)
        assert listener.call_count == 2

        # Second comment poll — nothing new
        provider._poll_comments(None)
        assert listener.call_count == 2  # unchanged

    def test_chat_mode_dedup_across_polls(self):
        """chat: second poll does not re-dispatch already-seen items."""
        provider, listener, mock_jira, issues, comment_issues = self._make_provider("chat")

        mock_jira.search_issues.return_value = issues
        provider._poll_issues(None)
        assert listener.call_count == 4

        provider._poll_issues(None)
        assert listener.call_count == 4  # no new dispatches

        listener.reset_mock()

        mock_jira.search_issues.return_value = comment_issues
        provider._poll_comments(None)
        assert listener.call_count == 3

        provider._poll_comments(None)
        assert listener.call_count == 3  # no new dispatches

    def test_mention_mode_metadata_matches(self):
        """mention: dispatched comments carry correct matched_phrase metadata."""
        provider, listener, mock_jira, issues, comment_issues = self._make_provider("mention")

        mock_jira.search_issues.return_value = comment_issues
        provider._poll_comments(None)

        meta_by_text = {
            call.args[0]["text"]: call.args[0]["metadata"]
            for call in listener.call_args_list
        }
        # "@bot" phrase matched in "hey @bot help"
        assert meta_by_text["hey @bot help"]["matched_phrase"] == "@bot"
        assert meta_by_text["hey @bot help"]["matched_label"] is None
        # "escalate" phrase matched in "escalate this please"
        assert meta_by_text["escalate this please"]["matched_phrase"] == "escalate"
        assert meta_by_text["escalate this please"]["matched_label"] is None

    def test_chat_mode_metadata_matches(self):
        """chat: label-matched comments carry matched_label, phrase-only carry matched_phrase."""
        provider, listener, mock_jira, issues, comment_issues = self._make_provider("chat")

        mock_jira.search_issues.return_value = comment_issues
        provider._poll_comments(None)

        meta_by_text = {
            call.args[0]["text"]: call.args[0]["metadata"]
            for call in listener.call_args_list
        }
        # Label-only: "just an update" on labeled issue
        assert meta_by_text["just an update"]["matched_label"] == "bot-watching"
        assert meta_by_text["just an update"]["matched_phrase"] is None
        # Label takes precedence: "hey @bot help" on labeled issue matched via label first
        assert meta_by_text["hey @bot help"]["matched_label"] == "bot-watching"
        assert meta_by_text["hey @bot help"]["matched_phrase"] is None
        # Phrase-only: "escalate this please" on non-labeled issue
        assert meta_by_text["escalate this please"]["matched_phrase"] == "escalate"
        assert meta_by_text["escalate this please"]["matched_label"] is None
