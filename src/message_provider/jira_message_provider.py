import logging
import threading
import time
from typing import Optional, Callable, List, Set
from datetime import datetime, timedelta, timezone
from message_provider.message_provider import MessageProvider

log = logging.getLogger(__name__)

try:
    from jira import JIRA
    from jira.exceptions import JIRAError
    _JIRA_AVAILABLE = True
except ImportError:
    JIRA = None
    JIRAError = None
    _JIRA_AVAILABLE = False


class JiraMessageProvider(MessageProvider):
    """
    Jira implementation of MessageProvider using polling.

    Polls Jira for:
    - New issues in specified projects
    - New comments on tickets with specific labels
    - New comments containing trigger phrases

    Args:
        server: Jira server URL (e.g., "https://your-company.atlassian.net")
        email: Jira user email
        api_token: Jira API token (create at https://id.atlassian.com/manage-profile/security/api-tokens)
        project_keys: List of project keys to monitor for new issues (e.g., ["SUPPORT", "BUG"])
        client_id: Unique identifier for this Jira instance (e.g., "jira:main")
        watch_labels: List of labels to monitor for comments (e.g., ["bot-watching"]). Default: []
        trigger_phrases: List of phrases in comments to trigger notifications (e.g., ["@bot"]). Default: []
        poll_interval: Seconds between polls. Default: 60
        initial_lookback: Minutes to look back on first poll. Default: 1440 (24 hours)
        ignore_existing_on_startup: If True, ignore issues/comments created before startup. Default: True

    Usage:
        provider = JiraMessageProvider(
            server="https://company.atlassian.net",
            email="bot@company.com",
            api_token="YOUR_API_TOKEN",
            project_keys=["SUPPORT", "BUG"],
            client_id="jira:main",
            watch_labels=["bot-watching"],
            trigger_phrases=["@bot", "escalate"],
            poll_interval=60
        )
        provider.register_message_listener(my_handler)
        provider.start()
    """

    def __init__(
        self,
        server: str,
        email: str,
        api_token: str,
        project_keys: List[str],
        client_id: str,
        watch_labels: Optional[List[str]] = None,
        trigger_phrases: Optional[List[str]] = None,
        poll_interval: int = 60,
        initial_lookback: int = 1440,
        ignore_existing_on_startup: bool = True
    ):
        super().__init__()

        if not _JIRA_AVAILABLE:
            raise ImportError(
                "jira library is required for JiraMessageProvider. "
                "Install with: pip install omni-message-provider[jira]"
            )

        if not server:
            raise ValueError("server is required")
        if not email:
            raise ValueError("email is required")
        if not api_token:
            raise ValueError("api_token is required")
        if not project_keys:
            raise ValueError("At least one project_key is required")
        if not client_id:
            raise ValueError("client_id is required")

        self.server = server
        self.email = email
        self.api_token = api_token
        self.project_keys = project_keys
        self.client_id = client_id
        self.watch_labels = watch_labels or []
        self.trigger_phrases = trigger_phrases or []
        self.poll_interval = poll_interval
        self.initial_lookback = initial_lookback
        self.ignore_existing_on_startup = ignore_existing_on_startup
        self.startup_time = datetime.utcnow()

        # Connect to Jira
        try:
            self.jira = JIRA(
                server=server,
                basic_auth=(email, api_token)
            )
            log.info(f"[JiraMessageProvider] Connected to {server}")
        except JIRAError as e:
            log.error(f"[JiraMessageProvider] Failed to connect to Jira: {e}")
            raise

        # Message listeners
        self.message_listeners: List[Callable] = []

        # Track seen issues and comments to avoid duplicates
        self.seen_issues: Set[str] = set()
        self.seen_comments: Set[str] = set()  # Format: "ISSUE-123#comment-456"

        # Last poll time
        self.last_poll_time: Optional[datetime] = None

        # Polling thread
        self.polling_thread: Optional[threading.Thread] = None
        self.running = False

        log.info(f"[JiraMessageProvider] Initialized")
        log.info(f"  Projects: {', '.join(project_keys)}")
        if self.watch_labels:
            log.info(f"  Watch labels: {', '.join(self.watch_labels)}")
        if self.trigger_phrases:
            log.info(f"  Trigger phrases: {', '.join(self.trigger_phrases)}")
        if self.ignore_existing_on_startup:
            log.info(f"  Ignore existing issues/comments before: {self.startup_time.isoformat()}Z")

    @staticmethod
    def _parse_jira_datetime(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")
        except ValueError:
            try:
                return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S%z")
            except ValueError:
                return None

    def _log_available_statuses(self):
        """Log available status transitions for issues in tracked projects."""
        for project_key in self.project_keys:
            try:
                issues = self.jira.search_issues(
                    f'project = "{project_key}" ORDER BY updated DESC',
                    maxResults=1
                )
                if not issues:
                    log.info(f"[JiraMessageProvider] Project {project_key}: no issues found; cannot determine statuses")
                    continue

                issue = issues[0]
                transitions = self.jira.transitions(issue)
                statuses = [t.get("name", "") for t in transitions if t.get("name")]

                if statuses:
                    log.info(
                        f"[JiraMessageProvider] Project {project_key} statuses "
                        f"(from issue {issue.key}): {', '.join(statuses)}"
                    )
                else:
                    log.info(
                        f"[JiraMessageProvider] Project {project_key} statuses "
                        f"(from issue {issue.key}): none available"
                    )
            except JIRAError as e:
                log.warning(f"[JiraMessageProvider] Failed to fetch statuses for {project_key}: {e}")
    def register_message_listener(self, callback: Callable):
        """
        Register a callback function to be called when new issues are found.

        Args:
            callback: Function that takes a message dict as parameter
        """
        if not callable(callback):
            raise ValueError("Callback must be a callable function")

        self.message_listeners.append(callback)
        log.info(f"[JiraMessageProvider] Registered message listener")

    def _notify_listeners(self, message_data: dict):
        """Notify all registered message listeners."""
        for listener in self.message_listeners:
            try:
                listener(message_data)
            except Exception as e:
                log.error(f"[JiraMessageProvider] Listener error: {str(e)}")

    def _build_jql(self, previous_poll_time: Optional[datetime]) -> str:
        """Build JQL query for polling."""
        # Build project filter
        project_filter = " OR ".join([f'project = "{key}"' for key in self.project_keys])

        # Time filter
        if previous_poll_time is None:
            # First poll - look back initial_lookback minutes
            minutes = self.initial_lookback
            time_filter = f"created >= -{minutes}m"
        else:
            # Subsequent polls - look back since last poll (with 1 min buffer)
            minutes = int((datetime.utcnow() - previous_poll_time).total_seconds() / 60) + 1
            time_filter = f"created >= -{minutes}m"

        jql = f"({project_filter}) AND {time_filter} ORDER BY created ASC"
        return jql

    def _poll_issues(self, previous_poll_time: Optional[datetime]):
        """Poll Jira for new issues."""
        try:
            jql = self._build_jql(previous_poll_time)
            log.debug(f"[JiraMessageProvider] Polling with JQL: {jql}")

            # Search for issues
            issues = self.jira.search_issues(jql, maxResults=100)

            new_issues_count = 0
            for issue in issues:
                # Skip if already seen
                if issue.key in self.seen_issues:
                    continue
                issue_created = self._parse_jira_datetime(issue.fields.created)
                if issue_created:
                    issue_created_utc = issue_created.astimezone(timezone.utc).replace(tzinfo=None)
                    if self.ignore_existing_on_startup and issue_created_utc <= self.startup_time:
                        self.seen_issues.add(issue.key)
                        continue

                # Mark as seen
                self.seen_issues.add(issue.key)
                new_issues_count += 1

                # Convert to message format
                message_data = self._issue_to_message(issue)

                # Notify listeners
                log.info(f"[JiraMessageProvider] New issue: {issue.key}")
                self._notify_listeners(message_data)

            if new_issues_count > 0:
                log.info(f"[JiraMessageProvider] Processed {new_issues_count} new issue(s)")

        except JIRAError as e:
            log.error(f"[JiraMessageProvider] Jira API error: {e}")
        except Exception as e:
            log.error(f"[JiraMessageProvider] Polling error: {str(e)}")

    def _issue_to_message(self, issue) -> dict:
        """Convert Jira issue to message format."""
        # Build message text
        summary = issue.fields.summary
        description = issue.fields.description or "(No description)"
        text = f"{summary}\n\n{description}"

        # Extract metadata
        reporter = issue.fields.reporter
        project = issue.fields.project

        message_data = {
            "type": "new_issue",
            "message_id": issue.key,
            "text": text,
            "user_id": reporter.accountId if reporter else "unknown",
            "channel": issue.key,  # Channel = the ticket itself
            "metadata": {
                "client_id": self.client_id,
                "issue_key": issue.key,
                "project": project.key,
                "project_name": project.name,
                "issue_type": issue.fields.issuetype.name,
                "priority": issue.fields.priority.name if issue.fields.priority else "None",
                "status": issue.fields.status.name,
                "labels": issue.fields.labels,
                "reporter_name": reporter.displayName if reporter else "Unknown",
                "reporter_email": reporter.emailAddress if reporter and hasattr(reporter, 'emailAddress') else None,
                "created": issue.fields.created,
                "url": f"{self.server}/browse/{issue.key}"
            }
        }

        return message_data

    def _poll_comments(self, previous_poll_time: Optional[datetime]):
        """Poll Jira for new comments on watched tickets or with trigger phrases."""
        if not self.watch_labels and not self.trigger_phrases:
            return  # Nothing to poll

        try:
            # Build JQL for watched labels
            jql_parts = []

            if self.watch_labels:
                label_filter = " OR ".join([f'labels = "{label}"' for label in self.watch_labels])
                jql_parts.append(f"({label_filter})")

            if self.trigger_phrases:
                # For trigger phrases, we need to check all updated issues in projects
                project_filter = " OR ".join([f'project = "{key}"' for key in self.project_keys])
                jql_parts.append(f"({project_filter})")

            # Combine with OR
            if len(jql_parts) == 0:
                return

            jql_base = " OR ".join(jql_parts)

            # Add time filter
            if previous_poll_time is None:
                minutes = self.initial_lookback
            else:
                minutes = int((datetime.utcnow() - previous_poll_time).total_seconds() / 60) + 1

            jql = f"({jql_base}) AND updated >= -{minutes}m ORDER BY updated ASC"
            log.debug(f"[JiraMessageProvider] Polling comments with JQL: {jql}")

            # Search for issues
            issues = self.jira.search_issues(jql, maxResults=100, expand='changelog')

            new_comments_count = 0
            for issue in issues:
                # Get comments
                comments = self.jira.comments(issue.key)

                for comment in comments:
                    comment_key = f"{issue.key}#comment-{comment.id}"

                    # Skip if already seen
                    if comment_key in self.seen_comments:
                        continue

                    # Check if comment is recent enough
                    comment_created = self._parse_jira_datetime(comment.created)
                    if comment_created is None:
                        log.warning(f"[JiraMessageProvider] Unable to parse comment time for {comment_key}")
                        continue
                    comment_created_utc = comment_created.astimezone(timezone.utc).replace(tzinfo=None)
                    if self.ignore_existing_on_startup and comment_created_utc <= self.startup_time:
                        self.seen_comments.add(comment_key)
                        continue
                    if previous_poll_time and comment_created_utc < previous_poll_time:
                        continue

                    # Check if matches criteria
                    matches = False
                    matched_label = None
                    matched_phrase = None

                    # Check watch labels
                    if self.watch_labels:
                        issue_labels = set(issue.fields.labels or [])
                        for label in self.watch_labels:
                            if label in issue_labels:
                                matches = True
                                matched_label = label
                                break

                    # Check trigger phrases
                    if self.trigger_phrases and not matches:
                        comment_body = comment.body.lower()
                        for phrase in self.trigger_phrases:
                            if phrase.lower() in comment_body:
                                matches = True
                                matched_phrase = phrase
                                break

                    if not matches:
                        continue

                    # Mark as seen
                    self.seen_comments.add(comment_key)
                    new_comments_count += 1

                    # Convert to message format
                    message_data = {
                        "type": "new_comment",
                        "message_id": comment_key,
                        "text": comment.body,
                        "user_id": comment.author.accountId if comment.author else "unknown",
                        "channel": issue.key,  # Channel = the ticket
                        "metadata": {
                            "client_id": self.client_id,
                            "comment_id": str(comment.id),
                            "issue_key": issue.key,
                            "issue_summary": issue.fields.summary,
                            "project": issue.fields.project.key,
                            "matched_label": matched_label,
                            "matched_phrase": matched_phrase,
                            "author_name": comment.author.displayName if comment.author else "Unknown",
                            "created": comment.created,
                            "url": f"{self.server}/browse/{issue.key}?focusedCommentId={comment.id}"
                        }
                    }

                    # Notify listeners
                    log.info(f"[JiraMessageProvider] New comment on {issue.key} by {message_data['metadata']['author_name']}")
                    self._notify_listeners(message_data)

            if new_comments_count > 0:
                log.info(f"[JiraMessageProvider] Processed {new_comments_count} new comment(s)")

        except JIRAError as e:
            log.error(f"[JiraMessageProvider] Jira API error while polling comments: {e}")
        except Exception as e:
            log.error(f"[JiraMessageProvider] Error polling comments: {str(e)}")

    def _polling_loop(self):
        """Main polling loop running in background thread."""
        log.info(f"[JiraMessageProvider] Polling started (interval: {self.poll_interval}s)")

        while self.running:
            try:
                poll_start = datetime.utcnow()
                previous_poll_time = self.last_poll_time
                self._poll_issues(previous_poll_time)
                self._poll_comments(previous_poll_time)
                self.last_poll_time = poll_start
            except Exception as e:
                log.error(f"[JiraMessageProvider] Unexpected error in polling loop: {str(e)}")

            # Sleep until next poll
            time.sleep(self.poll_interval)

    def send_message(
        self,
        message: str,
        user_id: str,
        channel: Optional[str] = None,
        previous_message_id: Optional[str] = None
    ) -> dict:
        """
        Add a comment to a Jira issue.

        Args:
            message: Comment text
            user_id: Not used (Jira uses authenticated user)
            channel: Jira issue key (e.g., "SUPPORT-123")
            previous_message_id: Not used (kept for interface compatibility)

        Returns:
            Dict with comment metadata
        """
        if not channel:
            log.error("[JiraMessageProvider] send_message requires channel (issue key)")
            return {"success": False, "error": "Issue key required in channel parameter"}

        try:
            # Add comment to issue
            comment = self.jira.add_comment(channel, message)

            log.info(f"[JiraMessageProvider] Added comment to {channel}")

            return {
                "success": True,
                "message_id": str(comment.id),
                "issue_key": channel,
                "comment_id": str(comment.id)
            }

        except JIRAError as e:
            log.error(f"[JiraMessageProvider] Failed to add comment: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def send_reaction(self, message_id: str, reaction: str) -> dict:
        """
        Add a label to a Jira issue.

        Args:
            message_id: Jira issue key (e.g., "SUPPORT-123")
            reaction: Label to add (e.g., "bot-processed", "acknowledged")

        Returns:
            Dict with success status
        """
        try:
            # Get issue
            issue = self.jira.issue(message_id)

            # Add label
            current_labels = issue.fields.labels
            if reaction not in current_labels:
                current_labels.append(reaction)
                issue.update(fields={'labels': current_labels})
                log.info(f"[JiraMessageProvider] Added label '{reaction}' to {message_id}")
            else:
                log.debug(f"[JiraMessageProvider] Label '{reaction}' already exists on {message_id}")

            return {
                "success": True,
                "message_id": message_id,
                "label": reaction
            }

        except JIRAError as e:
            log.error(f"[JiraMessageProvider] Failed to add label: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def update_message(self, message_id: str, new_text: str) -> dict:
        """
        Update a Jira ticket's status.

        Args:
            message_id: Jira issue key (e.g., "SUPPORT-123")
            new_text: New status name (e.g., "In Progress", "Done", "Closed")

        Returns:
            Dict with success status
        """
        try:
            # Get the issue
            issue = self.jira.issue(message_id)

            # Get available transitions
            transitions = self.jira.transitions(issue)

            # Find matching transition
            transition_id = None
            for transition in transitions:
                if transition['name'].lower() == new_text.lower():
                    transition_id = transition['id']
                    break

            if transition_id is None:
                available = [t['name'] for t in transitions]
                log.error(f"[JiraMessageProvider] Status '{new_text}' not available for {message_id}. Available: {available}")
                return {
                    "success": False,
                    "error": f"Status '{new_text}' not available",
                    "available_statuses": available
                }

            # Transition the issue
            self.jira.transition_issue(issue, transition_id)

            log.info(f"[JiraMessageProvider] Updated {message_id} status to '{new_text}'")

            return {
                "success": True,
                "message_id": message_id,
                "new_status": new_text
            }

        except JIRAError as e:
            log.error(f"[JiraMessageProvider] Failed to update status: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def start(self):
        """
        Start polling for Jira issues.

        This is a blocking call that runs until stopped.
        """
        if self.running:
            log.warning("[JiraMessageProvider] Already running")
            return

        self._log_available_statuses()

        self.running = True

        # Start polling thread
        self.polling_thread = threading.Thread(target=self._polling_loop, daemon=True)
        self.polling_thread.start()

        log.info("[JiraMessageProvider] Started")

        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("[JiraMessageProvider] Interrupted by user")
            self.stop()

    def stop(self):
        """Stop polling."""
        log.info("[JiraMessageProvider] Stopping...")
        self.running = False

        if self.polling_thread:
            self.polling_thread.join(timeout=5)

        log.info("[JiraMessageProvider] Stopped")
