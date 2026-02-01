#!/usr/bin/env python3
"""
Example usage of JiraMessageProvider.

Setup Instructions:
1. Get Jira API Token:
   - Go to https://id.atlassian.com/manage-profile/security/api-tokens
   - Click "Create API token"
   - Copy the token

2. Find your Jira server URL:
   - Example: https://your-company.atlassian.net

3. Identify project keys to monitor:
   - Go to your Jira project
   - Project key is in the URL: /projects/SUPPORT/...
   - Can monitor multiple: ["SUPPORT", "BUG", "TASK"]

4. Set environment variables:
   export JIRA_SERVER="https://your-company.atlassian.net"
   export JIRA_EMAIL="your-email@company.com"
   export JIRA_API_TOKEN="your-api-token"
   export JIRA_PROJECT_KEYS="SUPPORT,BUG"  # Comma-separated
   export JIRA_WATCH_LABELS="bot-watching,escalated"  # Optional
   export JIRA_TRIGGER_PHRASES="@bot,escalate"  # Optional

Usage:
    python -m message_provider.jira_example
"""

import os
from message_provider.jira_message_provider import JiraMessageProvider
from logzero import logger as log


def create_message_handler(provider):
    """
    Create a message handler with access to the provider instance.

    Args:
        provider: JiraMessageProvider instance

    Returns:
        Callable message handler function
    """
    def message_handler(message):
        """
        Handle new Jira issues and comments.

        Args:
            message: Dictionary containing:
                - type: "new_issue" or "new_comment"
                - message_id: Jira issue key or "ISSUE-123#comment-456"
                - text: Issue/comment text
                - user_id: Author account ID
                - channel: Issue key (the conversation thread)
                - metadata: Additional Jira-specific data
        """
        msg_type = message.get('type')
        message_id = message.get('message_id')
        text = message.get('text')
        channel = message.get('channel')  # The issue key
        metadata = message.get('metadata', {})

        if msg_type == 'new_issue':
            # Handle new issue
            log.info("=" * 60)
            log.info(f"NEW JIRA ISSUE: {message_id}")
            log.info("=" * 60)
            log.info(f"Project: {metadata.get('project_name')} ({metadata.get('project')})")
            log.info(f"Reporter: {metadata.get('reporter_name')}")
            log.info(f"Type: {metadata.get('issue_type')}")
            log.info(f"Priority: {metadata.get('priority')}")
            log.info(f"Status: {metadata.get('status')}")
            log.info(f"URL: {metadata.get('url')}")
            log.info("")
            log.info(f"Content:\n{text[:200]}...")
            log.info("=" * 60)

            # Example: Auto-respond to new issues
            response = provider.send_message(
                message="Thanks for submitting this issue! Our team will review it shortly.",
                user_id=message.get('user_id'),
                channel=channel  # Issue key
            )

            if response.get('success'):
                log.info(f"✓ Added auto-response comment to {channel}")

                # Example: Add a label to mark it as processed
                provider.send_reaction(channel, "bot-acknowledged")
                log.info(f"✓ Added 'bot-acknowledged' label to {channel}")

                # Example: Update ticket status to Something
                status_response = provider.update_message(channel, "Escalate")
                if status_response.get('success'):
                    log.info(f"✓ Updated {channel} status to 'Escalate'")
                else:
                    log.warning(f"✗ Failed to update status: {status_response.get('error')}")
            else:
                log.error(f"✗ Failed to respond: {response.get('error')}")

        elif msg_type == 'new_comment':
            # Handle new comment on watched ticket
            log.info("=" * 60)
            log.info(f"NEW COMMENT: {message_id}")
            log.info("=" * 60)
            log.info(f"Issue: {channel} - {metadata.get('issue_summary')}")
            log.info(f"Author: {metadata.get('author_name')}")
            if metadata.get('matched_label'):
                log.info(f"Matched label: {metadata.get('matched_label')}")
            if metadata.get('matched_phrase'):
                log.info(f"Matched phrase: {metadata.get('matched_phrase')}")
            log.info(f"URL: {metadata.get('url')}")
            log.info("")
            log.info(f"Comment:\n{text[:200]}...")
            log.info("=" * 60)

            # Example: Respond to comment
            response = provider.send_message(
                message=f"I saw your comment! Processing your request...",
                user_id=message.get('user_id'),
                channel=channel  # Issue key
            )

            if response.get('success'):
                log.info(f"✓ Added response comment to {channel}")
            else:
                log.error(f"✗ Failed to respond: {response.get('error')}")

        log.info("")

    return message_handler


def main():
    """Main function to run the Jira monitor."""
    try:
        # Load configuration from environment variables
        server = os.getenv("JIRA_SERVER")
        email = os.getenv("JIRA_EMAIL")
        api_token = os.getenv("JIRA_API_TOKEN")
        project_keys_str = os.getenv("JIRA_PROJECT_KEYS", "")
        watch_labels_str = os.getenv("JIRA_WATCH_LABELS", "")
        trigger_phrases_str = os.getenv("JIRA_TRIGGER_PHRASES", "")
        poll_interval = int(os.getenv("JIRA_POLL_INTERVAL", "60"))

        # Validate required configuration
        errors = []
        if not server:
            errors.append("JIRA_SERVER environment variable is required")
        if not email:
            errors.append("JIRA_EMAIL environment variable is required")
        if not api_token:
            errors.append("JIRA_API_TOKEN environment variable is required")
        if not project_keys_str:
            errors.append("JIRA_PROJECT_KEYS environment variable is required")

        if errors:
            for error in errors:
                log.error(error)
            log.error("\nSetup instructions:")
            log.error("1. Create API token at: https://id.atlassian.com/manage-profile/security/api-tokens")
            log.error("2. Set environment variables:")
            log.error('   export JIRA_SERVER="https://your-company.atlassian.net"')
            log.error('   export JIRA_EMAIL="your-email@company.com"')
            log.error('   export JIRA_API_TOKEN="your-api-token"')
            log.error('   export JIRA_PROJECT_KEYS="SUPPORT,BUG"')
            log.error('   export JIRA_WATCH_LABELS="bot-watching"  # Optional')
            log.error('   export JIRA_TRIGGER_PHRASES="@bot"  # Optional')
            return 1

        # Parse configuration
        project_keys = [k.strip() for k in project_keys_str.split(',') if k.strip()]
        watch_labels = [l.strip() for l in watch_labels_str.split(',') if l.strip()] if watch_labels_str else []
        trigger_phrases = [p.strip() for p in trigger_phrases_str.split(',') if p.strip()] if trigger_phrases_str else []

        log.info("=" * 60)
        log.info("Jira Message Provider - Issue & Comment Monitor")
        log.info("=" * 60)
        log.info(f"Server: {server}")
        log.info(f"Email: {email}")
        log.info(f"Projects: {', '.join(project_keys)}")
        if watch_labels:
            log.info(f"Watch Labels: {', '.join(watch_labels)}")
        if trigger_phrases:
            log.info(f"Trigger Phrases: {', '.join(trigger_phrases)}")
        log.info(f"Poll Interval: {poll_interval}s")
        log.info("=" * 60)
        log.info("")

        # Initialize Jira message provider
        provider = JiraMessageProvider(
            server=server,
            email=email,
            api_token=api_token,
            project_keys=project_keys,
            client_id=f"jira:{server.split('//')[1].split('.')[0]}",  # e.g., "jira:your-company"
            watch_labels=watch_labels,
            trigger_phrases=trigger_phrases,
            poll_interval=poll_interval,
            initial_lookback=1440  # Look back 24 hours on first run
        )

        # Register message handler
        handler = create_message_handler(provider)
        provider.register_message_listener(handler)

        log.info("Jira monitor is starting...")
        log.info(f"Monitoring projects: {', '.join(project_keys)}")
        if watch_labels:
            log.info(f"Watching for comments on tickets with labels: {', '.join(watch_labels)}")
        if trigger_phrases:
            log.info(f"Watching for comments containing: {', '.join(trigger_phrases)}")
        log.info(f"Polling every {poll_interval} seconds")
        log.info("")
        log.info("Waiting for new issues and comments...")
        log.info("(Press Ctrl+C to stop)")
        log.info("")

        # Start provider (blocking)
        provider.start()

    except ValueError as e:
        log.error(f"Configuration error: {e}")
        return 1
    except KeyboardInterrupt:
        log.info("\nShutting down...")
        return 0
    except Exception as e:
        log.error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
