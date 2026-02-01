#!/usr/bin/env python3
"""
Test script to verify lazy imports work correctly.

This should work even without optional dependencies installed.
"""

def test_basic_imports():
    """Test that basic imports work without optional deps."""
    print("Testing basic imports...")

    # These should work without any optional dependencies
    from message_provider import MessageProvider
    print("✓ MessageProvider imported")

    from message_provider import FastAPIMessageProvider
    print("✓ FastAPIMessageProvider imported")

    from message_provider import RelayHub
    print("✓ RelayHub imported")

    from message_provider import RelayMessageProvider
    print("✓ RelayMessageProvider imported")

    from message_provider import RelayClient
    print("✓ RelayClient imported")

    print("\n✅ All basic imports successful!")


def test_lazy_imports():
    """Test that lazy imports are in __all__ and dir()."""
    print("\nTesting lazy imports are discoverable...")

    import message_provider

    # Check __all__
    assert 'SlackMessageProvider' in message_provider.__all__
    assert 'DiscordMessageProvider' in message_provider.__all__
    assert 'JiraMessageProvider' in message_provider.__all__
    print("✓ Lazy imports in __all__")

    # Check dir()
    assert 'SlackMessageProvider' in dir(message_provider)
    assert 'DiscordMessageProvider' in dir(message_provider)
    assert 'JiraMessageProvider' in dir(message_provider)
    print("✓ Lazy imports in dir()")

    print("\n✅ Lazy imports are discoverable!")


def test_optional_import_errors():
    """Test that optional imports give helpful error messages."""
    print("\nTesting optional import error messages...")

    import message_provider

    # Try to import optional providers (will fail if deps not installed)
    try:
        from message_provider import SlackMessageProvider
        print("⚠ SlackMessageProvider imported (slack-bolt installed)")
    except ImportError as e:
        assert "pip install omni-message-provider[slack]" in str(e)
        print("✓ SlackMessageProvider gives helpful error message")

    try:
        from message_provider import DiscordMessageProvider
        print("⚠ DiscordMessageProvider imported (discord.py installed)")
    except ImportError as e:
        assert "pip install omni-message-provider[discord]" in str(e)
        print("✓ DiscordMessageProvider gives helpful error message")

    try:
        from message_provider import JiraMessageProvider
        print("⚠ JiraMessageProvider imported (jira installed)")
    except ImportError as e:
        assert "pip install omni-message-provider[jira]" in str(e)
        print("✓ JiraMessageProvider gives helpful error message")

    print("\n✅ Error messages are helpful!")


if __name__ == '__main__':
    test_basic_imports()
    test_lazy_imports()
    test_optional_import_errors()
    print("\n" + "="*60)
    print("ALL TESTS PASSED!")
    print("="*60)
