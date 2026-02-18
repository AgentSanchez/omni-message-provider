"""Tests for WebhookProvider abstract base class."""

import pytest
from fastapi import FastAPI


class TestWebhookProviderABC:
    """Tests that WebhookProvider enforces the ABC contract."""

    def test_cannot_instantiate_directly(self):
        from message_provider.webhook_provider import WebhookProvider

        with pytest.raises(TypeError):
            WebhookProvider()

    def test_must_implement_register_message_listener(self):
        from message_provider.webhook_provider import WebhookProvider

        class IncompleteProvider(WebhookProvider):
            def start(self): pass
            def get_formatting_rules(self): return "plaintext"
            def get_app(self): return FastAPI()

        with pytest.raises(TypeError):
            IncompleteProvider()

    def test_must_implement_start(self):
        from message_provider.webhook_provider import WebhookProvider

        class IncompleteProvider(WebhookProvider):
            def register_message_listener(self, callback): pass
            def get_formatting_rules(self): return "plaintext"
            def get_app(self): return FastAPI()

        with pytest.raises(TypeError):
            IncompleteProvider()

    def test_must_implement_get_formatting_rules(self):
        from message_provider.webhook_provider import WebhookProvider

        class IncompleteProvider(WebhookProvider):
            def register_message_listener(self, callback): pass
            def start(self): pass
            def get_app(self): return FastAPI()

        with pytest.raises(TypeError):
            IncompleteProvider()

    def test_must_implement_get_app(self):
        from message_provider.webhook_provider import WebhookProvider

        class IncompleteProvider(WebhookProvider):
            def register_message_listener(self, callback): pass
            def start(self): pass
            def get_formatting_rules(self): return "plaintext"

        with pytest.raises(TypeError):
            IncompleteProvider()

    def test_complete_implementation_works(self):
        from message_provider.webhook_provider import WebhookProvider

        class CompleteProvider(WebhookProvider):
            def register_message_listener(self, callback): pass
            def start(self): pass
            def get_formatting_rules(self): return "plaintext"
            def get_app(self): return FastAPI()

        provider = CompleteProvider()
        assert provider.get_formatting_rules() == "plaintext"
        assert isinstance(provider.get_app(), FastAPI)

    def test_is_not_subclass_of_message_provider(self):
        from message_provider.webhook_provider import WebhookProvider
        from message_provider.message_provider import MessageProvider

        assert not issubclass(WebhookProvider, MessageProvider)

    def test_abstract_methods_list(self):
        from message_provider.webhook_provider import WebhookProvider

        expected = {"register_message_listener", "start", "get_formatting_rules", "get_app"}
        assert WebhookProvider.__abstractmethods__ == expected
