"""Explicit provider registry. Third-party providers use the datasentry.providers entry point."""

from importlib.metadata import entry_points

from .anthropic import AnthropicProvider
from .base import ProviderNotConfigured, ProviderUnavailable, TextProvider
from .gemini import GeminiProvider
from .openai import OpenAIProvider

BUILTINS = {"openai": OpenAIProvider, "anthropic": AnthropicProvider, "gemini": GeminiProvider}


def available_providers() -> list[str]:
    return sorted(set(BUILTINS) | {point.name for point in entry_points(group="datasentry.providers")})


def get_provider(name: str) -> TextProvider:
    """Import only the explicitly selected plugin, never all installed plugins."""
    if name in BUILTINS:
        provider = BUILTINS[name]()
    else:
        matches = [point for point in entry_points(group="datasentry.providers") if point.name == name]
        if len(matches) != 1:
            raise ValueError(f"Unknown or ambiguous provider: {name}")
        try:
            provider = matches[0].load()()
        except Exception as exc:
            raise ValueError(f"Could not load provider plugin: {name}") from exc
    try:
        valid = (provider.id == name and isinstance(provider.model, str)
                 and isinstance(provider.configured, bool)
                 and callable(provider.generate))
    except (AttributeError, TypeError) as exc:
        raise ValueError(f"Invalid provider plugin: {name}") from exc
    if not valid:
        raise ValueError(f"Invalid provider plugin: {name}")
    return provider


__all__ = ["available_providers", "get_provider", "ProviderNotConfigured", "ProviderUnavailable", "TextProvider"]
