"""Contract and shared HTTP handling for text generation providers."""

from typing import Protocol

import aiohttp


class ProviderUnavailable(Exception):
    """A provider failed without exposing its response body or request data."""


class ProviderNotConfigured(ProviderUnavailable):
    """The selected provider has no usable API key."""


class TextProvider(Protocol):
    id: str

    @property
    def model(self) -> str: ...

    @property
    def configured(self) -> bool: ...

    async def generate(self, text: str, instructions: str) -> str: ...


def usable_key(key: str | None) -> bool:
    return bool(key and key.strip() and not key.strip().lower().startswith(("your-", "change-")))


async def post_json(url: str, headers: dict, payload: dict, provider: str) -> dict:
    """Send to a fixed provider URL; upstream bodies may contain sensitive text."""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as session:
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status != 200:
                    raise ProviderUnavailable(f"{provider} returned HTTP {response.status}")
                try:
                    return await response.json()
                except ValueError as exc:
                    raise ProviderUnavailable(f"{provider} returned invalid JSON") from exc
    except (aiohttp.ClientError, TimeoutError) as exc:
        raise ProviderUnavailable(f"Could not reach {provider}") from exc
