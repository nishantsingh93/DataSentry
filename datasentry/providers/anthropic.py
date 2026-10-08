"""Anthropic Messages API adapter."""

from ..core.config import settings
from .base import ProviderNotConfigured, ProviderUnavailable, post_json, usable_key


class AnthropicProvider:
    id = "anthropic"
    url = "https://api.anthropic.com/v1/messages"

    @property
    def model(self) -> str:
        return settings.anthropic_model

    @property
    def configured(self) -> bool:
        return usable_key(settings.anthropic_api_key)

    async def generate(self, text: str, instructions: str) -> str:
        if not self.configured:
            raise ProviderNotConfigured("Set ANTHROPIC_API_KEY in .env before rewriting")
        data = await post_json(
            self.url,
            {"x-api-key": settings.anthropic_api_key,
             "anthropic-version": "2023-06-01", "content-type": "application/json"},
            {"model": self.model, "max_tokens": 2048, "system": instructions,
             "messages": [{"role": "user", "content": text}]},
            self.id,
        )
        result = "".join(part.get("text", "") for part in data.get("content", [])
                         if part.get("type") == "text").strip()
        if not result:
            raise ProviderUnavailable("Anthropic returned no text")
        return result
