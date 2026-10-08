"""OpenAI Responses API adapter."""

from ..core.config import settings
from .base import ProviderNotConfigured, ProviderUnavailable, post_json, usable_key


class OpenAIProvider:
    id = "openai"
    url = "https://api.openai.com/v1/responses"

    @property
    def model(self) -> str:
        return settings.openai_model

    @property
    def configured(self) -> bool:
        return usable_key(settings.openai_api_key)

    async def generate(self, text: str, instructions: str) -> str:
        if not self.configured:
            raise ProviderNotConfigured("Set OPENAI_API_KEY in .env before rewriting")
        try:
            data = await post_json(
                self.url,
                {"Authorization": f"Bearer {settings.openai_api_key}", "Content-Type": "application/json"},
                {"model": self.model, "instructions": instructions, "input": text,
                 "store": False, "max_output_tokens": 2048},
                self.id,
            )
        except ProviderUnavailable as exc:
            if str(exc) == "openai returned HTTP 404":
                raise ProviderUnavailable(
                    f"OpenAI model {self.model} is unavailable to this project. "
                    "Check OPENAI_MODEL or verify your OpenAI API organization."
                ) from exc
            raise
        parts = [part.get("text", "") for output in data.get("output", [])
                 if output.get("type") == "message"
                 for part in output.get("content", []) if part.get("type") == "output_text"]
        result = "".join(parts).strip()
        if not result:
            raise ProviderUnavailable("OpenAI returned no text")
        return result
