"""Google Gemini generateContent API adapter."""

from ..core.config import settings
from .base import ProviderNotConfigured, ProviderUnavailable, post_json, usable_key


class GeminiProvider:
    id = "gemini"

    @property
    def model(self) -> str:
        return settings.gemini_model

    @property
    def configured(self) -> bool:
        return usable_key(settings.gemini_api_key)

    async def generate(self, text: str, instructions: str) -> str:
        if not self.configured:
            raise ProviderNotConfigured("Set GEMINI_API_KEY in .env before rewriting")
        # Restrict the path component so the configured model cannot alter the host or path.
        if not self.model or not all(c.isalnum() or c in "._-" for c in self.model):
            raise ProviderUnavailable("Invalid Gemini model name")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        data = await post_json(
            url,
            {"x-goog-api-key": settings.gemini_api_key, "Content-Type": "application/json"},
            {"systemInstruction": {"parts": [{"text": instructions}]},
             "contents": [{"role": "user", "parts": [{"text": text}]}],
             "store": False,
             "generationConfig": {"maxOutputTokens": 2048}},
            self.id,
        )
        candidates = data.get("candidates", [])
        result = "".join(part.get("text", "") for candidate in candidates[:1]
                         for part in candidate.get("content", {}).get("parts", [])).strip()
        if not result:
            raise ProviderUnavailable("Gemini returned no text")
        return result
