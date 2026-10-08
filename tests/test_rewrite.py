"""Privacy boundary and provider payload behavior without network calls."""

import asyncio
import os

os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("ADMIN_API_KEY", "test-api-key")

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from datasentry.api.app import create_app
from datasentry.cli import cli
from datasentry.core.config import settings
from datasentry.providers import ProviderUnavailable, get_provider
from datasentry.providers import anthropic, gemini, openai
from datasentry.rewrite import RewriteBlocked, RewriteService


@pytest.mark.parametrize("name,module,key_name,response", [
    ("openai", openai, "openai_api_key", {"output": [{"type": "message", "content": [
        {"type": "output_text", "text": "Contact [REDACTED_EMAIL]"}]}]}),
    ("anthropic", anthropic, "anthropic_api_key", {"content": [
        {"type": "text", "text": "Contact [REDACTED_EMAIL]"}]}),
    ("gemini", gemini, "gemini_api_key", {"candidates": [{"content": {"parts": [
        {"text": "Contact [REDACTED_EMAIL]"}]}}]}),
])
def test_every_provider_receives_only_redacted_text(monkeypatch, name, module, key_name, response):
    monkeypatch.setattr(settings, key_name, "test-only")
    requests = []

    async def fake_post(url, headers, payload, provider):
        requests.append((url, headers, payload, provider))
        return response

    monkeypatch.setattr(module, "post_json", fake_post)
    result = asyncio.run(RewriteService().rewrite("Contact jane@example.com", "professional", name))
    assert result.sent_to_provider == "Contact [REDACTED_EMAIL]"
    assert result.rewritten_text == "Contact [REDACTED_EMAIL]"
    assert result.provider == name
    assert result.detected_entity_types == ["EMAIL"]
    assert "jane@example.com" not in str(requests)
    assert requests[0][3] == name
    payload = requests[0][2]
    if name == "openai":
        assert payload["input"] == result.sent_to_provider
        assert payload["store"] is False
    elif name == "anthropic":
        assert payload["messages"][0]["content"] == result.sent_to_provider
    else:
        assert payload["contents"][0]["parts"][0]["text"] == result.sent_to_provider
        assert payload["store"] is False


@pytest.mark.parametrize("name,module,key_name", [
    ("openai", openai, "openai_api_key"),
    ("anthropic", anthropic, "anthropic_api_key"),
    ("gemini", gemini, "gemini_api_key"),
])
def test_high_risk_pii_never_calls_any_provider(monkeypatch, name, module, key_name):
    monkeypatch.setattr(settings, key_name, "test-only")
    calls = []

    async def fake_post(*args):
        calls.append(args)
        return {}

    monkeypatch.setattr(module, "post_json", fake_post)
    with pytest.raises(RewriteBlocked):
        asyncio.run(RewriteService().rewrite("My SSN is 123-45-6789", provider=name))
    assert calls == []


def test_model_output_is_scanned_again(monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "test-only")

    async def fake_post(*args):
        return {"output": [{"type": "message", "content": [
            {"type": "output_text", "text": "Email jane@example.com"}]}]}

    monkeypatch.setattr(openai, "post_json", fake_post)
    result = asyncio.run(RewriteService().rewrite("Rewrite this greeting"))
    assert result.rewritten_text == "Email [REDACTED_EMAIL]"


def test_cli_labels_sanitized_input_and_rewritten_output(monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "test-only")

    async def fake_post(*args):
        return {"output": [{"type": "message", "content": [
            {"type": "output_text", "text": "Please contact [REDACTED_EMAIL]"}]}]}

    monkeypatch.setattr(openai, "post_json", fake_post)
    shown = CliRunner().invoke(cli, ["rewrite", "Contact jane@example.com", "--show-sanitized"])
    assert shown.exit_code == 0
    assert "[INPUT: sanitized text sent to openai]\nContact [REDACTED_EMAIL]" in shown.output
    assert "[OUTPUT: rewritten text]\nPlease contact [REDACTED_EMAIL]" in shown.output
    assert "jane@example.com" not in shown.output

    plain = CliRunner().invoke(cli, ["rewrite", "Contact jane@example.com"])
    assert plain.exit_code == 0
    assert plain.output == "Please contact [REDACTED_EMAIL]\n"


def test_rewrite_endpoint_requires_local_api_key():
    with TestClient(create_app()) as client:
        response = client.post("/api/v1/rewrite", json={"text": "Hello"})
    assert response.status_code == 401


def test_rewrite_endpoint_selects_provider_without_echoing_original(monkeypatch):
    monkeypatch.setattr(settings, "anthropic_api_key", "test-only")

    async def fake_post(*args):
        return {"content": [{"type": "text", "text": "Contact [REDACTED_EMAIL]"}]}

    monkeypatch.setattr(anthropic, "post_json", fake_post)
    with TestClient(create_app()) as client:
        response = client.post("/api/v1/rewrite",
                               headers={"X-API-Key": settings.admin_api_key},
                               json={"text": "Contact jane@example.com", "provider": "anthropic"})
    assert response.status_code == 200
    data = response.json()
    assert "jane@example.com" not in str(data)
    assert data["sent_to_provider"] == "Contact [REDACTED_EMAIL]"
    assert data["provider"] == "anthropic"


def test_unknown_provider_is_rejected():
    with pytest.raises(ValueError, match="Unknown"):
        get_provider("unregistered")


def test_missing_provider_key_returns_503(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", None)
    with TestClient(create_app()) as client:
        response = client.post("/api/v1/rewrite",
                               headers={"X-API-Key": settings.admin_api_key},
                               json={"text": "Hello", "provider": "gemini"})
    assert response.status_code == 503
    assert "API key" in response.json()["detail"]


def test_openai_model_404_has_actionable_message(monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "test-only")

    async def fake_post(*args):
        raise ProviderUnavailable("openai returned HTTP 404")

    monkeypatch.setattr(openai, "post_json", fake_post)
    with pytest.raises(ProviderUnavailable, match="verify your OpenAI API organization"):
        asyncio.run(get_provider("openai").generate("safe text", "rewrite"))


def test_generic_proxy_is_retired():
    with TestClient(create_app()) as client:
        response = client.post("/api/v1/proxy",
                               headers={"X-API-Key": settings.admin_api_key},
                               json={"target_url": "https://example.com", "payload": {}})
    assert response.status_code == 410
