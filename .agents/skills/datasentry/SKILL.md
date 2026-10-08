---
name: datasentry
description: Safely rewrite text with DataSentry after local PII detection, policy checks, and redaction.
---

# DataSentry

Use the repository CLI for PII-safe rewriting. Read `README.md` for setup and `docs/ARCHITECTURE.md` for the trust boundary.

1. Run `python -m datasentry.cli providers` to see configured provider IDs. Never print or request an API key in chat; the user sets it in local `.env`.
2. For a rewrite, run `python -m datasentry.cli rewrite --provider <id> --tone <clear|professional|friendly> --show-sanitized "<text>"`. For private text, prefer `--file <path>` or stdin so it is not included in shell history.
3. If policy blocks the text, stop. Do not call the provider directly. If redaction removed facts needed by the rewrite, tell the user that those facts cannot be reconstructed.
4. To add a provider, follow `docs/ADDING_A_PROVIDER.md`. Keep the provider-specific request in an adapter and do not move detection or policy checks into it.

Supported built-in IDs: `openai`, `anthropic`, `gemini`. An installed entry-point plugin can add another ID.
