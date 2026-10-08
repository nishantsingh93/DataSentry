# Add a provider

Built-in examples are in `datasentry/providers/openai.py`, `anthropic.py`, and `gemini.py`. Keep provider-specific HTTP payloads and response parsing in the adapter. The shared `RewriteService` owns PII detection, policy, redaction, and output scanning.

## Contract

An adapter has these members:

```python
class ExampleProvider:
    id = "example"

    @property
    def model(self) -> str:
        return "example-model"

    @property
    def configured(self) -> bool:
        return bool(...)  # inspect the key without printing it

    async def generate(self, text: str, instructions: str) -> str:
        # text has already been redacted; use a fixed HTTPS endpoint.
        # Raise ProviderNotConfigured or ProviderUnavailable for failures.
        return "rewritten text"
```

The `id` must match the registered name. `generate` must not log request text, API keys, or upstream response bodies. Validate response shapes and raise `ProviderUnavailable` when no text is returned. Use the shared `post_json` helper if it fits the API; it sets a 60-second timeout and hides upstream response bodies in errors.

For an external package, register the class with a Python entry point:

```toml
[project.entry-points."datasentry.providers"]
example = "datasentry_example.provider:ExampleProvider"
```

Install the package into the same virtual environment as DataSentry. `python -m datasentry.cli providers` will list it. Set its key using the package's documented local configuration, then use `--provider example` or `{"provider":"example"}` in the rewrite API. Only the selected third-party entry point is imported. Entry points run in the DataSentry process and can read local environment variables, so install only trusted packages.

For a built-in adapter, add its module to `datasentry/providers/` and register its class in `BUILTINS` in `datasentry/providers/__init__.py`. Add an `.env.example` setting and a test asserting that the outbound payload contains redacted text and that a blocked request makes no HTTP call.
