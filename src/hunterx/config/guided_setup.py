# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Guided AI configuration.

Run when the AI Hunt Director has no usable provider configuration:

* interactive TTY → collect provider, model, endpoint and API key,
  validate connectivity + a real model round-trip, then persist to the
  resolved configuration file.
* non-interactive → fail clearly with actionable instructions instead of
  silently continuing in deterministic mode.

Secrets are read via ``getpass`` and never echoed, logged or serialized. The
persisted key lands only in the operator's private ``.env`` (mode ``0600``).
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any

#: Provider registry: display name → (provider id, default base URL, needs key,
#: needs base URL prompt, example model).
PROVIDERS: dict[str, dict[str, Any]] = {
    "openrouter": {
        "label": "OpenRouter",
        "base_url": "https://openrouter.ai/api/v1",
        "key": True,
        "ask_url": False,
        "example_model": "deepseek/deepseek-chat",
    },
    "requesty": {
        "label": "Requesty",
        "base_url": "https://router.requesty.ai/v1",
        "key": True,
        "ask_url": True,
        "provider_id": "openai_compatible",
        "example_model": "openai/gpt-4o-mini",
    },
    "openai": {
        "label": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "key": True,
        "ask_url": False,
        "example_model": "gpt-4o-mini",
    },
    "anthropic": {
        "label": "Anthropic",
        "base_url": "",
        "key": True,
        "ask_url": False,
        "example_model": "claude-3-5-haiku-latest",
    },
    "gemini": {
        "label": "Gemini",
        "base_url": "",
        "key": True,
        "ask_url": False,
        "example_model": "gemini-2.0-flash",
    },
    "deepseek": {
        "label": "DeepSeek",
        "base_url": "https://api.deepseek.com/v1",
        "key": True,
        "ask_url": False,
        "example_model": "deepseek-chat",
    },
    "grok": {
        "label": "Grok (xAI)",
        "base_url": "https://api.x.ai/v1",
        "key": True,
        "ask_url": False,
        "example_model": "grok-3-mini",
    },
    "lmstudio": {
        "label": "LM Studio (local)",
        "base_url": "http://127.0.0.1:1234/v1",
        "key": False,
        "ask_url": True,
        "example_model": "",
    },
    "ollama": {
        "label": "Ollama (local)",
        "base_url": "http://127.0.0.1:11434/v1",
        "key": False,
        "ask_url": True,
        "example_model": "llama3.1",
    },
    "openai_compatible": {
        "label": "OpenAI-compatible",
        "base_url": "",
        "key": True,
        "ask_url": True,
        "example_model": "",
    },
}

_KEY_VAR_BY_PROVIDER = {
    "openai": "HUNTERX_AI_OPENAI_KEY",
    "anthropic": "HUNTERX_AI_ANTHROPIC_KEY",
    "openrouter": "HUNTERX_AI_OPENROUTER_KEY",
    "gemini": "HUNTERX_AI_GEMINI_KEY",
    "deepseek": "HUNTERX_AI_DEEPSEEK_KEY",
    "grok": "HUNTERX_AI_GROK_KEY",
    "lmstudio": "HUNTERX_AI_LMSTUDIO_KEY",
    "ollama": "HUNTERX_AI_OLLAMA_KEY",
    "openai_compatible": "HUNTERX_AI_OPENAI_COMPATIBLE_KEY",
}


def _prompt(message: str, *, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{message}{suffix}: ").strip()
    except EOFError:
        return default
    return value or default


def _is_interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _config_write_target() -> Path:
    """Return the private .env path guided configuration should persist to."""
    data_dir = os.environ.get("HUNTERX_DATA_DIR", "").strip()
    if data_dir:
        candidate = Path(data_dir).expanduser() / ".env"
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            probe = candidate.parent / ".hunterx-write-probe"
            probe.touch()
            probe.unlink()
            return candidate
        except OSError:
            pass
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip() or str(Path.home() / ".config")
    home_dir = Path(xdg).expanduser() / "hunterx"
    try:
        home_dir.mkdir(parents=True, exist_ok=True)
        return home_dir / ".env"
    except OSError:
        return Path.cwd() / ".env"


def _upsert_env(path: Path, values: dict[str, str]) -> None:
    """Persist ``values`` into ``path`` without exposing them in output."""
    lines: list[str] = []
    if path.is_file():
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for key, value in values.items():
        prefix = f"{key}="
        replaced = False
        for index, line in enumerate(lines):
            if line.strip().startswith(prefix) or line.strip() == key:
                lines[index] = f"{key}={value}"
                replaced = True
                break
        if not replaced:
            lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - chmod best-effort
        pass


def build_client_from_values(provider: str, model: str, base_url: str, api_key: str, timeout: float = 120.0) -> Any:
    """Build an AI client from collected values (used by validation and tests)."""
    from hunterx.config.settings import AISettings
    from hunterx.infrastructure.ai.factory import build_ai_client

    settings = AISettings(
        provider=provider,
        model=model,
        base_url=base_url,
        timeout=timeout,
    )
    key_field = {
        "openai": "openai_key",
        "anthropic": "anthropic_key",
        "gemini": "gemini_key",
        "deepseek": "deepseek_key",
        "openrouter": "openrouter_key",
        "grok": "grok_key",
        "lmstudio": "lmstudio_key",
        "ollama": "ollama_key",
        "openai_compatible": "openai_compatible_key",
    }.get(provider)
    if key_field is not None and api_key:
        settings = settings.model_copy(update={key_field: __import__("pydantic").SecretStr(api_key)})
    return build_ai_client(settings)


def validate_configuration(provider: str, model: str, base_url: str, api_key: str, timeout: float = 120.0) -> tuple[bool, str]:
    """Validate connectivity AND a real model round-trip.

    Returns ``(ok, message)``; message never contains secret material.
    """
    try:
        client = build_client_from_values(provider, model, base_url, api_key, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - reported verbatim (no secrets in errors)
        return False, f"configuration rejected: {exc}"
    try:
        reachable = client.check()
    except Exception as exc:  # noqa: BLE001
        return False, f"connectivity check failed: {exc}"
    if not reachable:
        return False, (
            "provider unreachable or model unavailable "
            "(check endpoint URL, network access and that the model id exists)"
        )
    try:
        reply = client.complete(
            'Reply with exactly this JSON: {"status":"ok"}',
            model=model or None,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"model round-trip failed: {exc}"
    if not str(reply).strip():
        return False, "model returned an empty response"
    return True, "connectivity OK; model responded"


def collect_configuration(interactive: bool = True) -> dict[str, str] | None:
    """Interactively collect provider/model/endpoint/key.

    Returns a dict of env-var names to values, or ``None`` on decline/EOF.
    """
    if not interactive:
        return None
    names = list(PROVIDERS.keys())
    print("\nHunterX AI configuration required.\n")
    print("Select provider:")
    for index, name in enumerate(names, start=1):
        print(f"  {index:>2}. {PROVIDERS[name]['label']}")
    choice = _prompt("Provider number", default="1")
    try:
        selected = names[max(1, min(int(choice), len(names))) - 1]
    except ValueError:
        selected = _prompt("Provider name", default=names[0]).lower().replace("-", "_")
        if selected not in PROVIDERS:
            print(f"Unknown provider '{selected}'. Run 'hunterx ai configure' again.")
            return None
    spec = PROVIDERS[selected]
    provider_id = spec.get("provider_id", selected)

    example = spec["example_model"]
    default_model = ""
    if example:
        default_model = example
    model = _prompt(f"Model{'' if not default_model else f' (e.g. {default_model})'}", default=default_model)
    if not model and spec["key"] is False:
        # Local providers usually expose models dynamically; ask once more.
        model = _prompt("Model id", default="")
        if not model:
            print("A model id is required (run 'hunterx ai models' after pointing at a local server).")
            return None

    base_url = ""
    if spec["ask_url"]:
        base_url = _prompt("Endpoint (OpenAI-compatible base URL)", default=spec["base_url"])
        if not base_url:
            print("An endpoint URL is required for this provider.")
            return None

    api_key = ""
    if spec["key"]:
        import getpass

        try:
            api_key = getpass.getpass(f"API key ({_KEY_VAR_BY_PROVIDER.get(provider_id, 'HUNTERX_AI_OPENAI_COMPATIBLE_KEY')}): ").strip()
        except EOFError:
            api_key = ""
        if not api_key:
            print("An API key is required for this provider.")
            return None

    timeout = _prompt("Request timeout seconds", default="120")
    try:
        timeout_value = max(5.0, float(timeout))
    except ValueError:
        timeout_value = 120.0

    ok, message = validate_configuration(provider_id, model, base_url, api_key, timeout=timeout_value)
    print(f"Validation: {message}")
    if not ok:
        return None

    values = {
        "HUNTERX_AI_PROVIDER": provider_id,
        "HUNTERX_AI_MODEL": model,
        "HUNTERX_AI_TIMEOUT": repr(timeout_value),
    }
    if base_url:
        values["HUNTERX_AI_BASE_URL"] = base_url
    key_var = _KEY_VAR_BY_PROVIDER.get(provider_id)
    if key_var and api_key:
        values[key_var] = api_key
    return values


def run_guided_configuration(app: Any = None, *, interactive: bool | None = None) -> int:
    """Entry point for ``hunterx ai configure``.

    Returns a process exit code: 0 configured+validated, 1 failed/declined.
    """
    if interactive is None:
        interactive = _is_interactive()
    if not interactive:
        print(
            "HunterX AI configuration required, but no interactive terminal is attached.\n"
            "\n"
            "Configure non-interactively using ONE of:\n"
            "  1. Environment variables:\n"
            "       export HUNTERX_AI_PROVIDER=openai_compatible\n"
            "       export HUNTERX_AI_MODEL=<model-id>\n"
            "       export HUNTERX_AI_BASE_URL=<endpoint>\n"
            "       export HUNTERX_AI_OPENAI_COMPATIBLE_KEY=<api-key>\n"
            "  2. A .env file discovered from (in order):\n"
            "       $HUNTERX_ENV_FILE\n"
            "       $HUNTERX_DATA_DIR/.env\n"
            "       ./.env (or any parent directory)\n"
            "       ~/.config/hunterx/.env   (the invoking user's home under sudo)\n"
            "       /opt/hunterx/data/.env\n"
            "     See .env.example for the full variable list.\n"
            "  3. Re-run interactively on a TTY: hunterx ai configure\n"
            "\n"
            "HunterX will NOT silently fall back to deterministic mode."
        )
        return 1
    values = collect_configuration(interactive=True)
    if values is None:
        print("Configuration not completed; HunterX will not start an AI-directed mission.")
        return 1
    target = _config_write_target()
    _upsert_env(target, values)
    # Apply immediately so the current process can use it.
    for key, value in values.items():
        os.environ.setdefault(key, value)
    print(f"Configuration written to {target}")
    print("Validated: provider reachable, model responding, AI Hunt Director enabled.")
    print("Re-run your command to start the mission.")
    return 0


__all__ = [
    "PROVIDERS",
    "collect_configuration",
    "run_guided_configuration",
    "validate_configuration",
]
