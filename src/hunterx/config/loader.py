# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Configuration loader.

Loads settings from, in order of increasing precedence:

1. Built-in defaults.
2. The bundled ``hunterx.yaml`` default profile.
3. A user-provided profile file (``HUNTERX_CONFIG`` or ``hunterx.yaml`` in cwd).
4. Environment variables (``HUNTERX_*``).

The result is a validated :class:`~hunterx.config.settings.Settings` instance.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from hunterx.config.settings import Settings
from hunterx.domain.exceptions import ConfigurationError, ProfileNotFoundError, ValidationConfigError
from hunterx.shared import masking

#: Environment variable prefix for automatic mapping.
_ENV_PREFIX = "HUNTERX_"
#: Default profile shipped with the package.
_DEFAULT_PROFILE = "hunterx.yaml"


def load_env_file(env_file: str | Path | None = None) -> None:
    """Load a local ``.env`` file into the process environment (best-effort).

    Values already present in the real environment win over the file
    (``override=False``) so secrets injected by Docker, CI or Kubernetes take
    precedence over a local ``.env``. The call is a no-op when the file is
    missing or ``python-dotenv`` is not installed, keeping the base install
    dependency-light.

    Args:
        env_file: explicit path to a ``.env`` file; when ``None``,
            ``python-dotenv`` searches the working directory and its parents.

    """
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover - optional dependency
        return
    load_dotenv(dotenv_path=str(env_file) if env_file is not None else None, override=False)


def _default_profile_path() -> Path:
    return Path(__file__).with_name(_DEFAULT_PROFILE)


def _load_yaml(path: Path) -> dict[str, object]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid YAML in '{path}': {exc}") from exc
    return data if isinstance(data, dict) else {}


def _resolve_profile_files(profile: str | Path | None) -> list[Path]:
    candidates: list[Path] = []
    if profile:
        path = Path(profile)
        if not path.exists():
            raise ProfileNotFoundError(str(path))
        candidates.append(path)
    else:
        env_path = os.environ.get(f"{_ENV_PREFIX}CONFIG")
        if env_path:
            path = Path(env_path)
            if not path.exists():
                raise ProfileNotFoundError(str(path))
            candidates.append(path)
        else:
            cwd_file = Path.cwd() / _DEFAULT_PROFILE
            if cwd_file.exists():
                candidates.append(cwd_file)
    return candidates


def _env_override_paths() -> dict[str, list[str]]:
    """Map every supported ``HUNTERX_*`` variable to a ``Settings`` field path.

    Top-level fields map directly (``HUNTERX_LOG_LEVEL`` → ``log_level``);
    nested sections map with an underscore separator (``HUNTERX_DATABASE_URL``
    → ``database.url``). ``HUNTERX_API_KEY`` and ``HUNTERX_API_READ_ONLY_KEY``
    are accepted as aliases for the ``api`` section fields.
    """
    from hunterx.config.settings import (
        AISettings,
        ApiSettings,
        CacheSettings,
        DatabaseSettings,
        QueueSettings,
        SecuritySettings,
    )

    paths: dict[str, list[str]] = {}
    for name in Settings.model_fields:
        paths[f"{_ENV_PREFIX}{name.upper()}"] = [name]
    for section, model in (
        ("DATABASE", DatabaseSettings),
        ("CACHE", CacheSettings),
        ("QUEUE", QueueSettings),
        ("SECURITY", SecuritySettings),
        ("API", ApiSettings),
        ("AI", AISettings),
    ):
        for name in model.model_fields:
            paths[f"{_ENV_PREFIX}{section}_{name.upper()}"] = [section.lower(), name]
    paths[f"{_ENV_PREFIX}API_KEY"] = ["api", "api_key"]
    paths[f"{_ENV_PREFIX}API_READ_ONLY_KEY"] = ["api", "read_only_key"]
    return paths


def _apply_env(merged: dict[str, object], env: dict[str, str] | None = None) -> None:
    """Apply ``HUNTERX_*`` environment overrides onto ``merged`` in place."""
    source = dict(os.environ) if env is None else dict(env)
    for key, path in _env_override_paths().items():
        if key not in source:
            continue
        node: dict[str, Any] = merged
        for part in path[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = {}
                node[part] = child
            node = child
        node[path[-1]] = source[key]


def load_default_settings(
    *,
    profile: str | Path | None = None,
    env: dict[str, str] | None = None,
    env_file: str | Path | None = None,
) -> Settings:
    """Build :class:`Settings` from defaults + optional profile + environment.

    Args:
        profile: optional user profile file (``hunterx.yaml``).
        env: optional explicit environment mapping; when omitted, the real
            process environment is used (after loading a local ``.env`` file).
        env_file: optional explicit ``.env`` path for :func:`load_env_file`;
            ignored when ``env`` is provided.

    """
    if env is None:
        load_env_file(env_file)
    merged: dict[str, object] = dict(_load_yaml(_default_profile_path()))
    for profile_path in _resolve_profile_files(profile):
        merged.update(_load_yaml(profile_path))
    _apply_env(merged, env)
    try:
        return Settings.model_validate(merged)
    except Exception as exc:
        errors = getattr(exc, "errors", None)
        if errors is not None and callable(errors):
            detail = [f"{err.get('loc')}: {err.get('msg')}" for err in errors()]
        else:
            detail = [str(exc)]
        raise ValidationConfigError(detail) from exc


class ConfigurationManager:
    """Facade over settings loading and cached access."""

    def __init__(self, settings: Settings | None = None, *, profile: str | Path | None = None) -> None:
        if settings is not None:
            self._settings = settings
        else:
            self._settings = load_default_settings(profile=profile)

    @property
    def settings(self) -> Settings:
        """Return the resolved settings instance."""
        return self._settings

    def log_level(self) -> str:
        """Return the configured root log level."""
        return self._settings.log_level

    def masked_environment_snapshot(self) -> dict[str, str]:
        """Return masked HUNTERX_* environment values for diagnostics."""
        return masking.mask_secrets_in_mapping(
            {k: v for k, v in os.environ.items() if k.startswith(_ENV_PREFIX)}
        )
