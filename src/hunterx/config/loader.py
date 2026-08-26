# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Configuration loader.

Loads settings from, in order of increasing precedence:

1. Built-in defaults.
2. The bundled ``hunterx.yaml`` default profile.
3. A user-provided profile file (``HUNTERX_CONFIG`` or ``hunterx.yaml`` in cwd).
4. Environment variables (``HUNTERX_*``).

AI credentials are additionally discovered from a ``.env`` file resolved
intentionally (see :func:`discover_env_file`) so the configured provider is
available regardless of the working directory or ``sudo`` usage:

* ``$HUNTERX_ENV_FILE`` when set explicitly.
* ``$HUNTERX_DATA_DIR/.env`` — the install data directory managed by
  ``install.sh``.
* ``.env`` in the current directory and its parents.
* ``.env`` beside the ``$HUNTERX_CONFIG`` profile.
* User configuration directories (the invoking user's home under ``sudo``):
  ``~/.config/hunterx/.env``, ``~/.hunterx/.env``.
* The system install data directory (``/opt/hunterx/data/.env``).

Values already present in the real environment always win over file values so
Docker/CI/Kubernetes secret injection keeps precedence.

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
#: Default system install data directory (managed by ``install.sh``).
_SYSTEM_DATA_DIRS: tuple[str, ...] = ("/opt/hunterx/data",)


def _sudo_user_home() -> Path | None:
    """Return the invoking user's home when running under ``sudo``.

    ``sudo`` strips most caller environment but preserves ``SUDO_USER``/``SUDO_UID``
    unless explicitly configured otherwise. Configuration written by the human
    operator therefore stays discoverable instead of silently falling back to
    root's (usually empty) home.
    """
    user = os.environ.get("SUDO_USER", "").strip()
    if not user:
        return None
    try:
        import pwd

        entry = pwd.getpwnam(user)
        return Path(entry.pw_dir)
    except (ImportError, KeyError):  # pragma: no cover - platform dependent
        return None


def _candidate_env_files() -> list[Path]:
    """Return the ordered candidate ``.env`` paths for :func:`discover_env_file`."""
    candidates: list[Path] = []

    def _add(path: Path) -> None:
        if path not in candidates:
            candidates.append(path)

    explicit = os.environ.get("HUNTERX_ENV_FILE", "").strip()
    if explicit:
        _add(Path(explicit).expanduser())
    data_dir = os.environ.get("HUNTERX_DATA_DIR", "").strip()
    if data_dir:
        _add(Path(data_dir).expanduser() / ".env")
    cwd = Path.cwd()
    for parent in (cwd, *cwd.parents):
        _add(parent / ".env")
    config_profile = os.environ.get("HUNTERX_CONFIG", "").strip()
    if config_profile:
        _add(Path(config_profile).expanduser().parent / ".env")
    homes: list[Path | None] = [_sudo_user_home(), Path.home()]
    for home in homes:
        if home is None:
            continue
        xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
        if xdg:
            _add(Path(xdg).expanduser() / "hunterx" / ".env")
        _add(home / ".config" / "hunterx" / ".env")
        _add(home / ".hunterx" / ".env")
    for data_dir in _SYSTEM_DATA_DIRS:
        _add(Path(data_dir) / ".env")
    # Development checkout: <repo>/src/hunterx/config/loader.py → repo .env.
    try:
        repo_root = Path(__file__).resolve().parents[3]
        if repo_root.name and (repo_root / "pyproject.toml").exists():
            _add(repo_root / ".env")
    except IndexError:  # pragma: no cover - defensive
        pass
    return candidates


def discover_env_file() -> Path | None:
    """Return the first existing ``.env`` file from the intentional search path.

    Search order (most specific first):

    1. ``$HUNTERX_ENV_FILE``
    2. ``$HUNTERX_DATA_DIR/.env``
    3. ``.env`` from the current directory upward
    4. ``.env`` beside ``$HUNTERX_CONFIG``
    5. ``~/.config/hunterx/.env`` then ``~/.hunterx/.env`` (invoking user under sudo)
    6. ``/opt/hunterx/data/.env`` (system install)
    7. repository-root ``.env`` (development checkout)

    Set ``HUNTERX_SKIP_ENV_FILE=1`` to disable file discovery entirely
    (pure-environment mode: Docker, CI, hardened deployments).

    Returns ``None`` when no candidate exists — configuration may legitimately
    be supplied purely through the environment.
    """
    if os.environ.get("HUNTERX_SKIP_ENV_FILE", "").strip() in ("1", "true", "yes"):
        return None
    for candidate in _candidate_env_files():
        try:
            if candidate.is_file():
                return candidate
        except OSError:  # pragma: no cover - permission errors are non-fatal
            continue
    return None


def load_env_file(env_file: str | Path | None = None) -> Path | None:
    """Load a ``.env`` file into the process environment (best-effort).

    Values already present in the real environment win over the file
    (``override=False``) so secrets injected by Docker, CI or Kubernetes take
    precedence over a local ``.env``. The call is a no-op when the file is
    missing or ``python-dotenv`` is not installed, keeping the base install
    dependency-light.

    Args:
        env_file: explicit path to a ``.env`` file; when ``None`` the file is
            discovered intentionally via :func:`discover_env_file` (cwd is only
            one of several searched locations, so ``sudo`` and arbitrary
            working directories still resolve the configured AI provider).

    Returns:
        The loaded file path, or ``None`` when nothing was loaded.

    """
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover - optional dependency
        return None
    path = Path(env_file).expanduser() if env_file is not None else discover_env_file()
    if path is None or not path.is_file():
        return None
    load_dotenv(dotenv_path=str(path), override=False)
    return path


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
        ResourceSettings,
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
        ("RESOURCE", ResourceSettings),
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


def ai_configuration_source() -> str:
    """Return a human-readable description of where AI config was resolved from.

    One of ``environment``, ``<path> (.env)``, ``profile`` or ``not_configured``.
    Never includes secret values — only the location names.
    """
    provider = os.environ.get("HUNTERX_AI_PROVIDER", "").strip()
    if provider:
        return "environment"
    env_file = discover_env_file()
    if env_file is not None:
        try:
            text = env_file.read_text(encoding="utf-8", errors="replace")
        except OSError:  # pragma: no cover - unreadable file is non-fatal
            text = ""
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("HUNTERX_AI_PROVIDER") and "=" in stripped:
                value = stripped.split("=", 1)[1].strip().strip("'\"")
                if value:
                    return f"{env_file}"
    profile_path = os.environ.get("HUNTERX_CONFIG", "").strip()
    if profile_path and Path(profile_path).is_file():
        return f"{profile_path} (profile)"
    return "not_configured"
