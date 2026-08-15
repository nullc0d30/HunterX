# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""HunterX application path resolution (single source of truth).

Resolves where the application stores persistent data. The default SQLite
database lives at ``<application root>/data/hunterx.db`` so persistence works
regardless of the working directory (no fragile ``/home/<user>/...``,
``/opt/hunterx/...`` or ``/tmp/...`` developer paths).

Resolution order:

1. ``HUNTERX_DATA_DIR`` — explicit override (installer and Docker set this).
2. The application/project root, derived from the installed package location:
   - a source checkout (``pyproject.toml`` + ``src/hunterx``);
   - an install.sh-style root (a directory containing ``venv/`` and ``data/``).
3. ``~/.local/share/hunterx`` as a portable user-level fallback.

The default database URL sentinel (``sqlite:///hunterx.db``) is resolved to
``<data dir>/hunterx.db`` at engine-creation time so an explicitly configured
``HUNTERX_DATABASE_URL`` always wins.
"""

from __future__ import annotations

import os
from pathlib import Path

import hunterx

#: The default (unconfigured) database URL. Treated as a sentinel meaning
#: "resolve to the application data directory at engine-creation time".
DEFAULT_DATABASE_URL = "sqlite:///hunterx.db"


def hunterx_root() -> Path:
    """Return the HunterX application/project root directory.

    ``HUNTERX_ROOT`` (when set) is authoritative; otherwise the root is
    detected from the installed package location. Never a developer-specific
    absolute path — always derived from the runtime environment.
    """
    override = os.environ.get("HUNTERX_ROOT")
    if override:
        return Path(override).expanduser().resolve()
    package_dir = Path(hunterx.__file__).resolve().parent
    for candidate in (package_dir, *package_dir.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / "src" / "hunterx").is_dir():
            return candidate
        # install.sh layout: <root>/venv + <root>/data
        if (candidate / "venv").is_dir() and (candidate / "data").is_dir():
            return candidate
    return Path.home() / ".local" / "share" / "hunterx"


def hunterx_data_dir() -> Path:
    """Return the application data directory (``<root>/data``).

    ``HUNTERX_DATA_DIR`` overrides the location; otherwise it is derived from
    :func:`hunterx_root`. The returned directory is NOT created here (see
    :func:`ensure_data_dir`).
    """
    override = os.environ.get("HUNTERX_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return hunterx_root() / "data"


def ensure_data_dir() -> Path:
    """Return the application data directory, creating it (and parents) if needed."""
    data_dir = hunterx_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def resolve_database_url(url: str) -> str:
    """Resolve a configured SQLAlchemy URL to its concrete location.

    The default sentinel (``sqlite:///hunterx.db``) resolves to
    ``sqlite:///<data dir>/hunterx.db``; any other URL (explicitly configured
    via ``HUNTERX_DATABASE_URL`` or a profile) is returned unchanged.
    """
    if not url or url == DEFAULT_DATABASE_URL:
        data_dir = ensure_data_dir()
        return f"sqlite:///{data_dir / 'hunterx.db'}"
    return url


__all__ = [
    "DEFAULT_DATABASE_URL",
    "ensure_data_dir",
    "hunterx_data_dir",
    "hunterx_root",
    "resolve_database_url",
]
