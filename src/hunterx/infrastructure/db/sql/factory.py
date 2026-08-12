# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""SQLAlchemy engine/session factory and declarative base."""

from __future__ import annotations

import time
from typing import Any

from hunterx.config.settings import DatabaseSettings
from hunterx.domain.exceptions import InfrastructureConnectionError

# Imported lazily so `hunterx.infrastructure` imports cheaply even without the
# `db` extra installed.
_mod_cache: dict[str, Any] = {}


def _load_sqlalchemy() -> dict[str, Any]:
    if "loaded" not in _mod_cache:
        try:
            from sqlalchemy import create_engine
            from sqlalchemy.exc import OperationalError
            from sqlalchemy.orm import DeclarativeBase, sessionmaker
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise InfrastructureConnectionError(
                "SQLAlchemy is not installed; add the 'db' extra."
            ) from exc

        class _Base(DeclarativeBase):  # type: ignore[misc]
            pass

        _mod_cache.update(
            {
                "loaded": True,
                "create_engine": create_engine,
                "sessionmaker": sessionmaker,
                "OperationalError": OperationalError,
                "Base": _Base,
            }
        )
    return _mod_cache


def get_base() -> type:
    """Return the SQLAlchemy declarative base used by all model definitions."""
    return _load_sqlalchemy()["Base"]  # type: ignore[return-value]


def create_engine_from_settings(settings: DatabaseSettings) -> Any:
    """Create a SQLAlchemy engine from typed settings.

    SQLite ``:memory:`` databases use a static pool so every connection shares
    the same in-process database.
    """
    mod = _load_sqlalchemy()
    if settings.url.startswith("sqlite:///:memory:"):
        from sqlalchemy.pool import StaticPool

        return mod["create_engine"](
            settings.url,
            echo=settings.echo,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
    return mod["create_engine"](
        settings.url,
        echo=settings.echo,
        pool_size=settings.pool_size,
        pool_timeout=settings.pool_timeout,
    )


class SessionFactory:
    """Small session factory wrapper around ``sessionmaker``."""

    def __init__(self, settings: DatabaseSettings, *, engine: Any | None = None) -> None:
        mod = _load_sqlalchemy()
        self._engine = engine if engine is not None else create_engine_from_settings(settings)
        self._session_factory = mod["sessionmaker"](bind=self._engine, expire_on_commit=False)

    @property
    def engine(self) -> Any:
        """Return the underlying SQLAlchemy engine."""
        return self._engine

    def session(self) -> Any:
        """Open a new session."""
        return self._session_factory()

    def create_all(self, *, retries: int = 25, retry_delay: float = 0.1) -> None:
        """Create tables for all registered models.

        Retries a bounded number of times on SQLite ``OperationalError``
        conditions raised when a concurrent process is racing to create the
        same schema (``table ... already exists``, stale reflection via
        ``database schema has changed``, or a held write lock via ``database
        is locked``). SQLAlchemy's ``create_all`` uses ``checkfirst=True`` by
        default, so it is idempotent: after the other process finishes, the
        retried call sees the tables already present and quietly completes.

        The default budget (25 attempts with linear backoff, ~32s worst case)
        comfortably outlives a cold bootstrap of the full model registry
        (~15s), so the loser of a concurrent first-run simply waits for the
        winner instead of crashing.
        """
        mod = _load_sqlalchemy()
        metadata = mod["Base"].metadata
        last_error: Exception | None = None
        for attempt in range(retries):
            try:
                metadata.create_all(self._engine)
                return
            except mod["OperationalError"] as exc:
                last_error = exc
                message = str(getattr(exc, "orig", exc) or exc).lower()
                transient = (
                    "already exists" in message
                    or "locked" in message
                    or "schema has changed" in message
                )
                if not transient:
                    raise
                time.sleep(retry_delay * (attempt + 1))
        assert last_error is not None
        raise last_error

    def dispose(self) -> None:
        """Dispose the engine connection pool."""
        self._engine.dispose()
