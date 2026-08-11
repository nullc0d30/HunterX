# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB security entities (secrets, credentials, tokens)."""

from __future__ import annotations

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class SecretModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.security.Secret`."""

    __tablename__ = "tidb_secrets"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="password")
    value_masked: Mapped[str | None] = mapped_column(String(255), nullable=True)
    checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    secret_key: Mapped[str | None] = mapped_column(String(1024), nullable=True, index=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scope: Mapped[str | None] = mapped_column(String(255), nullable=True)


class CredentialModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.security.Credential`."""

    __tablename__ = "tidb_credentials"

    username: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    secret_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_secrets.id"), nullable=True, index=True
    )
    realm: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attrs: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)


class APIKeyModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.security.APIKey`."""

    __tablename__ = "tidb_api_keys"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    key_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    secret_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_secrets.id"), nullable=True, index=True
    )
    expires_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_used_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class TokenModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.security.Token`."""

    __tablename__ = "tidb_tokens"

    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="bearer")
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    secret_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_secrets.id"), nullable=True, index=True
    )
    expires_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class SessionModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.security.Session`."""

    __tablename__ = "tidb_sessions"

    user_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    expires_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    revoked_at: Mapped[str | None] = mapped_column(String(32), nullable=True)


class JWTModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.security.JWT`."""

    __tablename__ = "tidb_jwts"

    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    issuer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    audience: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    algorithm: Mapped[str | None] = mapped_column(String(16), nullable=True)
    expires_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    not_before: Mapped[str | None] = mapped_column(String(32), nullable=True)


class CertificatePrivateKeyModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.security.CertificatePrivateKey`."""

    __tablename__ = "tidb_certificate_private_keys"

    certificate_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_certificates.id"), nullable=False, index=True
    )
    key_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    algorithm: Mapped[str | None] = mapped_column(String(32), nullable=True)
    bits: Mapped[int | None] = mapped_column(Integer, nullable=True)
    encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
