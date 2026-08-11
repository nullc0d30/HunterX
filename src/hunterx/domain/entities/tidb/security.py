# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security-material Target Intelligence Database entities.

Secrets, credentials and tokens. Secret *values* never live in the TIDB —
only masked values and one-way hashes are stored, in line with the
Development Bible security standards (``13 - Security Standards.md``).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class Secret(TidbEntity):
    """A reference record for a secret held in the secrets vault.

    Attributes:
        name: secret name.
        kind: password|token|apikey|private-key|certificate|... .
        value_masked: masked display value (never the plaintext).
        checksum: SHA-256 of the secret value for integrity checks.
        secret_key: opaque key in the secrets vault.
        owner: owning user/team.
        scope: scope of the secret.

    """

    name: str
    kind: str = "password"
    value_masked: str | None = None
    checksum: str | None = None
    secret_key: str | None = None
    owner: str | None = None
    scope: str | None = None


@dataclass(slots=True)
class Credential(TidbEntity):
    """A username/secret credential.

    Attributes:
        username: credential username.
        secret_id: owning secret reference.
        realm: authentication realm.
        attrs: extra attributes map.

    """

    username: str
    secret_id: str | None = None
    realm: str | None = None
    attrs: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class APIKey(TidbEntity):
    """A discovered or provisioned API key.

    Attributes:
        name: key name.
        key_hash: SHA-256 of the key value.
        secret_id: owning secret reference.
        expires_at: expiry timestamp (ISO).
        last_used_at: last use timestamp (ISO).
        revoked: whether the key is revoked.

    """

    name: str
    key_hash: str | None = None
    secret_id: str | None = None
    expires_at: str | None = None
    last_used_at: str | None = None
    revoked: bool = False


@dataclass(slots=True)
class Token(TidbEntity):
    """A bearer/refresh/other token.

    Attributes:
        kind: bearer|refresh|access|... .
        token_hash: SHA-256 of the token value.
        secret_id: owning secret reference.
        expires_at: expiry timestamp (ISO).
        revoked: whether the token is revoked.

    """

    kind: str = "bearer"
    token_hash: str | None = None
    secret_id: str | None = None
    expires_at: str | None = None
    revoked: bool = False


@dataclass(slots=True)
class Session(TidbEntity):
    """An authentication session.

    Attributes:
        user_id: owning user.
        token_hash: SHA-256 of the session token.
        expires_at: expiry timestamp (ISO).
        ip_address: originating IP.
        user_agent: client user-agent string.
        revoked_at: revocation timestamp (ISO).

    """

    user_id: str | None = None
    token_hash: str | None = None
    expires_at: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    revoked_at: str | None = None


@dataclass(slots=True)
class JWT(TidbEntity):
    """A discovered JSON Web Token.

    Attributes:
        token_hash: SHA-256 of the JWT.
        subject: JWT subject claim.
        issuer: JWT issuer claim.
        audience: JWT audience claims.
        algorithm: signing algorithm (``RS256``, ``HS256``, ...).
        expires_at: expiry timestamp (ISO).
        not_before: not-before timestamp (ISO).

    """

    token_hash: str | None = None
    subject: str | None = None
    issuer: str | None = None
    audience: list[str] = field(default_factory=list)
    algorithm: str | None = None
    expires_at: str | None = None
    not_before: str | None = None


@dataclass(slots=True)
class CertificatePrivateKey(TidbEntity):
    """A private key paired with a certificate.

    Attributes:
        certificate_id: owning certificate.
        key_hash: SHA-256 of the private key material.
        algorithm: key algorithm (RSA, EC, ...).
        bits: key strength in bits.
        encrypted: whether the key is encrypted at rest.

    """

    certificate_id: str
    key_hash: str | None = None
    algorithm: str | None = None
    bits: int | None = None
    encrypted: bool = True
