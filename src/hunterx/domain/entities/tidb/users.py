# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""User and access Target Intelligence Database entities.

Users, roles, permissions, teams and API clients. The TIDB stores only
identity and authorization data; credentials and tokens live in the secrets
vault (see ``hunterx.domain.entities.tidb.security``), so passwords and
secret material never appear here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class User(TidbEntity):
    """A platform user.

    Attributes:
        username: unique login name.
        email: user email address.
        full_name: display name.
        status: active|invited|disabled|locked.
        is_service_account: whether this is a service identity.
        mfa_enabled: whether multi-factor authentication is enabled.
        last_login_at: UTC ISO-8601 last-login timestamp.
        preferences: per-user preferences map.

    """

    username: str = ""
    email: str | None = None
    full_name: str | None = None
    status: str = "active"
    is_service_account: bool = False
    mfa_enabled: bool = False
    last_login_at: str | None = None
    preferences: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class Role(TidbEntity):
    """A named role with a set of permissions.

    Attributes:
        name: unique role name.
        description: role description.
        permissions: granted permission identifiers.

    """

    name: str
    description: str = ""
    permissions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Permission(TidbEntity):
    """A single permission grant.

    Attributes:
        name: unique permission name (e.g. ``finding.read``).
        resource: resource the permission applies to.
        action: verb (read, write, delete, execute, ...).
        description: permission description.

    """

    name: str
    resource: str = ""
    action: str = "read"
    description: str = ""


@dataclass(slots=True)
class Team(TidbEntity):
    """A group of users.

    Attributes:
        name: unique team name.
        description: team description.
        user_ids: member user identifiers.
        role_ids: granted role identifiers.

    """

    name: str
    description: str = ""
    user_ids: list[str] = field(default_factory=list)
    role_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class APIClient(TidbEntity):
    """An API client identity.

    Attributes:
        name: client name.
        client_type: first-party|third-party|automation.
        user_id: owning user when human-backed.
        scopes: granted API scopes.
        status: active|revoked|expired.
        last_used_at: UTC ISO-8601 last-use timestamp.

    """

    name: str
    client_type: str = "automation"
    user_id: str | None = None
    scopes: list[str] = field(default_factory=list)
    status: str = "active"
    last_used_at: str | None = None
