# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authentication intelligence collection strategy.

Maps an execution mode (passive/active/hybrid) and a target onto the concrete
set of analyses the capability should run. The strategy is a pure function of
(mode, target, requested features) so the same inputs always yield the same
plan. The authentication capability is intelligence-only: even active postures
never authenticate, and passive postures only consume already-acquired static
material (HTTP snapshots, script content, API schemes, TIDB intelligence).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from hunterx.domain.recon.models import ReconMode

#: Tools available for authentication analysis (single in-process analyzer).
_AUTH_TOOLS = ("auth-analysis",)


@dataclass(frozen=True, slots=True)
class AuthStrategy:
    """A concrete authentication analysis plan.

    Attributes:
        target: the target value (hostname, domain, IP or URL).
        target_kind: canonical target kind.
        mode: the execution posture.
        tools: the tool ids to run.
        include_endpoints: whether to model authentication endpoints/flows.
        include_cookies: whether to analyse cookie security metadata.
        include_schemes: whether to analyse authentication schemes.
        include_identity: whether to analyse identity-provider/OAuth/OIDC/SAML.
        include_mfa: whether to analyse MFA/WebAuthn indicators.
        include_history: whether to compare against historical observations.
        include_existing: whether to fold in existing TIDB intelligence.
        min_confidence: minimum confidence for a record to be retained.
        max_concurrency: execution concurrency ceiling.

    """

    target: str
    target_kind: str = "hostname"
    mode: ReconMode = ReconMode.HYBRID
    tools: tuple[str, ...] = _AUTH_TOOLS
    include_endpoints: bool = True
    include_cookies: bool = True
    include_schemes: bool = True
    include_identity: bool = True
    include_mfa: bool = True
    include_history: bool = False
    include_existing: bool = True
    min_confidence: float = 0.0
    max_concurrency: int = 4


class AuthStrategyBuilder:
    """Build an :class:`AuthStrategy` for a target and mode."""

    def build(
        self,
        target: str,
        *,
        mode: ReconMode | str = ReconMode.HYBRID,
        target_kind: str = "",
        tools: tuple[str, ...] = (),
        include_endpoints: bool | None = None,
        include_cookies: bool | None = None,
        include_schemes: bool | None = None,
        include_identity: bool | None = None,
        include_mfa: bool | None = None,
        include_history: bool = False,
        include_existing: bool | None = None,
        min_confidence: float | None = None,
        max_concurrency: int = 4,
    ) -> AuthStrategy:
        """Build the strategy for ``target``."""
        if not target_kind:
            target_kind = _infer_target_kind(target)
        parsed_mode = _mode(mode)
        return AuthStrategy(
            target=str(target).strip(),
            target_kind=target_kind,
            mode=parsed_mode,
            tools=tuple(tools) if tools else _AUTH_TOOLS,
            include_endpoints=_feature_default(parsed_mode, include_endpoints),
            include_cookies=_feature_default(parsed_mode, include_cookies),
            include_schemes=_feature_default(parsed_mode, include_schemes),
            include_identity=_feature_default(parsed_mode, include_identity),
            include_mfa=_feature_default(parsed_mode, include_mfa),
            include_history=include_history,
            include_existing=_feature_default(parsed_mode, include_existing),
            min_confidence=min_confidence if min_confidence is not None else 0.0,
            max_concurrency=max(1, max_concurrency),
        )

    def tools_for(self, mode: ReconMode) -> tuple[str, ...]:
        """Return the tool ids available for a posture.

        The in-process analyzer is always available: it performs no network I/O
        and never authenticates, so passive postures still run it against
        already-acquired material.
        """
        return _AUTH_TOOLS


def _feature_default(mode: ReconMode, requested: bool | None) -> bool:
    """Return a feature's default for a posture."""
    if requested is not None:
        return requested
    return True


def _mode(mode: ReconMode | str) -> ReconMode:
    """Coerce a mode into a :class:`ReconMode`."""
    if isinstance(mode, ReconMode):
        return mode
    try:
        return ReconMode(str(mode).lower())
    except ValueError:
        return ReconMode.HYBRID


def _infer_target_kind(value: str) -> str:
    """Infer a canonical target kind from a target value."""
    candidate = str(value).strip()
    lowered = candidate.lower()
    if lowered.startswith(("http://", "https://")):
        return "url"
    if "/" in candidate:
        try:
            ipaddress.ip_network(candidate, strict=False)
            return "cidr"
        except ValueError:
            return "hostname"
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        return "domain" if candidate.count(".") == 1 else "hostname"
