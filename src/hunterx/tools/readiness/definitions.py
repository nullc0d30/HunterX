# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool definition builder.

Derives machine-readable :class:`~hunterx.tools.readiness.models.ToolDefinition`
objects from the authoritative Tool Intelligence Platform (TIP) knowledge
contract merged with the trusted static readiness manifest. There is no second
tool registry: the TIP owns identity/capabilities/knowledge and the manifest
only adds the discovery/provisioning facts (binary name, version probe,
install methods, profiles).
"""

from __future__ import annotations

from typing import Any

from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.readiness.manifest import (
    CAPABILITY_LEVELS,
    CAPABILITY_PROVIDERS,
    INPROCESS_TOOLS,
    INSTALL_METHODS,
    PROFILE_TOOLS,
    PROFILES,
    TOOL_BINARY_SPECS,
    TOOL_CLASSIFICATIONS,
    install_methods_for,
)
from hunterx.tools.readiness.models import InstallMethod, ToolDefinition
from hunterx.tools.readiness.platform import PlatformInfo


class ToolDefinitionBuilder:
    """Build :class:`ToolDefinition` objects for registered tools.

    Args:
        tip: the Tool Intelligence API (registry of tool knowledge).
        platform: the detected runtime platform (used to pre-filter install
            methods and to decide ``UNSUPPORTED`` classification).

    """

    def __init__(
        self,
        tip: ToolIntelligenceAPI,
        platform: PlatformInfo | None = None,
    ) -> None:
        self._tip = tip
        self._platform = platform

    def build_all(self) -> list[ToolDefinition]:
        """Return a definition for every integrated tool.

        The base set is every tool registered in the TIP. Tools declared in the
        trusted readiness manifest but not yet registered in the TIP (catalog
        completeness, e.g. ``crt-sh``/``crobat``) are appended so ``hunterx
        tools check`` always reports the full supported CLI catalog and never
        leaves a supported tool in an unexplained gap.
        """
        tool_ids = [metadata.tool_id for metadata in self._tip.list_tools()]
        manifest_ids = set(TOOL_BINARY_SPECS) | set(INSTALL_METHODS) | set(TOOL_CLASSIFICATIONS)
        for tool_id in sorted(manifest_ids - set(tool_ids)):
            tool_ids.append(tool_id)
        return [
            definition
            for tool_id in tool_ids
            if (definition := self.build(tool_id)) is not None
        ]

    def build(self, tool_id: str) -> ToolDefinition | None:
        """Return the definition for ``tool_id`` or ``None`` when unknown."""
        metadata = self._tip.get_tool(tool_id)
        knowledge = self._tip.get_knowledge(tool_id)
        classification = TOOL_CLASSIFICATIONS.get(tool_id, {})
        if metadata is None and tool_id not in TOOL_BINARY_SPECS and tool_id not in INSTALL_METHODS:
            return None

        spec = TOOL_BINARY_SPECS.get(tool_id, {})
        kind = "inprocess" if tool_id in INPROCESS_TOOLS else "binary"
        executable = str(spec.get("executable") or "") or (
            knowledge.cli_binary if knowledge is not None else ""
        )
        aliases = _tuple_of(spec.get("aliases"))
        raw_version_command = spec.get("version_command")
        version_command = ("--version",) if raw_version_command is None else _tuple_of(raw_version_command)
        version_regex = str(spec.get("version_regex") or "")
        min_version = str(spec.get("min_version") or "")
        if not min_version and knowledge is not None:
            for constraint in knowledge.version_constraints:
                if constraint.startswith(">="):
                    min_version = constraint[2:].strip()
                    break

        install_methods = self.install_methods_for(tool_id)
        capabilities = _planner_capabilities(tool_id)
        profiles = _profiles_for(tool_id)
        required = tool_id in INPROCESS_TOOLS

        classification_status = str(classification.get("status") or "")
        classification_reason = str(classification.get("reason") or "")
        remediation = str(classification.get("remediation") or "")
        if not remediation and install_methods:
            remediation = (
                f"provision with 'hunterx tools install {tool_id}'"
                + (f" or profile '{', '.join(profiles) or 'full'}'" if profiles else "")
            )
        cli_only_value = spec.get("cli_only", classification.get("cli_only", "true"))
        cli_only = _as_bool(cli_only_value, default=True)
        expected_identity = str(spec.get("expected_identity") or classification.get("expected_identity") or "")
        homepage = str(spec.get("homepage") or classification.get("homepage") or "")

        return ToolDefinition(
            tool_id=tool_id,
            name=metadata.display_name if metadata is not None else (tool_id.title() if metadata is None else tool_id),
            executable=executable,
            aliases=aliases,
            version_command=version_command,
            version_regex=version_regex,
            min_version=min_version,
            capabilities=capabilities,
            platform_support=metadata.platforms if metadata is not None and metadata.platforms else ("linux", "darwin", "windows"),
            installation_methods=install_methods,
            kind=kind,
            profiles=profiles,
            required=required,
            description=metadata.description if metadata is not None else "",
            cli_only=cli_only,
            expected_identity=expected_identity,
            homepage=homepage,
            classification=classification_status,
            classification_reason=classification_reason,
            remediation=remediation,
        )

    def capability_providers(self) -> dict[str, tuple[str, ...]]:
        """Return the planner capability → provider tool ids mapping."""
        return dict(CAPABILITY_PROVIDERS)

    def capability_levels(self) -> dict[str, Any]:
        """Return the default capability importance mapping."""
        return dict(CAPABILITY_LEVELS)

    def profile_tools(self, profile: str) -> tuple[str, ...]:
        """Return the tool ids included in ``profile`` (empty when unknown)."""
        return PROFILE_TOOLS.get(profile, ())

    def profiles(self) -> tuple[str, ...]:
        """Return the canonical install profile names."""
        return PROFILES

    def install_methods_for(self, tool_id: str) -> tuple[InstallMethod, ...]:
        """Return the trusted install methods for ``tool_id``."""
        if self._platform is None:
            return INSTALL_METHODS.get(tool_id, ())
        return install_methods_for(tool_id, self._platform)


def _planner_capabilities(tool_id: str) -> tuple[str, ...]:
    """Return the planner capabilities provided by ``tool_id``."""
    return tuple(
        capability
        for capability, providers in CAPABILITY_PROVIDERS.items()
        if tool_id in providers
    )


def _profiles_for(tool_id: str) -> tuple[str, ...]:
    """Return the install profiles that include ``tool_id``."""
    profiles: list[str] = []
    for profile, tools in PROFILE_TOOLS.items():
        if tool_id in tools and profile not in profiles:
            profiles.append(profile)
    return tuple(profiles)


def _tuple_of(value: object) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value if item)
    if value:
        return (str(value),)
    return ()


def _as_bool(value: object, *, default: bool = True) -> bool:
    """Coerce a manifest ``cli_only`` value to a boolean."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in ("false", "0", "no", "off"):
        return False
    if normalized in ("true", "1", "yes", "on"):
        return True
    return default


__all__ = ["ToolDefinitionBuilder"]
