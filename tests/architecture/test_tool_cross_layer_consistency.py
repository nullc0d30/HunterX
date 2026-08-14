# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cross-layer tool identity consistency (CI).

Tool Knowledge, Tool Manifest, Tool Discovery, Tool Provisioner, Tool Registry,
Capability Resolver and the CLI must all reference the SAME canonical tool
identity. This test prevents duplicated definitions, inconsistent names and
aliases that resolve incorrectly.
"""

from __future__ import annotations

from hunterx.platform import build_platform
from hunterx.tools.readiness import manifest as _manifest


class TestManifestMatchesTip:
    def test_manifest_tools_exist_in_tip(self) -> None:
        platform = build_platform()
        tip_ids = {metadata.tool_id for metadata in platform.tip.list_tools()}
        missing = [
            tool_id
            for tool_id in (
                *_manifest.INSTALL_METHODS,
                *_manifest.INPROCESS_TOOLS,
                * _manifest.CLAIMED_EXTERNAL_TOOLS,
            )
            if tool_id not in tip_ids
        ]
        assert not missing, f"manifest references tools absent from the TIP: {missing}"

    def test_every_claimed_tool_has_a_definition(self) -> None:
        platform = build_platform()
        for tool_id in _manifest.CLAIMED_EXTERNAL_TOOLS:
            definition = platform.tool_readiness_service.definition(tool_id)
            assert definition is not None, f"no readiness definition for claimed tool '{tool_id}'"

    def test_inprocess_tools_are_not_external_binaries(self) -> None:
        overlap = set(_manifest.INPROCESS_TOOLS) & set(_manifest.INSTALL_METHODS)
        assert not overlap, f"tools marked both in-process and externally installable: {overlap}"


class TestCapabilityProvidersResolve:
    def test_capability_providers_are_registered_tools(self) -> None:
        platform = build_platform()
        tip_ids = {metadata.tool_id for metadata in platform.tip.list_tools()}
        for capability, providers in _manifest.CAPABILITY_PROVIDERS.items():
            for provider in providers:
                assert provider in tip_ids, (
                    f"capability '{capability}' lists unregistered provider '{provider}'"
                )

    def test_capability_provider_has_command_knowledge(self) -> None:
        platform = build_platform()
        for capability, providers in _manifest.CAPABILITY_PROVIDERS.items():
            for provider in providers:
                knowledge = platform.tip.get_knowledge(provider)
                assert knowledge is not None, f"no knowledge for provider '{provider}' of '{capability}'"
                assert knowledge.cli_binary or knowledge.capabilities, provider


class TestCliMatchesRegistry:
    def test_tools_list_matches_tip(self) -> None:
        platform = build_platform()
        listed = {entry["tool_id"] for entry in platform.toolchain_service.list_tools()}
        tip_ids = {metadata.tool_id for metadata in platform.tip.list_tools()}
        assert listed == tip_ids

    def test_no_duplicate_tool_ids(self) -> None:
        platform = build_platform()
        listed = [entry["tool_id"] for entry in platform.toolchain_service.list_tools()]
        assert len(listed) == len(set(listed)), "duplicate tool ids in the toolchain catalog"
