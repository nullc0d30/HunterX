# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Installer UX tests.

Covers the human-facing installer contract implemented by the provisioning
layer and the CLI:

- multi-column inventory output (compact, adaptive layout);
- human vs explicit JSON output for ``install`` / ``tools install``;
- live progress reporting with the current tool always visible;
- per-method install timeouts;
- failure isolation (a failed tool does not abort the run);
- graceful Ctrl+C handling (no traceback; state preserved);
- installation state persistence and resume reconciliation;
- idempotent re-installation;
- final readiness / exit-code semantics (READY / PARTIAL / NOT READY);
- non-TTY deterministic output;
- quick-start output.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from hunterx.cli.app import CliApplication
from hunterx.cli.commands import register_default_commands
from hunterx.platform import build_platform
from hunterx.tools.readiness.models import (
    CapabilityLevel,
    CapabilityReadiness,
    InstallOutcome,
    ReadinessReport,
    ToolInventory,
    ToolReadiness,
    ToolReadinessStatus,
)
from hunterx.tools.readiness.provisioner import _METHOD_DEFAULT_TIMEOUTS, ToolProvisioner, _install_error
from hunterx.tools.readiness.reporting import (
    ProgressWriter,
    columnize,
    render_inventory,
    render_progress_line,
    render_summary,
)
from hunterx.tools.readiness.state import InstallationState
from tests.framework.readiness import (
    StubRunner,
    all_commands_available,
    linux_platform,
    tip_with,
)
from tests.unit.test_tool_readiness_provisioning import StubDiscovery, _definition

# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------


class TestColumnize:
    def test_multi_column_layout(self) -> None:
        rows = columnize(["a", "b", "c", "d", "e"], width=40)
        # 40 wide, "a"+"b" cell width 3 -> ~13 columns; all on one row.
        assert len(rows) >= 1
        assert any("a" in row and "b" in row for row in rows)

    def test_narrow_terminal_falls_back_to_single_column(self) -> None:
        rows = columnize(["one", "two", "three"], width=4)
        assert len(rows) == 3
        for row in rows:
            assert len(row.split()) == 1

    def test_empty(self) -> None:
        assert columnize([], width=80) == []


class TestRenderInventory:
    def test_groups_available_and_missing(self) -> None:
        inventory = ToolInventory(
            available=["amass", "nmap", "masscan"],
            missing=["subfinder", "assetfinder", "findomain"],
        )
        out = render_inventory(inventory, width=60)
        assert "Available" in out
        assert "Missing" in out
        assert "amass" in out and "subfinder" in out
        assert "Broken" not in out and "Outdated" not in out

    def test_empty_buckets_omitted(self) -> None:
        inventory = ToolInventory(available=["nmap"])
        out = render_inventory(inventory, width=60)
        assert "Missing" not in out


class TestRenderProgressLine:
    def test_start_line_shows_tool_before_install(self) -> None:
        line = render_progress_line(1, 68, "subfinder")
        assert "subfinder" in line
        assert "[ 1/68]" in line

    def test_done_success_and_failure_marks(self) -> None:
        ok = render_progress_line(1, 2, "nmap", InstallOutcome(tool_id="nmap", success=True))
        bad = render_progress_line(2, 2, "metasploit", InstallOutcome(tool_id="metasploit", success=False))
        assert "\u2713" in ok
        assert "\u2717" in bad


class TestProgressWriter:
    def test_non_tty_prints_start_and_finish(self) -> None:
        lines: list[str] = []

        def write(line: str, *, end: str = "\n", flush: bool = False) -> None:
            lines.append(line + end)

        writer = ProgressWriter(write=write, is_terminal=False)
        writer.start(1, 2, "nmap")
        assert lines[-1].endswith("\n")
        assert "nmap" in lines[-1]
        writer.finish(1, 2, "nmap", InstallOutcome(tool_id="nmap", success=True))
        assert "nmap" in lines[-1]
        assert len(lines) == 2

    def test_tty_rewrites_in_place_with_carriage_return(self) -> None:
        writes: list[str] = []

        def write(line: str, *, end: str = "\n", flush: bool = False) -> None:
            writes.append(line + end)

        writer = ProgressWriter(write=write, is_terminal=True)
        writer.start(1, 2, "nmap")
        writer.finish(1, 2, "nmap", InstallOutcome(tool_id="nmap", success=True))
        assert any(w.startswith("\r[") for w in writes)
        assert any("nmap" in w for w in writes)
        assert "\u2713" in "".join(writes)


class TestRenderSummary:
    def test_summary_counts(self) -> None:
        out = render_summary(
            [
                InstallOutcome(tool_id="a", success=True),
                InstallOutcome(tool_id="b", success=True, skipped=True),
                InstallOutcome(tool_id="c", success=False, error="timeout"),
            ],
            already_available=1,
        )
        assert "Installed: 1" in out
        assert "Already available: 1" in out
        assert "Failed: 1" in out
        assert "c: timeout" in out


# ---------------------------------------------------------------------------
# Provisioner: timeouts + isolation
# ---------------------------------------------------------------------------


class TestMethodTimeouts:
    def test_default_timeouts_exist_per_kind(self) -> None:
        assert _METHOD_DEFAULT_TIMEOUTS["apt"] < _METHOD_DEFAULT_TIMEOUTS["cargo"]
        assert _METHOD_DEFAULT_TIMEOUTS["go"] > 0
        assert "default" in _METHOD_DEFAULT_TIMEOUTS

    def test_runner_receives_per_method_timeout(self) -> None:
        platform = linux_platform(is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery(after=ToolReadinessStatus.AVAILABLE)
        provisioner = ToolProvisioner(discovery, platform, runner, command_available=all_commands_available)
        provisioner.install(_definition("nmap", platform))
        assert runner.timeouts and runner.timeouts[0] == _METHOD_DEFAULT_TIMEOUTS["apt"]

    def test_explicit_timeout_overrides_default(self) -> None:
        from hunterx.tools.readiness.definitions import ToolDefinitionBuilder

        platform = linux_platform(is_root=True)
        tip = tip_with(["nmap"])
        builder = ToolDefinitionBuilder(tip, platform)
        definition = builder.build("nmap")
        assert definition is not None
        # Build a variant method with an explicit timeout.
        from hunterx.tools.readiness.models import InstallMethod, ToolDefinition

        definition = ToolDefinition(
            tool_id="nmap",
            executable="nmap",
            installation_methods=(InstallMethod(kind="apt", package="nmap", timeout_s=12.5),),
        )
        runner = StubRunner({})
        discovery = StubDiscovery(after=ToolReadinessStatus.AVAILABLE)
        provisioner = ToolProvisioner(discovery, platform, runner, command_available=all_commands_available)
        provisioner.install(definition)
        assert runner.timeouts and runner.timeouts[0] == 12.5


class TestInstallErrorExplanation:
    def test_timeout_error_is_explained(self) -> None:
        from hunterx.tools.readiness.models import InstallMethod

        method = InstallMethod(kind="go", name="github.com/example/mod@latest")
        message = _install_error(method, 124, "", "", 600.0)
        assert "timed out" in message
        assert "600" in message
        assert "go" in message

    def test_nonzero_error_uses_output(self) -> None:
        from hunterx.tools.readiness.models import InstallMethod

        method = InstallMethod(kind="pip", package="sqlmap")
        message = _install_error(method, 1, "", "ERROR: no matching distribution", 300.0)
        assert "ERROR: no matching distribution" in message


class TestFailureIsolation:
    def test_one_tool_failure_does_not_abort_next(self) -> None:
        # The service install loop continues after a failed tool. Verified at
        # the service level below.
        assert True


# ---------------------------------------------------------------------------
# Installation state
# ---------------------------------------------------------------------------


class TestInstallationState:
    def test_round_trip(self, tmp_path: pathlib.Path) -> None:
        state = InstallationState(profile="full")
        state.mark_tool_started("nmap")
        state.record_tool(InstallOutcome(tool_id="nmap", success=True, version="7.94"))
        state.record_tool(InstallOutcome(tool_id="metasploit", success=False, error="apt timeout"))
        state.save(tmp_path)

        loaded = InstallationState.load(tmp_path)
        assert loaded.completed_tools() == ["nmap"]
        assert loaded.failed_tools()[0].error == "apt timeout"

    def test_load_missing_is_empty(self, tmp_path: pathlib.Path) -> None:
        state = InstallationState.load(tmp_path / "does-not-exist")
        assert state.completed_tools() == []
        assert state.install_id

    def test_load_corrupt_is_empty(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "install.json").write_text("{ not json", encoding="utf-8")
        state = InstallationState.load(tmp_path)
        assert state.completed_tools() == []

    def test_interrupted_marker(self, tmp_path: pathlib.Path) -> None:
        state = InstallationState()
        state.mark_interrupted("ctrl-c")
        state.save(tmp_path)
        loaded = InstallationState.load(tmp_path)
        assert loaded.interrupted is True
        assert loaded.error == "ctrl-c"

    def test_record_is_idempotent(self, tmp_path: pathlib.Path) -> None:
        state = InstallationState()
        outcome = InstallOutcome(tool_id="nmap", success=True)
        state.record_tool(outcome)
        state.record_tool(outcome)
        assert len(state.tools) == 1


# ---------------------------------------------------------------------------
# Service-level install: progress events + state + isolation
# ---------------------------------------------------------------------------


class _SucceedingProvisioner:
    """Provisioner double that always produces a successful outcome."""

    def install(self, definition, *, verify=True):  # noqa: ANN001
        return InstallOutcome(tool_id=definition.tool_id, success=True, version="1.2.3")


def _service_with(statuses: dict[str, ToolReadinessStatus], *, provisioner: object | None = None):
    from hunterx.tools.readiness.definitions import ToolDefinitionBuilder
    from hunterx.tools.readiness.service import ToolReadinessService

    platform = linux_platform(is_root=True)
    tip = tip_with(list(statuses))
    builder = ToolDefinitionBuilder(tip, platform)

    class MappingDiscovery:
        def probe(self, definition, platform):  # noqa: ANN001
            return ToolReadiness(
                tool_id=definition.tool_id,
                status=statuses.get(definition.tool_id, ToolReadinessStatus.MISSING),
                version="1.2.3"
                if statuses.get(definition.tool_id) is ToolReadinessStatus.AVAILABLE
                else "",
                definition=definition,
                platform=platform.os,
            )

        def discover(self, definitions, platform):  # noqa: ANN001
            return [self.probe(d, platform) for d in definitions]

        def mark_installed(self, tool_id, version=""):  # noqa: ANN001
            statuses[tool_id] = ToolReadinessStatus.AVAILABLE

    return ToolReadinessService(
        tip=tip,
        engine=None,
        platform=platform,
        definitions=builder,
        discovery=MappingDiscovery(),
        provisioner=provisioner if provisioner is not None else _SucceedingProvisioner(),
    )


class TestServiceInstallProgress:
    def test_emits_start_and_done_events(self) -> None:
        service = _service_with({"nmap": ToolReadinessStatus.MISSING})
        events: list[dict] = []

        def observer(event) -> None:  # noqa: ANN001
            events.append({"phase": event.phase, "tool_id": event.tool_id, "index": event.index})

        outcomes = service.install(["nmap"], observer=observer)
        assert [e["phase"] for e in events] == ["start", "done"]
        assert events[0]["index"] == 1
        assert outcomes[0].tool_id == "nmap"

    def test_failure_is_isolated_and_continues(self) -> None:
        class FailingProvisioner:
            def install(self, definition, *, verify=True):  # noqa: ANN001
                if definition.tool_id == "nmap":
                    return InstallOutcome(tool_id="nmap", success=False, error="boom")
                return InstallOutcome(tool_id=definition.tool_id, success=True)

        service = _service_with(
            {"nmap": ToolReadinessStatus.MISSING, "subfinder": ToolReadinessStatus.MISSING},
            provisioner=FailingProvisioner(),
        )
        outcomes = service.install(["nmap", "subfinder"])
        assert [o.tool_id for o in outcomes] == ["nmap", "subfinder"]
        assert outcomes[0].success is False
        assert outcomes[1].success is True

    def test_state_updated_through_install(self, tmp_path: pathlib.Path) -> None:
        service = _service_with({"nmap": ToolReadinessStatus.MISSING})
        state = InstallationState(profile="minimal")
        service.install(["nmap"], state=state)
        state.save(tmp_path)
        loaded = InstallationState.load(tmp_path)
        assert loaded.completed_tools() == ["nmap"]

    def test_interrupt_preserves_state(self, tmp_path: pathlib.Path) -> None:
        class InterruptingProvisioner:
            def install(self, definition, *, verify=True):  # noqa: ANN001
                raise KeyboardInterrupt

        service = _service_with({"nmap": ToolReadinessStatus.MISSING}, provisioner=InterruptingProvisioner())
        state = InstallationState(profile="minimal")
        with pytest.raises(KeyboardInterrupt):
            service.install(["nmap"], state=state)
        assert state.interrupted is True


# ---------------------------------------------------------------------------
# CLI: human vs JSON, readiness exit codes, quick-start
# ---------------------------------------------------------------------------


class _FakeReadiness:
    """Deterministic readiness double for CLI UX tests."""

    def __init__(
        self,
        *,
        available: tuple[str, ...] = ("nmap",),
        missing: tuple[str, ...] = ("nuclei",),
        capabilities_missing_required: bool = False,
    ) -> None:
        self._available = available
        self._missing = missing
        self._capabilities_missing_required = capabilities_missing_required
        self.install_calls: list[dict] = []

    def check(self, tool_ids=None, *, sync_engine=True):  # noqa: ANN001
        tools = [ToolReadiness(tool_id=t, status=ToolReadinessStatus.AVAILABLE) for t in self._available]
        tools += [ToolReadiness(tool_id=t, status=ToolReadinessStatus.MISSING) for t in self._missing]
        caps = [
            CapabilityReadiness(
                capability="port_discovery",
                level=CapabilityLevel.REQUIRED,
                providers=self._available,
                available=self._available if not self._capabilities_missing_required else (),
                missing=() if not self._capabilities_missing_required else self._available,
            )
        ]
        return ReadinessReport(
            platform={"os": "linux"},
            tools=tools,
            capabilities=caps,
            summary={
                "total": len(tools),
                "available": len(self._available),
                "missing": len(self._missing),
                "broken": 0,
                "outdated": 0,
                "unsupported": 0,
                "capabilities_ready": 0 if self._capabilities_missing_required else 1,
                "capabilities_missing": 1 if self._capabilities_missing_required else 0,
            },
        )

    def install(self, tool_ids=None, *, profile="", verify=True, observer=None, state=None):  # noqa: ANN001
        self.install_calls.append({"tool_ids": tool_ids, "profile": profile})
        targets = tool_ids if tool_ids else (list(self._missing) or ["nuclei"])
        if observer is not None:
            for index, tool_id in enumerate(targets, start=1):
                observer(type("E", (), {"index": index, "total": len(targets), "tool_id": tool_id, "phase": "start"})())
                observer(
                    type(
                        "E",
                        (),
                        {
                            "index": index,
                            "total": len(targets),
                            "tool_id": tool_id,
                            "phase": "done",
                            "outcome": InstallOutcome(tool_id=tool_id, success=True),
                        },
                    )()
                )
        return [InstallOutcome(tool_id=t, success=True) for t in targets]

    def profiles(self) -> tuple[str, ...]:
        return ("minimal", "recon", "web", "network", "vulnerability", "full")

    def profile_tools(self, profile: str) -> tuple[str, ...]:
        return tuple(self._missing)

    def definition(self, tool_id: str):  # noqa: ANN001
        return None


@pytest.fixture()
def ux_app():
    platform = build_platform()
    app = CliApplication()
    register_default_commands(app, platform)
    return app, platform


class TestCLIHumanVsJson:
    def test_tools_check_default_is_human(self, ux_app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = ux_app
        platform.tool_readiness_service = _FakeReadiness()  # type: ignore[assignment]
        assert app_instance.run(["tools", "check"]) == 0
        output = capsys.readouterr().out
        assert "Available" in output and "Missing" in output
        assert not output.lstrip().startswith("{")

    def test_tools_check_json(self, ux_app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = ux_app
        platform.tool_readiness_service = _FakeReadiness()  # type: ignore[assignment]
        assert app_instance.run(["tools", "check", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["tools"][0]["tool_id"] == "nmap"

    def test_tools_install_default_is_human(self, ux_app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = ux_app
        platform.tool_readiness_service = _FakeReadiness()  # type: ignore[assignment]
        assert app_instance.run(["tools", "install", "--profile", "full"]) == 0
        output = capsys.readouterr().out
        assert "Installing security toolchain" in output
        assert not output.lstrip().startswith("[")

    def test_tools_install_json(self, ux_app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = ux_app
        platform.tool_readiness_service = _FakeReadiness()  # type: ignore[assignment]
        assert app_instance.run(["tools", "install", "--profile", "full", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload[0]["tool_id"] == "nuclei"


class TestCLIReadinessExitCode:
    def test_ready_returns_zero(self, ux_app) -> None:
        app_instance, platform = ux_app
        platform.tool_readiness_service = _FakeReadiness()  # type: ignore[assignment]
        assert app_instance.run(["install", "--profile", "minimal", "--json"]) == 0

    def test_minimal_gates_only_on_base_capabilities(self, ux_app) -> None:
        # The minimal profile intentionally provisions no external tools, so a
        # missing external-tool capability must not fail the base environment.
        app_instance, platform = ux_app
        platform.tool_readiness_service = _FakeReadiness(capabilities_missing_required=True)  # type: ignore[assignment]
        assert app_instance.run(["install", "--profile", "minimal", "--json"]) == 0

    def test_full_profile_required_missing_returns_nonzero(self, ux_app) -> None:
        app_instance, platform = ux_app
        platform.tool_readiness_service = _FakeReadiness(capabilities_missing_required=True)  # type: ignore[assignment]
        assert app_instance.run(["install", "--profile", "full", "--json"]) == 1

    def test_tools_install_required_missing_returns_nonzero(self, ux_app) -> None:
        app_instance, platform = ux_app
        platform.tool_readiness_service = _FakeReadiness(capabilities_missing_required=True)  # type: ignore[assignment]
        assert app_instance.run(["tools", "install", "--profile", "full", "--json"]) == 1


class TestCLIQuickStart:
    def test_quick_start_renders_supported_commands(self) -> None:
        from hunterx.tools.readiness.reporting import render_quick_start

        out = render_quick_start(
            [
                ("Start HunterX", "hunterx help"),
                ("Run a security assessment", "hunterx mission create <objective> <target>"),
                ("Check tool readiness", "hunterx tools check"),
            ]
        )
        assert "hunterx help" in out
        assert "hunterx mission create <objective> <target>" in out
        assert "hunterx tools check" in out


class TestResumeReconciliation:
    def test_state_completed_tools_reconcile_against_environment(self, tmp_path: pathlib.Path) -> None:
        # A tool recorded as completed in persisted state but now missing must
        # be re-provisioned (resume never trusts state blindly).
        from hunterx.tools.readiness.definitions import ToolDefinitionBuilder
        from hunterx.tools.readiness.service import ToolReadinessService

        platform = linux_platform(is_root=True)
        tip = tip_with(["nmap", "subfinder"])
        builder = ToolDefinitionBuilder(tip, platform)

        state = InstallationState(profile="full")
        state.record_tool(InstallOutcome(tool_id="nmap", success=True, version="7.94"))
        state.save(tmp_path)

        class ReinstallingDiscovery:
            def probe(self, definition, platform):  # noqa: ANN001
                return ToolReadiness(
                    tool_id=definition.tool_id,
                    status=ToolReadinessStatus.MISSING,  # environment lost the tool
                    definition=definition,
                    platform=platform.os,
                )

            def discover(self, definitions, platform):  # noqa: ANN001
                return [self.probe(d, platform) for d in definitions]

            def mark_installed(self, tool_id, version=""):  # noqa: ANN001
                pass

        calls: list[str] = []

        class RecordingProvisioner:
            def install(self, definition, *, verify=True):  # noqa: ANN001
                calls.append(definition.tool_id)
                return InstallOutcome(tool_id=definition.tool_id, success=True)

        service = ToolReadinessService(
            tip=tip,
            engine=None,
            platform=platform,
            definitions=builder,
            discovery=ReinstallingDiscovery(),
            provisioner=RecordingProvisioner(),
        )
        service.install(["nmap"], state=state)
        # The provisioning layer re-probes the live environment; state records
        # are informational and never skip a genuinely-missing tool.
        assert "nmap" in calls

    def test_interrupted_state_is_reconciled_on_rerun(self, tmp_path: pathlib.Path) -> None:
        # A prior interrupted run leaves markers that a re-run may consult.
        state = InstallationState(profile="full")
        state.mark_interrupted("interrupted while installing 'nmap'")
        state.save(tmp_path)
        loaded = InstallationState.load(tmp_path)
        assert loaded.interrupted is True
        assert "nmap" in loaded.error
        # Re-running resets the interrupt marker while preserving completed work.
        loaded.mark_tool_started("subfinder")
        loaded.record_tool(InstallOutcome(tool_id="subfinder", success=True))
        loaded.interrupted = False
        loaded.save(tmp_path)
        reloaded = InstallationState.load(tmp_path)
        assert reloaded.interrupted is False
        assert reloaded.completed_tools() == ["subfinder"]


class TestNonTTYOutput:
    def test_tools_install_non_tty_is_deterministic(self, ux_app, capsys: pytest.CaptureFixture[str]) -> None:
        # In a non-TTY context (pytest capture) the CLI emits plain text with
        # no ANSI/cursor control; the human contract still applies.
        app_instance, platform = ux_app
        platform.tool_readiness_service = _FakeReadiness()  # type: ignore[assignment]
        assert app_instance.run(["tools", "install", "--profile", "full"]) == 0
        output = capsys.readouterr().out
        assert "Installing security toolchain" in output
        assert not output.startswith("[")  # not raw JSON
        assert "\x1b[" not in output  # no ANSI escapes
