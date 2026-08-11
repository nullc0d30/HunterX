# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the Live Host & Service Discovery capability.

Covers the live discovery security model: command/argument injection through
tool parameters, credential leakage into argv, scope/safety enforcement and
untrusted tool output never being executed.
"""

from __future__ import annotations

from hunterx.domain.livehost.scope import LiveScopeEnforcer, LiveScopePolicy
from hunterx.tools.livehost.masscan import MasscanAdapter
from hunterx.tools.livehost.naabu import NaabuAdapter
from hunterx.tools.livehost.nmap import NmapAdapter
from hunterx.tools.sdk.context import ExecutionContextBuilder


def _context(tool_id: str, *, target: str = "1.2.3.4", params: dict[str, object] | None = None):
    builder = ExecutionContextBuilder(tool_id=tool_id, target=target).with_permissions(("network",))
    if params:
        builder = builder.with_parameters(params)
    return builder.build()


class TestNmapArgvInjection:
    def test_shell_metacharacters_are_not_split(self) -> None:
        adapter = NmapAdapter()
        argv = adapter.build_argv(_context("nmap", target="1.2.3.4; rm -rf /", params={"ports": [22, 443]}))
        assert "1.2.3.4; rm -rf /" in argv
        assert not any(part in (";", "|", "&&", "$(") for part in argv)

    def test_ports_param_cannot_inject_flags(self) -> None:
        adapter = NmapAdapter()
        argv = adapter.build_argv(_context("nmap", params={"ports": [22, "443 -sS"]}))
        assert "-sS" not in argv

    def test_unrelated_credential_params_never_land_in_argv(self) -> None:
        adapter = NmapAdapter()
        argv = adapter.build_argv(
            _context(
                "nmap",
                params={
                    "ports": [22, 443],
                    "api_key": "hunterx-secret-token",
                    "password": "hunterx-pass",
                },
            )
        )
        assert not any("hunterx-secret-token" in arg for arg in argv)
        assert not any("hunterx-pass" in arg for arg in argv)


class TestNaabuArgvInjection:
    def test_ports_param_cannot_inject_flags(self) -> None:
        adapter = NaabuAdapter()
        argv = adapter.build_argv(_context("naabu", params={"ports": [22, "80,443 -rate 100"]}))
        assert "-rate" not in argv
        assert "--" not in argv


class TestMasscanArgvInjection:
    def test_rate_param_is_numeric_only(self) -> None:
        adapter = MasscanAdapter()
        argv = adapter.build_argv(_context("masscan", params={"rate_limit": "1000; rm -rf /"}))
        assert ";" not in argv


class TestLiveScopeSafety:
    def test_out_of_scope_addresses_denied(self) -> None:
        enforcer = LiveScopeEnforcer(LiveScopePolicy(root_cidrs=frozenset({"192.0.2.0/24"})))
        assert not enforcer.allows_address("10.0.0.1").allowed
        assert enforcer.allows_address("192.0.2.5").allowed

    def test_excluded_ports_denied(self) -> None:
        enforcer = LiveScopeEnforcer(LiveScopePolicy(excluded_ports=frozenset({22})))
        assert not enforcer.allows_port(22).allowed
        assert enforcer.allows_port(80).allowed


class TestLiveUntrustedOutput:
    def test_malformed_output_is_skipped_not_executed(self) -> None:
        from hunterx.tools.livehost.masscan import MasscanAdapter
        from hunterx.tools.recon.runner import CommandResult

        adapter = MasscanAdapter()
        result = CommandResult(
            returncode=0,
            stdout='{"ip":"1.2.3.4","ports":[{"port":22,"proto":"tcp","status":"open","reason":"syn-ack"}]}\n'
            '__import__("os").system("rm -rf /")\n',
        )
        observations = adapter.parse_output(_context("masscan"), result)
        assert observations
        from hunterx.domain.livehost.models import LiveHost, PortFinding

        assert any(isinstance(observation, (LiveHost, PortFinding)) for observation in observations)
        # The injected python payload is data, never executed; only 2 observations survive.
        assert len(observations) == 2

    def test_bogus_output_produces_no_observations(self) -> None:
        from hunterx.tools.livehost.naabu import NaabuAdapter
        from hunterx.tools.recon.runner import CommandResult

        adapter = NaabuAdapter()
        result = CommandResult(returncode=0, stdout="garbage line\nnot json\n")
        assert adapter.parse_output(_context("naabu"), result) == []
