# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Command/argument injection resistance (Sprint 034.4 §5, §6).

Every subprocess invocation in the Tool Integration SDK must pass a structural
argv (never a shell string), and target-derived values must remain data rather
than becoming options or additional flags.
"""

from __future__ import annotations

import ast
import sys

import pytest

from hunterx.domain.exceptions import ToolExecutionError
from hunterx.tools.recon.runner import BinaryRunner, guard_option_value, guard_positional_target

_HOSTILE = (
    "; rm -rf /",
    "| shutdown",
    "`id`",
    "$(whoami)",
    "--script=http-shellshock",
    "-Pn -p 1-65535",
    "-o /tmp/pwn",
    "evil.com\n--data 'x'",
    "example.com && echo pwned",
)


def _context(target: str, params: dict | None = None) -> object:
    from hunterx.domain.execution import ExecutionContext

    return ExecutionContext(tool_id="t", target=target, parameters=params or {})


# -- structural invocation -----------------------------------------------------


def test_runner_never_uses_a_shell() -> None:
    """The source tree must not contain shell-invocation subprocess calls."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[3] / "src"
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        if "__pycache__" in str(path):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = None
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                name = func.id
            if name not in ("system", "popen", "run", "Popen"):
                continue
            for keyword in node.keywords:
                if keyword.arg == "shell" and _ast_bool_true(keyword.value):
                    offenders.append(f"{path.relative_to(root)}:{node.lineno}")
    assert not offenders, "shell-invocation paths found:\n" + "\n".join(offenders)


def _ast_bool_true(value: ast.AST) -> bool:
    return isinstance(value, ast.Constant) and value.value is True


def test_hostile_target_stays_a_single_argv_element() -> None:
    """A hostile target is one argv element; metacharacters cannot split it."""
    argv = ["subfinder", "-d", "; rm -rf /; echo", "-silent"]
    assert len(argv) == 4
    assert argv[2] == "; rm -rf /; echo"


_OPTION_LIKE = [payload for payload in _HOSTILE if payload.lstrip().startswith("-")]


@pytest.mark.parametrize("payload", _OPTION_LIKE)
def test_positional_guard_rejects_option_like_targets(payload: str) -> None:
    with pytest.raises(ToolExecutionError):
        guard_positional_target(payload, label="target")


@pytest.mark.parametrize("payload", [p for p in _HOSTILE if not p.lstrip().startswith("-")])
def test_shell_metacharacters_remain_inert_data(payload: str) -> None:
    """Shell metacharacters without a leading '-' are inert inside argv."""
    assert guard_positional_target(payload) == payload


def test_positional_guard_accepts_legitimate_targets() -> None:
    for value in ("example.com", "sub.example.com", "203.0.113.1", "10.0.0.0/24", "https://example.com/a"):
        assert guard_positional_target(value) == value


def test_option_value_guard_rejects_option_like_values() -> None:
    with pytest.raises(ToolExecutionError):
        guard_option_value("--data=1", label="url")


# -- adapters that place the target as a bare positional ------------------------


@pytest.mark.parametrize(
    "adapter_path, tool",
    [
        ("hunterx.tools.livehost.nmap", "NmapAdapter"),
        ("hunterx.tools.livehost.masscan", "MasscanAdapter"),
        ("hunterx.tools.recon.assetfinder", "AssetfinderAdapter"),
        ("hunterx.tools.topology.traceroute", "TracerouteAdapter"),
        ("hunterx.tools.tech.whatweb", "WhatWebAdapter"),
    ],
)
def test_positional_target_adapters_block_option_injection(adapter_path: str, tool: str) -> None:
    import importlib

    module = importlib.import_module(adapter_path)
    adapter = getattr(module, tool)()
    with pytest.raises(ToolExecutionError):
        adapter.build_argv(_context("--script=http-shellshock", {"ports": [80]}))
    with pytest.raises(ToolExecutionError):
        adapter.build_argv(_context("-Pn -p 1-65535", {"ports": [80]}))


def test_flag_value_target_adapters_pass_target_as_single_argument() -> None:
    """Targets passed as flag values stay one argv element (never re-parsed)."""
    from hunterx.tools.content.ffuf import FfufAdapter
    from hunterx.tools.dns.dnsx import DnsxAdapter
    from hunterx.tools.livehost.naabu import NaabuAdapter
    from hunterx.tools.recon.subfinder import SubfinderAdapter
    from hunterx.tools.tech.httpx import HttpxAdapter
    from hunterx.tools.vuln.nuclei import NucleiAdapter
    from hunterx.tools.web.katana import KatanaAdapter

    cases = [
        (FfufAdapter(), "-u", "https://example.com -x all"),
        (DnsxAdapter(), "-d", "example.com;id"),
        (NaabuAdapter(), "-host", "10.0.0.1 --rate 0"),
        (SubfinderAdapter(), "-d", "example.com -oJ"),
        (HttpxAdapter(), "-u", "https://example.com --follow"),
        (NucleiAdapter(), "-u", "https://example.com;cat /etc/passwd"),
        (KatanaAdapter(), "-u", "https://example.com -x all"),
    ]
    for adapter, flag, target in cases:
        argv = adapter.build_argv(_context(target))
        flag_index = argv.index(flag)
        value = argv[flag_index + 1]
        assert value == target, f"{adapter.descriptor.name}: target was mangled"


# -- binary runner start failures -----------------------------------------------


def test_runner_reports_missing_binary_as_tool_error() -> None:
    runner = BinaryRunner(max_output_bytes=65536)
    with pytest.raises(ToolExecutionError):
        runner.run(["_hunterx_no_such_binary_", "-flag"])


def test_runner_uses_trusted_argv_for_real_execution() -> None:
    runner = BinaryRunner(max_output_bytes=65536)
    result = runner.run([sys.executable, "-c", "import sys; print(sys.argv[1])", ";touch /tmp/pwn"])
    assert result.returncode == 0
    assert result.stdout.strip() == ";touch /tmp/pwn"
