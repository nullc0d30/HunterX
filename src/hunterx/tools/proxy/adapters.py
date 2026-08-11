# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Proxy / interception tool adapters.

Integrates ``zap`` (OWASP ZAP baseline scanner) and ``mitmproxy`` (traffic
interception) into the Tool Integration SDK. External binaries run through the
shared runner seam and emit canonical observations.

Interception traffic and scanner alerts are evidence data. ZAP alert lines are
candidates requiring validation; mitmproxy captures are artifacts referenced by
path, never opened by the SDK.
"""

from __future__ import annotations

import abc
import re
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector

_ZAP_ALERT_RE = re.compile(r"(FAIL-NEW|WARN-NEW|FAIL-INPROG|WARN-INPROG|INFO|PASS)\s*:\s*(.*)", re.IGNORECASE)


class ProxyToolAdapter(ToolAdapter, abc.ABC):
    """Shared base for SDK proxy/interception adapters."""

    descriptor: ToolDescriptor

    def __init__(self, runner: BinaryRunner | None = None) -> None:
        self._runner = runner or BinaryRunner()

    @property
    def runner(self) -> BinaryRunner:
        """Return the binary runner used by this adapter."""
        return self._runner

    def prepare(self, context: ExecutionContext) -> None:
        """No setup required; hook kept for parity."""

    def cleanup(self, context: ExecutionContext) -> None:
        """Nothing to release; hook kept for parity."""

    @abc.abstractmethod
    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Return the full command line for ``context``."""

    @abc.abstractmethod
    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Convert the captured tool output into canonical observations."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Invoke the binary, capture output and emit observations."""
        argv = self.build_argv(context)
        timeout = context.timeout_effective or 0.0
        result = self._runner.run(argv, timeout_s=timeout, tool_id=context.tool_id)
        collector.set_exit_code(result.returncode)
        if result.stdout:
            collector.attach_stdout(result.stdout)
        if result.stderr:
            collector.attach_stderr(result.stderr)
        records = self.parse_output(context, result)
        collector.set_json(self._payload(records))

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; empty observation sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        if not output.has_content:
            errors.append("no output produced")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project proxy observations into the legacy asset surface."""
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        payload = output.json
        if isinstance(payload, dict) and isinstance(payload.get("observations"), list):
            tool_output.assets = [entry for entry in payload["observations"] if isinstance(entry, dict)]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    @staticmethod
    def _payload(records: list[dict[str, Any]]) -> dict[str, Any]:
        return {"observations": records, "count": len(records)}

    def _param(self, context: ExecutionContext, name: str, default: Any = None) -> Any:
        return context.parameters.get(name, default)

    def _param_int(self, context: ExecutionContext, name: str, default: int) -> int:
        try:
            return int(self._param(context, name, default))
        except (TypeError, ValueError):
            return default

    def _param_bool(self, context: ExecutionContext, name: str, default: bool) -> bool:
        value = self._param(context, name, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes")


class ZapAdapter(ProxyToolAdapter):
    """SDK adapter for the ``zap-baseline`` active scanner."""

    descriptor = ToolDescriptor(
        name="zap",
        version="2.15.0",
        description="OWASP ZAP baseline passive/active web scanner.",
        entrypoint="hunterx.tools.proxy.adapters:ZapAdapter",
        targets=("url",),
        capabilities=("vulnerability-scan", "web-vulnerability-detection", "proxy-inspection"),
        permissions=("network",),
        parameters={
            "url": {"type": "string", "description": "Target URL (defaults to execution target)."},
            "active": {"type": "boolean", "description": "Run the active scanner (vs passive baseline)."},
            "lurker": {"type": "boolean", "description": "Enable the spider/lurker."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        target = str(context.parameters.get("url") or context.target)
        argv = ["zap-baseline.py", "-t", target, "-J", "-"]
        if self._param_int(context, "active", 0) or self._param_bool(context, "active", False):
            argv.append("-a")
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        records: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            match = _ZAP_ALERT_RE.match(line.strip())
            if not match:
                continue
            state, detail = match.group(1).upper(), match.group(2).strip()
            if state in ("PASS",):
                continue
            records.append(
                {
                    "kind": "zap-alert",
                    "state": state,
                    "detail": detail,
                    "vulnerability_class": "web-vulnerability",
                    "severity": "high" if state.startswith("FAIL") else "medium",
                    "confidence": 0.6,
                    "requires_validation": True,
                    "tool_id": "zap",
                    "correlation_id": context.correlation_id,
                    "mission_id": context.mission_id,
                    "execution_id": context.execution_id,
                }
            )
        return records


class MitmproxyAdapter(ProxyToolAdapter):
    """SDK adapter for ``mitmproxy`` traffic interception.

    The adapter starts ``mitmdump`` with a bounded timeout to capture in-scope
    traffic to a flow file and emits a capture observation referencing the
    artifact. Captured traffic is evidence data referenced by path; the SDK
    never opens or replays it automatically.
    """

    descriptor = ToolDescriptor(
        name="mitmproxy",
        version="10.4.0",
        description="Interactive HTTPS interception proxy (mitmdump capture).",
        entrypoint="hunterx.tools.proxy.adapters:MitmproxyAdapter",
        targets=("url", "host"),
        capabilities=("proxy-inspection", "traffic-capture", "http-interception"),
        permissions=("network",),
        parameters={
            "capture_file": {"type": "string", "description": "Path where the flow capture is written (artifact)."},
            "listen_port": {"type": "integer", "description": "Proxy listen port."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        capture_file = context.parameters.get("capture_file")
        if not isinstance(capture_file, str) or not capture_file:
            raise ValueError("mitmproxy requires a 'capture_file' parameter")
        argv = ["mitmdump", "-w", capture_file, "-q"]
        port = self._param_int(context, "listen_port", 0)
        if port > 0:
            argv += ["--listen-port", str(port)]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        capture_file = str(context.parameters.get("capture_file") or "")
        return [
            {
                "kind": "traffic-capture",
                "detail": f"mitmdump capture started on {capture_file}",
                "capture_file": capture_file,
                "tool_id": "mitmproxy",
                "correlation_id": context.correlation_id,
                "mission_id": context.mission_id,
                "execution_id": context.execution_id,
            }
        ]


__all__ = ["ZapAdapter", "MitmproxyAdapter"]
