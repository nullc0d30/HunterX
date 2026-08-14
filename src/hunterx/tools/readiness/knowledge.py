# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Executable command knowledge for the integrated external toolchain.

Machine-actionable invocation knowledge (command, arguments, argument types,
defaults, output formats, parser, supported modes, target binding) for every
external tool HunterX claims to integrate. This module enriches the canonical
Tool Intelligence Platform (TIP) registry — the TIP remains the single source
of truth. There is no second tool registry and no second tool list.

Registration is additive and idempotent: fields already populated by the
platform tool registrations are never overwritten.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from hunterx.domain.tool_intelligence import (
    ToolArgument,
    ToolExecutionMode,
    ToolInputContract,
    ToolSafetyClass,
    ToolSafetyProfile,
)
from hunterx.tools.intelligence.api import ToolIntelligenceAPI

#: Per-tool command knowledge merged into the TIP knowledge contract.
#: Keys: cli_binary, arguments, outputs (formats/parser/normalizer), safe_mode,
#: inputs (accepts/required/optional), modes, safety_class.
COMMAND_KNOWLEDGE: dict[str, dict[str, Any]] = {
    # -- content discovery ----------------------------------------------------
    "feroxbuster": {
        "cli_binary": "feroxbuster",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("url", "-u", "string", required=True, description="Target base URL."),
            ToolArgument("wordlist", "-w", "path", required=True, description="Wordlist data file path."),
            ToolArgument("threads", "-t", "int", description="Concurrent scan threads."),
            ToolArgument("rate_limit", "--rate-limit", "int", description="Maximum requests per second."),
            ToolArgument("timeout", "--timeout", "int", description="Per-request timeout in seconds."),
            ToolArgument("output", "-o", "path", description="JSON report artifact path."),
        ),
        "inputs": {
            "accepts": ("url",),
            "required": ("url", "wordlist"),
            "optional": ("threads", "rate_limit", "timeout", "output"),
        },
        "outputs": {
            "formats": ("json",),
            "parser": "feroxbuster-json",
            "normalizer": "content-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="Recursive content discovery.", safe=False),),
        "safe_mode": "scan",
    },
    "gobuster": {
        "cli_binary": "gobuster",
        "cli_structure": "subcommand",
        "arguments": (
            ToolArgument("mode", "", "string", required=True, choices=("dir", "dns", "vhost", "fuzz"), description="Gobuster mode."),
            ToolArgument("url", "-u", "string", description="Target URL (dir/vhost/fuzz modes)."),
            ToolArgument("wordlist", "-w", "path", required=True, description="Wordlist data file path."),
            ToolArgument("threads", "-t", "int", description="Concurrent threads."),
            ToolArgument("status_codes", "-s", "string", description="HTTP status codes to include."),
            ToolArgument("output", "-o", "path", description="Output file path."),
        ),
        "inputs": {
            "accepts": ("url", "host", "domain"),
            "required": ("mode", "wordlist"),
            "optional": ("url", "threads", "status_codes", "output"),
        },
        "outputs": {
            "formats": ("text",),
            "parser": "gobuster-text",
            "normalizer": "content-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="Brute-force directory/DNS/vhost discovery.", safe=False),),
        "safe_mode": "scan",
    },
    "dirsearch": {
        "cli_binary": "dirsearch",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("url", "-u", "string", required=True, description="Target URL."),
            ToolArgument("wordlist", "-w", "path", description="Wordlist data file path."),
            ToolArgument("extensions", "-e", "string", description="Comma-separated file extensions."),
            ToolArgument("threads", "-t", "int", description="Concurrent threads."),
            ToolArgument("format", "--format", "string", choices=("plain", "json", "xml", "csv", "yaml"), description="Output format."),
            ToolArgument("output", "-o", "path", description="Output file path."),
        ),
        "inputs": {
            "accepts": ("url",),
            "required": ("url",),
            "optional": ("wordlist", "extensions", "threads", "format", "output"),
        },
        "outputs": {
            "formats": ("json", "text"),
            "parser": "dirsearch-json",
            "normalizer": "content-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="Dictionary-based content discovery.", safe=False),),
        "safe_mode": "scan",
    },
    # -- injection / vulnerability -------------------------------------------
    "dalfox": {
        "cli_binary": "dalfox",
        "cli_structure": "subcommand",
        "arguments": (
            ToolArgument("target", "", "string", required=True, description="Target URL to scan for XSS."),
            ToolArgument("format", "--format", "string", choices=("plain", "json", "xml"), description="Output format."),
            ToolArgument("silent", "--silent", "bool", description="Suppress banner and non-result output."),
            ToolArgument("output", "-o", "path", description="Output file path."),
            ToolArgument("worker", "-w", "int", description="Concurrency level."),
        ),
        "inputs": {
            "accepts": ("url",),
            "required": ("target",),
            "optional": ("format", "silent", "output", "worker"),
        },
        "outputs": {
            "formats": ("json",),
            "parser": "dalfox-json",
            "normalizer": "vulnerability-candidate-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="XSS detection and validation.", safe=False),),
        "safe_mode": "scan",
    },
    "xssstrike": {
        "cli_binary": "xssstrike",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("url", "-u", "string", required=True, description="Target URL."),
            ToolArgument("crawl", "-c", "bool", description="Crawl the target before testing."),
            ToolArgument("level", "--level", "int", description="Crawl depth level."),
        ),
        "inputs": {
            "accepts": ("url",),
            "required": ("url",),
            "optional": ("crawl", "level"),
        },
        "outputs": {
            "formats": ("text",),
            "parser": "xssstrike-text",
            "normalizer": "vulnerability-candidate-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="XSS detection with a browser-based engine.", safe=False),),
        "safe_mode": "scan",
    },
    "sqlmap": {
        "cli_binary": "sqlmap",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("url", "-u", "string", required=True, description="Target URL with injectable parameters."),
            ToolArgument("data", "-d", "string", description="POST/body data string."),
            ToolArgument("level", "--level", "int", description="Level of tests to perform (1-5)."),
            ToolArgument("risk", "--risk", "int", description="Risk of tests to perform (1-3)."),
            ToolArgument("batch", "--batch", "bool", description="Never ask for user input; use defaults."),
            ToolArgument("threads", "--threads", "int", description="Concurrent HTTP requests."),
            ToolArgument("forms", "--forms", "bool", description="Parse and test forms on the target."),
            ToolArgument("tamper", "--tamper", "string", description="Tamper script(s) to apply."),
            ToolArgument("output_dir", "--output-dir", "path", description="Output directory for results."),
        ),
        "inputs": {
            "accepts": ("url", "host"),
            "required": ("url",),
            "optional": ("data", "level", "risk", "batch", "threads", "forms", "tamper", "output_dir"),
        },
        "outputs": {
            "formats": ("text", "json"),
            "parser": "sqlmap-text",
            "normalizer": "vulnerability-candidate-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="SQL injection detection and exploitation.", safe=False),),
        "safe_mode": "scan",
    },
    "ghauri": {
        "cli_binary": "ghauri",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("url", "-u", "string", required=True, description="Target URL with injectable parameters."),
            ToolArgument("data", "-d", "string", description="POST/body data string."),
            ToolArgument("level", "--level", "int", description="Level of tests to perform."),
            ToolArgument("risk", "--risk", "int", description="Risk of tests to perform."),
            ToolArgument("batch", "--batch", "bool", description="Never ask for user input."),
            ToolArgument("threads", "--threads", "int", description="Concurrent HTTP requests."),
        ),
        "inputs": {
            "accepts": ("url", "host"),
            "required": ("url",),
            "optional": ("data", "level", "risk", "batch", "threads"),
        },
        "outputs": {
            "formats": ("text",),
            "parser": "ghauri-text",
            "normalizer": "vulnerability-candidate-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="Advanced SQL injection detection.", safe=False),),
        "safe_mode": "scan",
    },
    "commix": {
        "cli_binary": "commix",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("url", "-u", "string", required=True, description="Target URL."),
            ToolArgument("data", "-d", "string", description="POST/body data string."),
            ToolArgument("level", "--level", "int", description="Level of tests to perform."),
            ToolArgument("batch", "--batch", "bool", description="Never ask for user input."),
            ToolArgument("output_dir", "--output-dir", "path", description="Output directory for results."),
        ),
        "inputs": {
            "accepts": ("url", "host"),
            "required": ("url",),
            "optional": ("data", "level", "batch", "output_dir"),
        },
        "outputs": {
            "formats": ("text",),
            "parser": "commix-text",
            "normalizer": "vulnerability-candidate-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="Command injection detection and exploitation.", safe=False),),
        "safe_mode": "scan",
    },
    "interactsh": {
        "cli_binary": "interactsh-client",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("server", "-server", "string", description="Interactsh server to connect to."),
            ToolArgument("token", "-token", "string", description="Authentication token for the server."),
            ToolArgument("output", "-o", "path", description="Output file path for interactions."),
            ToolArgument("nocolor", "-nocolor", "bool", description="Disable colored output."),
            ToolArgument("json", "-json", "bool", description="Emit interactions as JSON."),
        ),
        "inputs": {
            "accepts": ("url", "host"),
            "required": (),
            "optional": ("server", "token", "output", "nocolor", "json"),
        },
        "outputs": {
            "formats": ("json", "text"),
            "parser": "interactsh-json",
            "normalizer": "observation-normalizer",
        },
        "modes": (ToolExecutionMode("listen", description="OOB/out-of-band interaction collection.", safe=True),),
        "safe_mode": "listen",
    },
    "tplmap": {
        "cli_binary": "tplmap",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("url", "-u", "string", required=True, description="Target URL."),
            ToolArgument("data", "-d", "string", description="POST/body data string."),
            ToolArgument("level", "--level", "int", description="Level of tests to perform."),
            ToolArgument("engine", "--engine", "string", description="Force a specific template engine."),
        ),
        "inputs": {
            "accepts": ("url", "host"),
            "required": ("url",),
            "optional": ("data", "level", "engine"),
        },
        "outputs": {
            "formats": ("text",),
            "parser": "tplmap-text",
            "normalizer": "vulnerability-candidate-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="Server-side template injection detection.", safe=False),),
        "safe_mode": "scan",
    },
    "sstimap": {
        "cli_binary": "sstimap",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("url", "-u", "string", required=True, description="Target URL."),
            ToolArgument("data", "-d", "string", description="POST/body data string."),
            ToolArgument("level", "--level", "int", description="Level of tests to perform."),
            ToolArgument("engine", "--engine", "string", description="Force a specific template engine."),
        ),
        "inputs": {
            "accepts": ("url", "host"),
            "required": ("url",),
            "optional": ("data", "level", "engine"),
        },
        "outputs": {
            "formats": ("text",),
            "parser": "sstimap-text",
            "normalizer": "vulnerability-candidate-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="Server-side template injection detection.", safe=False),),
        "safe_mode": "scan",
    },
    "graphqlmap": {
        "cli_binary": "graphqlmap",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("url", "-u", "string", required=True, description="GraphQL endpoint URL."),
            ToolArgument("method", "-m", "string", choices=("GET", "POST"), description="HTTP method."),
            ToolArgument("headers", "-H", "list", description="Extra HTTP headers."),
            ToolArgument("output", "-o", "path", description="Output file path."),
        ),
        "inputs": {
            "accepts": ("url",),
            "required": ("url",),
            "optional": ("method", "headers", "output"),
        },
        "outputs": {
            "formats": ("json",),
            "parser": "graphqlmap-json",
            "normalizer": "api-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="GraphQL endpoint probing and exploitation.", safe=False),),
        "safe_mode": "scan",
    },
    "inql": {
        "cli_binary": "inql",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("target", "-t", "string", description="Target GraphQL URL."),
            ToolArgument("input", "-i", "path", description="Input file (query/file pair)."),
            ToolArgument("output", "-o", "path", description="Output file path."),
        ),
        "inputs": {
            "accepts": ("url", "file"),
            "required": (),
            "optional": ("target", "input", "output"),
        },
        "outputs": {
            "formats": ("text",),
            "parser": "inql-text",
            "normalizer": "api-normalizer",
        },
        "modes": (ToolExecutionMode("introspect", description="GraphQL introspection and query generation.", safe=True),),
        "safe_mode": "introspect",
    },
    # -- secrets / analysis ----------------------------------------------------
    "trufflehog": {
        "cli_binary": "trufflehog",
        "cli_structure": "subcommand",
        "arguments": (
            ToolArgument("source", "", "string", required=True, description="Source to scan (git/filesystem/s3/...)."),
            ToolArgument("only_verified", "--only-verified", "bool", description="Only report verified secrets."),
            ToolArgument("json", "--json", "bool", description="Emit results as JSON."),
            ToolArgument("concurrency", "--concurrency", "int", description="Concurrent workers."),
            ToolArgument("output", "-o", "path", description="Output file path."),
        ),
        "inputs": {
            "accepts": ("url", "path", "repo"),
            "required": ("source",),
            "optional": ("only_verified", "json", "concurrency", "output"),
        },
        "outputs": {
            "formats": ("json",),
            "parser": "trufflehog-json",
            "normalizer": "secret-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="Secrets detection across repositories and filesystems.", safe=True),),
        "safe_mode": "scan",
    },
    "semgrep": {
        "cli_binary": "semgrep",
        "cli_structure": "subcommand",
        "arguments": (
            ToolArgument("target", "", "string", required=True, description="Path, directory or URL to scan."),
            ToolArgument("config", "--config", "string", description="Ruleset (auto, p/..., or path)."),
            ToolArgument("json", "--json", "bool", description="Emit results as JSON."),
            ToolArgument("output", "-o", "path", description="Output file path."),
            ToolArgument("severity", "--severity", "list", description="Severity filter (INFO/WARNING/ERROR)."),
            ToolArgument("timeout", "--timeout", "int", description="Per-rule timeout in seconds."),
        ),
        "inputs": {
            "accepts": ("path", "url", "repo"),
            "required": ("target",),
            "optional": ("config", "json", "output", "severity", "timeout"),
        },
        "outputs": {
            "formats": ("json", "text"),
            "parser": "semgrep-json",
            "normalizer": "sast-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="Static analysis with a ruleset engine.", safe=True),),
        "safe_mode": "scan",
    },
    # -- proxy / exploitation ---------------------------------------------------
    "zap": {
        "cli_binary": "zap",
        "aliases": ("zap.sh", "zaproxy"),
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("cmd", "-cmd", "bool", required=True, description="Run ZAP in command-line mode."),
            ToolArgument("quickurl", "-quickurl", "string", description="URL to scan in quick mode."),
            ToolArgument("quickout", "-quickout", "path", description="Quick-scan output file."),
            ToolArgument("port", "-port", "int", description="Local proxy port."),
        ),
        "inputs": {
            "accepts": ("url",),
            "required": ("cmd",),
            "optional": ("quickurl", "quickout", "port"),
        },
        "outputs": {
            "formats": ("json", "html"),
            "parser": "zap-json",
            "normalizer": "vulnerability-candidate-normalizer",
        },
        "modes": (ToolExecutionMode("scan", description="Active/passive web application scanning.", safe=False),),
        "safe_mode": "scan",
    },
    "mitmproxy": {
        "cli_binary": "mitmproxy",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("port", "-p", "int", description="Listen port."),
            ToolArgument("listen_host", "--listen-host", "string", description="Listen host."),
            ToolArgument("mode", "--mode", "string", description="Proxy mode (regular/transparent/...)."),
            ToolArgument("save_stream_file", "-w", "path", description="Stream output file."),
        ),
        "inputs": {
            "accepts": ("url", "host", "port"),
            "required": (),
            "optional": ("port", "listen_host", "mode", "save_stream_file"),
        },
        "outputs": {
            "formats": ("text",),
            "parser": "mitmproxy-text",
            "normalizer": "proxy-normalizer",
        },
        "modes": (ToolExecutionMode("intercept", description="Interactive HTTP interception proxy.", safe=True),),
        "safe_mode": "intercept",
    },
    "metasploit": {
        "cli_binary": "msfconsole",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("quiet", "-q", "bool", description="Suppress banner."),
            ToolArgument("resource", "-r", "path", description="Run commands from a resource file."),
            ToolArgument("command", "-x", "string", description="Execute a single command and exit."),
        ),
        "inputs": {
            "accepts": ("host", "url"),
            "required": (),
            "optional": ("quiet", "resource", "command"),
        },
        "outputs": {
            "formats": ("text",),
            "parser": "metasploit-text",
            "normalizer": "vulnerability-candidate-normalizer",
        },
        "modes": (ToolExecutionMode("exploit", description="Exploitation framework console.", safe=False),),
        "safe_mode": "exploit",
    },
    "searchsploit": {
        "cli_binary": "searchsploit",
        "cli_structure": "flags",
        "arguments": (
            ToolArgument("term", "", "string", required=True, description="Search term(s)."),
            ToolArgument("json", "--json", "bool", description="Emit results as JSON."),
            ToolArgument("verbose", "-v", "bool", description="Verbose output with paths."),
            ToolArgument("exclude", "-e", "string", description="Terms to exclude."),
        ),
        "inputs": {
            "accepts": ("query",),
            "required": ("term",),
            "optional": ("json", "verbose", "exclude"),
        },
        "outputs": {
            "formats": ("json", "text"),
            "parser": "searchsploit-json",
            "normalizer": "exploit-normalizer",
        },
        "modes": (ToolExecutionMode("search", description="Exploit-DB search.", safe=True),),
        "safe_mode": "search",
    },
}

#: Safety class per tool when the platform knowledge leaves it unset.
_SAFETY_CLASS: dict[str, str] = {
    "feroxbuster": "active",
    "gobuster": "active",
    "dirsearch": "active",
    "dalfox": "active",
    "xssstrike": "active",
    "sqlmap": "active",
    "ghauri": "active",
    "commix": "active",
    "interactsh": "passive",
    "tplmap": "active",
    "sstimap": "active",
    "graphqlmap": "active",
    "inql": "passive",
    "trufflehog": "passive",
    "semgrep": "passive",
    "zap": "active",
    "mitmproxy": "passive",
    "metasploit": "active",
    "searchsploit": "passive",
    "arjun": "active",
    "paramspider": "passive",
    "kiterunner": "active",
}


def register_command_knowledge(tip: ToolIntelligenceAPI) -> int:
    """Enrich TIP knowledge with executable command data for gap tools.

    Only fields that are empty (or missing) are filled; populated knowledge is
    never overwritten. Returns the number of tools enriched.
    """
    enriched = 0
    safety_targets = set(COMMAND_KNOWLEDGE) | set(_SAFETY_CLASS)
    for tool_id in sorted(safety_targets):
        knowledge = tip.get_knowledge(tool_id)
        if knowledge is None:
            continue
        spec = COMMAND_KNOWLEDGE.get(tool_id, {})
        updates: dict[str, Any] = {}
        if not knowledge.cli_binary and spec.get("cli_binary"):
            updates["cli_binary"] = spec["cli_binary"]
        if not knowledge.cli_structure and spec.get("cli_structure"):
            updates["cli_structure"] = spec["cli_structure"]
        if not knowledge.arguments and spec.get("arguments"):
            updates["arguments"] = tuple(spec["arguments"])
        if not knowledge.safe_mode and spec.get("safe_mode"):
            updates["safe_mode"] = spec["safe_mode"]
        if not knowledge.outputs.formats and spec.get("outputs"):
            updates["outputs"] = replace(
                knowledge.outputs,
                formats=tuple(spec["outputs"].get("formats", ())),
                parser=spec["outputs"].get("parser", ""),
                normalizer=spec["outputs"].get("normalizer", ""),
            )
        inputs_spec = spec.get("inputs")
        if inputs_spec and not knowledge.inputs.accepts:
            updates["inputs"] = ToolInputContract(
                accepts=tuple(inputs_spec.get("accepts", ())),
                required=tuple(inputs_spec.get("required", ())),
                optional=tuple(inputs_spec.get("optional", ())),
            )
        if not knowledge.modes and spec.get("modes"):
            updates["modes"] = tuple(spec["modes"])
        safety_class = _SAFETY_CLASS.get(tool_id)
        if safety_class and knowledge.safety_profile is None:
            updates["safety_profile"] = ToolSafetyProfile(
                safety_class=_safety_class_enum(safety_class),
                destructive=_is_active(safety_class),
                requires_authorization=_is_active(safety_class),
            )
        if not updates:
            continue
        tip.register_knowledge(replace(knowledge, **updates))
        enriched += 1
    return enriched


def _is_active(safety_class: str) -> bool:
    """Return ``True`` for safety classes that actively interact with the target."""
    return safety_class in ("active", "exploit")


def _safety_class_enum(value: str) -> ToolSafetyClass:
    """Coerce a safety-class name into the canonical :class:`ToolSafetyClass`."""
    mapping = {
        "passive": ToolSafetyClass.PASSIVE,
        "active": ToolSafetyClass.ACTIVE,
        "low-impact-active": ToolSafetyClass.LOW_IMPACT_ACTIVE,
        "exploit": ToolSafetyClass.HIGH_IMPACT,
        "high-impact": ToolSafetyClass.HIGH_IMPACT,
    }
    return mapping.get(value, ToolSafetyClass.LOW_IMPACT_ACTIVE)


__all__ = ["COMMAND_KNOWLEDGE", "register_command_knowledge"]
