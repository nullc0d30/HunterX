# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""I/O generators: schemas, parser, normalizer and mappings.

Emits the input/output JSON Schemas, the parser and normalizer skeletons, and
the database / evidence / risk mappings of a Tool Integration Pack.
"""

from __future__ import annotations

import json

from hunterx.domain.tool_factory import PackArtifactKind
from hunterx.tools.factory.generators.base import PackContext, PackGenerator
from hunterx.tools.factory.templates import BUILTIN_FILES


class SchemaGenerator(PackGenerator):
    """Generates the input and output JSON Schemas."""

    name = "schemas"
    description = "Generates the input and output JSON Schemas."

    def generate(self, ctx: PackContext):
        """Emit the input and output JSON Schemas."""
        spec = ctx.spec
        display_name = ctx.context["display_name"]
        input_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": f"{display_name} input",
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "The scan target."},
                "parameters": {
                    "type": "object",
                    "description": "Tool parameters.",
                    "properties": {key: {"type": "string"} for key in spec.parameters},
                },
            },
        }
        output_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": f"{display_name} output",
            "type": "object",
            "required": ["findings"],
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["title", "severity", "target"],
                        "properties": {
                            "title": {"type": "string"},
                            "severity": {"type": "string"},
                            "target": {"type": "string"},
                            "description": {"type": "string"},
                            "risk_score": {"type": ["number", "null"]},
                            "metadata": {"type": "object"},
                        },
                    },
                }
            },
        }
        return [
            self.file(
                "schemas/input.json",
                json.dumps(input_schema, indent=2, sort_keys=True) + "\n",
                PackArtifactKind.INPUT_SCHEMA,
            ),
            self.file(
                "schemas/output.json",
                json.dumps(output_schema, indent=2, sort_keys=True) + "\n",
                PackArtifactKind.OUTPUT_SCHEMA,
            ),
        ]


class ParserGenerator(PackGenerator):
    """Generates the parser skeleton (``parsing/parser.py``)."""

    name = "parser"
    description = "Generates the output parser skeleton."

    def generate(self, ctx: PackContext):
        """Emit the parser skeleton."""
        content = self.render(ctx, "parsing/parser.py", BUILTIN_FILES["parsing/parser.py"])
        return [self.file("parsing/parser.py", content, PackArtifactKind.PARSER)]


class NormalizerGenerator(PackGenerator):
    """Generates the normalizer skeleton (``parsing/normalizer.py``)."""

    name = "normalizer"
    description = "Generates the result normalizer skeleton."

    def generate(self, ctx: PackContext):
        """Emit the normalizer skeleton."""
        content = self.render(ctx, "parsing/normalizer.py", BUILTIN_FILES["parsing/normalizer.py"])
        return [self.file("parsing/normalizer.py", content, PackArtifactKind.NORMALIZER)]


class DatabaseMappingGenerator(PackGenerator):
    """Generates the database, evidence and risk mappings."""

    name = "database-mapping"
    description = "Generates the database, evidence and risk mappings."

    def generate(self, ctx: PackContext):
        """Emit the database, evidence and risk mappings."""
        spec = ctx.spec
        database_data = {
            "tool_id": spec.pack_id,
            "findings": {
                "table": "findings",
                "columns": {
                    "title": "finding.title",
                    "severity": "finding.severity",
                    "target": "finding.target",
                    "description": "finding.description",
                    "risk_score": "finding.risk_score",
                    "metadata": "finding.metadata",
                },
                "dedup_key": ["target", "title"],
            },
        }
        evidence_data = {
            "tool_id": spec.pack_id,
            "evidence_capture": ["file", "screenshot", "pcap"],
            "outputs": [spec.output_format],
        }
        risk_data = {
            "tool_id": spec.pack_id,
            "risk_formula": "cvss-v3-base-v2",
            "mappings": {
                "critical": [9.0, 10.0],
                "high": [7.0, 8.9],
                "medium": [4.0, 6.9],
                "low": [0.1, 3.9],
                "info": [0.0, 0.0],
            },
        }
        return [
            self.file(
                "mapping/database.yaml",
                _yaml(database_data),
                PackArtifactKind.DATABASE_MAPPING,
            ),
            self.file(
                "mapping/evidence.yaml",
                _yaml(evidence_data),
                PackArtifactKind.EVIDENCE_MAPPING,
            ),
            self.file(
                "mapping/risk.yaml",
                _yaml(risk_data),
                PackArtifactKind.RISK_MAPPING,
            ),
        ]


def _yaml(data: dict[str, object]) -> str:
    from hunterx.domain.tool_factory import render_yaml

    return render_yaml(data) + "\n"
