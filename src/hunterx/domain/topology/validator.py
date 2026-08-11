# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology relationship validator.

Structural and semantic checks applied to every raw observation before it
enters correlation. The validator is deterministic and returns a list of
human-readable errors; an observation with any error is dropped by the
pipeline.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from hunterx.domain.topology.enums import EntityKind, RelationshipType
from hunterx.domain.topology.keys import is_ip


class TopologyValidator:
    """Validate raw relationship observations."""

    def validate(self, observation: Any) -> list[str]:
        """Return a list of validation errors for ``observation``."""
        errors: list[str] = []

        if observation.source is None or observation.target is None:
            errors.append("missing source or target")
            return errors

        if observation.source.key == observation.target.key:
            errors.append(f"self-loop detected: {observation.source.key}")

        rel_type = observation.rel_type
        if not isinstance(rel_type, RelationshipType):
            try:
                RelationshipType(str(rel_type))
            except ValueError:
                errors.append(f"unknown relationship type '{rel_type}'")

        try:
            EntityKind(observation.source.kind.value)
            EntityKind(observation.target.kind.value)
        except ValueError:
            errors.append("unknown entity kind")

        if not observation.source.name or not observation.target.name:
            errors.append("empty entity name")

        if not (0.0 <= float(observation.confidence) <= 1.0):
            errors.append("confidence out of [0, 1]")

        if str(observation.rel_type) in (RelationshipType.PART_OF.value,):
            errors.extend(self._part_of_checks(observation))

        if str(observation.rel_type) in (RelationshipType.ROUTES_TO.value,) and not is_ip(observation.target.name):
            errors.append("routes_to target must be an IP address")

        return errors

    @staticmethod
    def _part_of_checks(observation: Any) -> list[str]:
        errors: list[str] = []
        if observation.source.kind == EntityKind.IP and observation.target.kind == EntityKind.CIDR:
            try:
                if ipaddress.ip_address(observation.source.name) not in ipaddress.ip_network(
                    observation.target.name, strict=False
                ):
                    errors.append(f"{observation.source.name} is not inside {observation.target.name}")
            except ValueError:
                errors.append("invalid ip/cidr pair")
        return errors

    def validate_all(self, observations: list[Any]) -> tuple[list[Any], list[tuple[Any, list[str]]]]:
        """Partition observations into valid ones and ``(observation, errors)``."""
        valid: list[Any] = []
        invalid: list[tuple[Any, list[str]]] = []
        for observation in observations:
            errors = self.validate(observation)
            if errors:
                invalid.append((observation, errors))
            else:
                valid.append(observation)
        return valid, invalid
