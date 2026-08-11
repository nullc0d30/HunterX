# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Parameter discovery tool adapters."""

from hunterx.tools.parameter.adapters import ArjunAdapter, KiterunnerAdapter, ParamspiderAdapter
from hunterx.tools.parameter.base import ParameterToolAdapter
from hunterx.tools.parameter.registry import (
    PARAMETER_TOOL_IDS,
    ParameterAdapterFactory,
    parameter_adapters,
    register_parameter_adapters,
)
from hunterx.tools.parameter.tip import register_parameter_tools

__all__ = [
    "ArjunAdapter",
    "KiterunnerAdapter",
    "PARAMETER_TOOL_IDS",
    "ParamspiderAdapter",
    "ParameterAdapterFactory",
    "ParameterToolAdapter",
    "parameter_adapters",
    "register_parameter_adapters",
    "register_parameter_tools",
]
