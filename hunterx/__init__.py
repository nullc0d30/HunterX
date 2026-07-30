# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter

__version__ = "6.0.0"
__author__ = "Ahmed Awad (NullC0d3)"
__license__ = "Apache-2.0"

__all__ = [
    "main", "load_payloads", "classify_payload_files",
    "Engine", "get_copyright_text", "get_json_metadata",
    "logger", "console",
]

from .cli import main as main
from .cli import load_payloads as load_payloads
from .cli import classify_payload_files as classify_payload_files
from .engines.engine import Engine as Engine
from .core.legal import get_copyright_text as get_copyright_text
from .core.legal import get_json_metadata as get_json_metadata
from .utils.utils import logger as logger
from .utils.utils import console as console
