# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — Backward-compatibility shim for api package

import importlib
import sys
from hunterx.api import app as app, start_api as start_api

_MOVED = {
    'server': 'hunterx.api.server',
    'models': 'hunterx.api.models',
    'job_queue': 'hunterx.api.job_queue',
}

for name, target in _MOVED.items():
    try:
        mod = importlib.import_module(target)
        sys.modules[f'api.{name}'] = mod
    except ImportError:
        pass
