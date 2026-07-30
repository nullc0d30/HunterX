# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — Backward-compatibility shim for plugins package

import importlib
import pkgutil
import sys
_plugins = importlib.import_module('hunterx.plugins')
sys.modules['plugins'] = _plugins

for importer, name, ispkg in pkgutil.walk_packages(_plugins.__path__, 'hunterx.plugins.'):
    short_name = 'plugins.' + name[len('hunterx.plugins.'):]
    try:
        mod = importlib.import_module(name)
        sys.modules[short_name] = mod
    except ImportError:
        pass
