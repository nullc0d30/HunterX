# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
import importlib
import inspect
import os
import sys
from typing import Dict, List, Any


class PluginLoader:
    """Discovers and loads plugins from designated directories."""

    def __init__(self, plugin_dirs: List[str] = None):
        self.plugin_dirs = plugin_dirs or []
        self._detectors: Dict[str, Any] = {}
        self._reporters: Dict[str, Any] = {}
        self._hooks: Dict[str, List[Any]] = {}

    def discover(self):
        for directory in self.plugin_dirs:
            if not os.path.isdir(directory):
                continue
            if directory not in sys.path:
                sys.path.insert(0, os.path.dirname(directory))

            for filename in os.listdir(directory):
                if filename.startswith("_") or not filename.endswith(".py"):
                    continue
                module_name = filename[:-3]
                module_path = os.path.join(directory, filename)

                try:
                    spec = importlib.util.spec_from_file_location(module_name, module_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)

                        for name, obj in inspect.getmembers(module, inspect.isclass):
                            if hasattr(obj, "_plugin_type"):
                                plugin_type = obj._plugin_type
                                if plugin_type == "detector":
                                    self._detectors[name] = obj()
                                elif plugin_type == "reporter":
                                    self._reporters[name] = obj()
                                elif plugin_type == "hook":
                                    hook_type = getattr(obj, "_hook_type", "*")
                                    self._hooks.setdefault(hook_type, []).append(obj())
                except Exception as e:
                    print(f"Failed to load plugin {module_name}: {e}")

        return self

    def get_detectors(self) -> Dict[str, Any]:
        return self._detectors

    def get_reporters(self) -> Dict[str, Any]:
        return self._reporters

    def get_hooks(self, event: str = None) -> List[Any]:
        if event is None:
            hooks = []
            for hlist in self._hooks.values():
                hooks.extend(hlist)
            return hooks
        return self._hooks.get(event, [])

    def run_hooks(self, event: str, **kwargs):
        for hook in self.get_hooks(event):
            try:
                hook.run(**kwargs)
            except Exception as e:
                print(f"Hook {hook.__class__.__name__} failed: {e}")


def plugin(plugin_type: str, **kwargs):
    """Decorator to mark a class as a plugin."""

    def decorator(cls):
        cls._plugin_type = plugin_type
        for k, v in kwargs.items():
            setattr(cls, f"_{k}", v)
        return cls

    return decorator
