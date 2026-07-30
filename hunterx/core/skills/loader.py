from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
import threading
from typing import List, Optional

from ...utils.utils import logger
from .base import SecuritySkill
from .registry import SkillRegistry


class SkillLoader:
    def __init__(self, registry: Optional[SkillRegistry] = None):
        self._registry = registry or SkillRegistry()
        self._lock = threading.RLock()

    def discover_builtin(self) -> int:
        from . import plugins as plugins_module
        count = 0
        plugin_dir = os.path.dirname(plugins_module.__file__)
        sys_path_backup = list(__import__("sys").path)
        try:
            __import__("sys").path.insert(0, os.path.dirname(plugin_dir))
            for importer, modname, ispkg in pkgutil.iter_modules([plugin_dir]):
                if ispkg:
                    continue
                try:
                    module = importlib.import_module(f"core.skills.plugins.{modname}")
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, SecuritySkill) and obj is not SecuritySkill and not inspect.isabstract(obj):
                            try:
                                skill = obj()
                                self._registry.register(skill)
                                count += 1
                                logger.info(f"SkillLoader: discovered {skill.metadata.name} ({skill.metadata.skill_id})")
                            except Exception as e:
                                logger.debug(f"SkillLoader: failed to instantiate {name}: {e}")
                except Exception as e:
                    logger.debug(f"SkillLoader: failed to load {modname}: {e}")
        finally:
            __import__("sys").path = sys_path_backup
        return count

    def discover_plugins(self, plugin_dirs: List[str]) -> int:
        count = 0
        for plugin_dir in plugin_dirs:
            if not os.path.isdir(plugin_dir):
                continue
            sys_path_backup = list(__import__("sys").path)
            try:
                __import__("sys").path.insert(0, os.path.dirname(plugin_dir))
                for importer, modname, ispkg in pkgutil.iter_modules([plugin_dir]):
                    try:
                        module = importlib.import_module(modname)
                        for name, obj in inspect.getmembers(module, inspect.isclass):
                            if issubclass(obj, SecuritySkill) and obj is not SecuritySkill and not inspect.isabstract(obj):
                                try:
                                    skill = obj()
                                    self._registry.register(skill)
                                    count += 1
                                except Exception as e:
                                    logger.debug(f"SkillLoader: failed to instantiate {name} from {modname}: {e}")
                    except Exception as e:
                        logger.debug(f"SkillLoader: failed to load {modname}: {e}")
            finally:
                __import__("sys").path = sys_path_backup
        return count

    def load_from_path(self, file_path: str) -> Optional[SecuritySkill]:
        if not os.path.exists(file_path):
            logger.error(f"Skill file not found: {file_path}")
            return None
        try:
            module_name = os.path.splitext(os.path.basename(file_path))[0]
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if not spec or not spec.loader:
                return None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, SecuritySkill) and obj is not SecuritySkill and not inspect.isabstract(obj):
                    return obj()
        except Exception as e:
            logger.error(f"Failed to load skill from {file_path}: {e}")
        return None
