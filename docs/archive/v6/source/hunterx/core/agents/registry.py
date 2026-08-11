from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
import threading
from typing import Any, Dict, List, Optional, Type

from .base import SecurityAgent
from .capabilities import AgentCapability, CapabilityRegistry
from ...utils.utils import logger


class AgentRegistry:
    _instance: Optional[AgentRegistry] = None
    _lock: threading.RLock = threading.RLock()

    def __new__(cls) -> AgentRegistry:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._agents: Dict[str, SecurityAgent] = {}
                    cls._instance._agent_classes: Dict[str, Type[SecurityAgent]] = {}
        return cls._instance

    def register(self, agent: SecurityAgent) -> None:
        self._agents[agent.agent_id] = agent
        CapabilityRegistry.register(agent.agent_id, agent.capabilities)
        logger.info(f"AgentRegistry: registered {agent.name} ({agent.agent_id[:8]})")

    def register_class(self, name: str, agent_class: Type[SecurityAgent]) -> None:
        self._agent_classes[name] = agent_class

    def unregister(self, agent_id: str) -> None:
        self._agents.pop(agent_id, None)
        CapabilityRegistry.unregister(agent_id)

    def get(self, agent_id: str) -> Optional[SecurityAgent]:
        return self._agents.get(agent_id)

    def get_by_name(self, name: str) -> Optional[SecurityAgent]:
        for agent in self._agents.values():
            if agent.name == name:
                return agent
        return None

    def list_agents(self) -> List[Dict[str, Any]]:
        return [a.to_dict() for a in self._agents.values()]

    def list_healthy(self) -> List[Dict[str, Any]]:
        return [a.to_dict() for a in self._agents.values() if a.state.value in ("idle", "busy")]

    def find_by_capability(self, capability: AgentCapability) -> List[SecurityAgent]:
        agent_ids = CapabilityRegistry.find_agents_by_capability(capability)
        return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def find_by_capabilities(self, capabilities: List[AgentCapability]) -> List[SecurityAgent]:
        agent_ids = CapabilityRegistry.find_agents_by_capabilities(capabilities)
        return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def count(self) -> int:
        return len(self._agents)

    def shutdown_all(self) -> None:
        for agent in self._agents.values():
            try:
                agent.shutdown()
            except Exception as e:
                logger.error(f"Error shutting down agent {agent.name}: {e}")

    def discover_plugins(self, plugin_dirs: Optional[List[str]] = None) -> int:
        discovered = 0
        if plugin_dirs is None:
            plugin_dirs = [
                os.path.join(os.path.dirname(__file__), "plugins"),
            ]

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
                            if issubclass(obj, SecurityAgent) and obj is not SecurityAgent:
                                self.register_class(name, obj)
                                discovered += 1
                                logger.info(f"AgentRegistry: discovered agent class {name} from {modname}")
                    except Exception as e:
                        logger.debug(f"AgentRegistry: failed to load {modname}: {e}")
            finally:
                __import__("sys").path = sys_path_backup
        return discovered
