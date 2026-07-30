import importlib
import sys

import hunterx as hunterx

_MODULE_MAP = {
    'core.engine': 'hunterx.engines.engine',
    'core.config': 'hunterx.config',
    'core.utils': 'hunterx.utils.utils',
    'core.plugin_loader': 'hunterx.utils.plugin_loader',
    'core.report': 'hunterx.reporting.report',
    'core.sarif_reporter': 'hunterx.reporting.sarif_reporter',
    'core.visual_graph': 'hunterx.reporting.visual_graph',
    'core.visualizer': 'hunterx.reporting.visualizer',
    'core.adaptive_memory': 'hunterx.modules.intelligence.adaptive_memory',
    'core.attack_chain': 'hunterx.modules.intelligence.attack_chain',
    'core.browser_intelligence': 'hunterx.modules.intelligence.browser_intelligence',
    'core.evolution': 'hunterx.modules.intelligence.evolution',
    'core.explainability': 'hunterx.modules.intelligence.explainability',
    'core.knowledge_graph': 'hunterx.modules.intelligence.knowledge_graph',
    'core.relationship': 'hunterx.modules.intelligence.relationship',
    'core.threat_model': 'hunterx.modules.intelligence.threat_model',
    'core.payload_context': 'hunterx.modules.payloads.payload_context',
    'core.payload_feedback': 'hunterx.modules.payloads.payload_feedback',
    'core.payload_graph': 'hunterx.modules.payloads.payload_graph',
    'core.payload_index': 'hunterx.modules.payloads.payload_index',
    'core.payload_manager': 'hunterx.modules.payloads.payload_manager',
    'core.payload_metadata': 'hunterx.modules.payloads.payload_metadata',
    'core.payload_policy': 'hunterx.modules.payloads.payload_policy',
    'core.payload_provenance': 'hunterx.modules.payloads.payload_provenance',
    'core.payload_ranking': 'hunterx.modules.payloads.payload_ranking',
    'core.payload_reasoning': 'hunterx.modules.payloads.payload_reasoning',
    'core.payload_repo': 'hunterx.modules.payloads.payload_repo',
    'core.payload_search': 'hunterx.modules.payloads.payload_search',
    'core.payload_sync': 'hunterx.modules.payloads.payload_sync',
}

for _sp in ('agents', 'protocols', 'reasoning', 'skills'):
    importlib.import_module(f'hunterx.core.{_sp}')

for _mod_name in list(sys.modules):
    if _mod_name.startswith('hunterx.core.'):
        _shim_name = _mod_name[len('hunterx.'):]
        if _shim_name not in sys.modules:
            sys.modules[_shim_name] = sys.modules[_mod_name]

for _shim_name, _real_name in _MODULE_MAP.items():
    if _shim_name in sys.modules:
        continue
    if _real_name in sys.modules:
        sys.modules[_shim_name] = sys.modules[_real_name]
        continue
    try:
        _mod = importlib.import_module(_real_name)
        sys.modules[_shim_name] = _mod
    except ImportError:
        pass

del _sp, _mod_name, _shim_name, _real_name, _mod

_EXPORT_NAMES = {
    'Engine': 'hunterx.engines.engine',
    'Reporter': 'hunterx.reporting.report',
    'Detector': 'hunterx.core.detector',
    'PayloadClassifier': 'hunterx.core.classifier',
    'StealthSession': 'hunterx.core.session',
    'Planner': 'hunterx.core.planner',
    'PayloadIndexer': 'hunterx.modules.payloads.payload_index',
    'KnowledgeGraph': 'hunterx.modules.intelligence.knowledge_graph',
    'AdaptiveMemory': 'hunterx.modules.intelligence.adaptive_memory',
    'AIManager': 'hunterx.core.ai.manager',
    'AgentRegistry': 'hunterx.core.agents.registry',
    'SkillRegistry': 'hunterx.core.skills.registry',
    'ReasoningOrchestrator': 'hunterx.core.reasoning.engine',
    'GraphQLTester': 'hunterx.core.protocols.graphql',
}

def __getattr__(name):
    if name in _EXPORT_NAMES:
        mod = importlib.import_module(_EXPORT_NAMES[name])
        attr = getattr(mod, name)
        globals()[name] = attr
        return attr
    full = f'core.{name}'
    if full in sys.modules:
        return sys.modules[full]
    if name in ('ai', 'agents', 'auth', 'protocols', 'reasoning', 'skills'):
        mod = importlib.import_module(f'hunterx.core.{name}')
        sys.modules[full] = mod
        return mod
    if full in _MODULE_MAP:
        mod = importlib.import_module(_MODULE_MAP[full])
        sys.modules[full] = mod
        return mod
    real_name = f'hunterx.core.{name}'
    try:
        mod = importlib.import_module(real_name)
        sys.modules[full] = mod
        return mod
    except ImportError:
        raise AttributeError(f'module core has no attribute {name}')
