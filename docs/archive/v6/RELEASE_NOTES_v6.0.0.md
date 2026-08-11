# Release Notes — HunterX v6.0.0

## Highlights

HunterX v6.0.0 is a complete rewrite of the architecture. The project has evolved from a 4-stage vulnerability scanner into a full security intelligence platform with autonomous multi-agent coordination, a reasoning engine, and a plugin-based security skills framework. This release represents over 6 months of development and adds 4 major subsystems.

## Breaking Changes

- Complete architecture overhaul. The CLI has been restructured: subcommands for agents, workflow, reasoning, skills, AI, and payload replace the old monolithic flags.
- API server endpoints have been reorganized with new namespaced routes.
- The configuration system now uses hierarchical YAML with env var overrides.
- Minimum Python version is now 3.11.

## Migration Notes

- Update scripts from `--ai` flag to `hunterx ai test` subcommand pattern.
- API users should update endpoint paths to the new namespace hierarchy.
- The old `core/reasoning.py` is preserved as `core/reasoning_engine_old.py` for backward compatibility.

## Major Improvements

- New: Autonomous Multi-Agent Platform with 10 default agents
- New: Reasoning Engine with 18 goal types, 5 safety levels, consensus
- New: Security Skills Framework with 41 built-in skills
- New: Payload Intelligence Platform with SQLite index, search, graph, provenance
- New: AI Provider Abstraction Layer (OpenAI + Ollama)
- New: Knowledge Graph, Threat Model, MITRE Mapping, Risk Engine
- New: Explainable AI for all findings
- New: Purple Team detection rule generation
- New: Visual Attack Graph (HTML/Graphviz)
- New: SARIF 2.1 reporting
- New: 40+ REST API endpoints

## Performance

- Thread-safe async architecture throughout
- AI response caching with TTL
- Skill execution caching with LRU eviction
- Concurrent agent execution with dependency resolution
- SQLite-backed payload index with FTS5 full-text search
- LRU eviction in adaptive memory

## Testing

- 623 pytest tests (was 76 in v4.0.1)
- Ruff: 0 errors across entire codebase
- 95%+ type hint coverage
- All tests pass (4 pre-existing infrastructure failures unrelated to v6.0 features)

## Known Limitations

- AI providers require external servers (OpenAI API key or local Ollama)
- In-memory job queue (not persistent across restarts)
- No native gRPC support (via skills/plugins)
- OAuth2 refresh flow not yet implemented
- No persistent database for agent state (SQLite optional)

## Acknowledgements

- OWASP for testing methodologies
- PayloadsAllTheThings for payload collections
- FastAPI, Ruff, Pytest communities
- All contributors and users