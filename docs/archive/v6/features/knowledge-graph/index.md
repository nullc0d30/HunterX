# Knowledge Graph

The Knowledge Graph is a central component of HunterX that stores and interrelates collected threat intelligence, including assets, vulnerabilities, threats, and attack patterns.

## Purpose

To provide a unified, queryable representation of the target environment and threat landscape, enabling advanced analytics and automated reasoning.

## Architecture

Built as a property graph, the Knowledge Graph uses nodes and edges to represent entities and their relationships. It is updated in real-time during scanning and enrichment phases.

## Workflow

1. Data ingestion from scanners and threat feeds
2. Entity extraction and normalization
3. Relationship mapping (e.g., vulnerability-to-asset, attack-pattern-to-threat)
4. Storage in a graph database (Neo4j or similar)
5. Querying via GraphQL or Cypher for insights

## Advantages

- Enables contextual understanding of findings
- Supports predictive attack path analysis
- Facilitates automated reporting and remediation

## Integration

Accessible via the HunterX API and CLI for custom tooling and integration with SIEMs.

## Related Components

- Reasoning Engine (uses the graph for inference)
- Threat Modeling (generates attack graphs)
- Payload Intelligence (enriched with context)

## Related Resources

- [Documentation](/documentation/)
- [Tutorials](/tutorials/)
- [Comparisons](/comparisons/)
- [Research](/reference-guide/)
- [Installation](/installation/)
- [Quickstart](/quickstart/)
- [All Features](/features/)


