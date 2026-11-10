# Capability Verification Matrix

| Capability | Evidence needed | Test file | Pass criteria |
|---|---|---|---|
| Consensus Reviewer | Reviewer disagreement and false-positive tests | test_consensus_reviewer.py | Consensus threshold met, false-positive rate < 5% |
| Self-Healing Debugger | Failure recovery and bounded retry tests | test_self_healing_debugger.py | Retry ≤3, state preserved, no infinite loop |
| Threat Modeling | STRIDE coverage and gap-analysis tests | test_threat_modeling.py | Coverage report generated, gaps identified |
| Attack Path Visualizer | Graph integrity and provenance tests | test_attack_path_visualizer.py | Graph nodes/edges valid, provenance metadata present |
| Offensive Doctrine | Activation, isolation, rollback, policy enforcement tests | test_offensive_doctrine.py | Activation works, isolation clean, rollback succeeds, policies enforce |
