from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class DoctrineState:
    target: str = ""
    scope: str = ""
    auth_state: str = ""
    tech_stack: str = ""
    interesting_endpoints: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    next_chain_plan: str = ""

    def summary(self) -> str:
        return (
            f"TARGET | {self.target}\n"
            f"SCOPE | {self.scope}\n"
            f"AUTH STATE | {self.auth_state}\n"
            f"TECH STACK | {self.tech_stack}\n"
            f"INTERESTING ENDPOINTS | {', '.join(self.interesting_endpoints)}\n"
            f"FINDINGS | {', '.join(self.findings)}\n"
            f"NEXT CHAIN PLAN | {self.next_chain_plan}"
        )
