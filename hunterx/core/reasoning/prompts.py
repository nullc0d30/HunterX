from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PromptTemplate:
    name: str
    system_prompt: str
    user_prompt_template: str
    version: str = "1.0.0"
    variables: List[str] = field(default_factory=list)
    expected_output_schema: Optional[Dict[str, Any]] = None
    category: str = "general"

    def format(self, **kwargs: Any) -> Dict[str, str]:
        return {
            "system": self.system_prompt,
            "user": self.user_prompt_template.format(**kwargs),
        }


class ReasoningPromptManager:
    _templates: Dict[str, PromptTemplate] = {}

    @classmethod
    def register(cls, template: PromptTemplate) -> None:
        cls._templates[template.name] = template

    @classmethod
    def get(cls, name: str) -> Optional[PromptTemplate]:
        return cls._templates.get(name)

    @classmethod
    def list_templates(cls, category: str = "") -> List[PromptTemplate]:
        if category:
            return [t for t in cls._templates.values() if t.category == category]
        return list(cls._templates.values())

    @classmethod
    def format(cls, template_name: str, **kwargs: Any) -> Dict[str, str]:
        template = cls.get(template_name)
        if not template:
            raise ValueError(f"Prompt template not found: {template_name}")
        return template.format(**kwargs)


def _register_default_templates() -> None:
    templates = [
        PromptTemplate(
            name="threat_modeling",
            category="threat_modeling",
            system_prompt="You are a threat modeling expert. Analyze the target and identify threats, attack vectors, and risk patterns.",
            user_prompt_template="""Target: {target}
Technologies: {technologies}
Findings: {findings}

Identify:
1. Entry points and attack surface
2. Threat actors and capabilities needed
3. Potential attack vectors
4. Risk levels for each vector
5. Recommended mitigations""",
            variables=["target", "technologies", "findings"],
        ),
        PromptTemplate(
            name="payload_selection",
            category="payload_selection",
            system_prompt="You are a payload selection expert. Choose the most effective payloads for the given vulnerability context.",
            user_prompt_template="""Vulnerability: {vulnerability_type}
Target Technology: {technology}
Framework: {framework}
Previous Attempts: {previous_attempts}
WAF Present: {waf_present}

Select payloads that:
1. Match the vulnerability type
2. Are compatible with the target technology
3. Avoid known WAF signatures
4. Have high success probability
5. Minimize noise and false positives""",
            variables=["vulnerability_type", "technology", "framework", "previous_attempts", "waf_present"],
        ),
        PromptTemplate(
            name="verification",
            category="verification",
            system_prompt="You are a verification expert. Analyze evidence to confirm or refute vulnerability findings.",
            user_prompt_template="""Finding: {finding}
Evidence: {evidence}
Context: {context}

Verify:
1. Evidence supports the finding (confidence 0-1)
2. Alternative explanations
3. False positive probability
4. Recommended follow-up tests""",
            variables=["finding", "evidence", "context"],
        ),
        PromptTemplate(
            name="risk_analysis",
            category="risk_analysis",
            system_prompt="You are a risk analysis expert. Assess the business and technical risk of identified vulnerabilities.",
            user_prompt_template="""Vulnerability: {vulnerability}
Asset Value: {asset_value}
Exploitability: {exploitability}
Impact: {impact}
Existing Controls: {controls}

Provide:
1. Risk score (0-10)
2. Likelihood (Low/Medium/High/Critical)
3. Business impact
4. Recommended priority""",
            variables=["vulnerability", "asset_value", "exploitability", "impact", "controls"],
        ),
        PromptTemplate(
            name="planning",
            category="planning",
            system_prompt="You are a security testing planner. Create an optimal testing plan based on findings and context.",
            user_prompt_template="""Target: {target}
Findings: {findings}
Available Tools: {tools}
Constraints: {constraints}

Generate a testing plan:
1. Prioritized action items
2. Dependencies between actions
3. Estimated effort
4. Risk considerations
5. Success criteria""",
            variables=["target", "findings", "tools", "constraints"],
        ),
        PromptTemplate(
            name="executive_reporting",
            category="reporting",
            system_prompt="You are an executive reporting expert. Create clear, actionable executive summaries of security findings.",
            user_prompt_template="""Findings: {findings}
Risk Scores: {risk_scores}
Compliance: {compliance}

Generate executive report:
1. Overall security posture
2. Critical findings summary
3. Business impact
4. Recommended actions
5. Risk acceptance criteria""",
            variables=["findings", "risk_scores", "compliance"],
        ),
        PromptTemplate(
            name="technical_reporting",
            category="reporting",
            system_prompt="You are a technical reporting expert. Create detailed technical reports for security findings.",
            user_prompt_template="""Finding: {finding}
Evidence: {evidence}
Reproduction Steps: {steps}
Impact: {impact}

Generate technical report:
1. Technical description
2. Proof of concept
3. Remediation guidance
4. References
5. CVSS score""",
            variables=["finding", "evidence", "steps", "impact"],
        ),
        PromptTemplate(
            name="mitigation",
            category="mitigation",
            system_prompt="You are a remediation expert. Provide actionable mitigation strategies for security vulnerabilities.",
            user_prompt_template="""Vulnerability: {vulnerability}
Technology Stack: {technology}
Impact: {impact}
Exploitability: {exploitability}

Provide:
1. Immediate remediation steps
2. Long-term fixes
3. Workarounds if patching is not possible
4. Detection rules
5. Verification steps""",
            variables=["vulnerability", "technology", "impact", "exploitability"],
        ),
        PromptTemplate(
            name="classification",
            category="classification",
            system_prompt="You are a classification expert. Categorize security findings by type, severity, and impact.",
            user_prompt_template="""Finding Description: {description}
Evidence: {evidence}
Context: {context}

Classify:
1. Vulnerability type (OWASP/CWE)
2. Severity (Critical/High/Medium/Low/Info)
3. Confidence level
4. Affected components""",
            variables=["description", "evidence", "context"],
        ),
        PromptTemplate(
            name="summarization",
            category="summarization",
            system_prompt="You are a summarization expert. Create concise summaries of security analysis results.",
            user_prompt_template="""Content: {content}
Format: {format}
Max Length: {max_length}

Summarize while preserving:
1. Key findings
2. Critical risks
3. Actionable insights
4. Data provenance""",
            variables=["content", "format", "max_length"],
        ),
        PromptTemplate(
            name="purple_team",
            category="purple_team",
            system_prompt="You are a purple team expert. Generate detection rules and defensive recommendations from offensive findings.",
            user_prompt_template="""Attack Technique: {technique}
Payload Used: {payload}
Target: {target}
Detection Gaps: {gaps}

Generate:
1. Detection rules (Sigma format)
2. Alerting logic
3. Response procedures
4. False positive tuning""",
            variables=["technique", "payload", "target", "gaps"],
        ),
    ]
    for t in templates:
        ReasoningPromptManager.register(t)


_register_default_templates()
