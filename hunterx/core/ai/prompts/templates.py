from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class PromptCategory(str, Enum):
    THREAT_MODELING = "threat_modeling"
    PAYLOAD_SELECTION = "payload_selection"
    REASONING = "reasoning"
    RISK_ANALYSIS = "risk_analysis"
    EXECUTIVE_REPORT = "executive_report"
    TECHNICAL_REPORT = "technical_report"
    CODE_REVIEW = "code_review"
    REMEDIATION = "remediation"
    SUMMARIZATION = "summarization"
    CLASSIFICATION = "classification"


@dataclass
class PromptTemplate:
    name: str
    category: PromptCategory
    template: str
    description: str = ""
    version: str = "1.0.0"
    variables: List[str] = field(default_factory=list)
    examples: List[Dict[str, str]] = field(default_factory=list)

    def render(self, **kwargs: Any) -> str:
        result = self.template
        for key, value in kwargs.items():
            placeholder = "{" + key + "}"
            if placeholder in result:
                str_value = json.dumps(value, indent=2) if isinstance(value, (dict, list)) else str(value)
                result = result.replace(placeholder, str_value)
        return result

    def validate(self, **kwargs: Any) -> List[str]:
        missing: List[str] = []
        for var in self.variables:
            if var not in kwargs:
                missing.append(var)
        return missing


DEFAULT_PROMPTS: List[PromptTemplate] = [
    PromptTemplate(
        name="threat_analysis",
        category=PromptCategory.THREAT_MODELING,
        description="Analyze threats for a target based on findings and context",
        version="1.0.0",
        variables=["target_url", "findings", "technologies", "context"],
        template="""You are a threat modeling expert. Analyze the following target:

Target URL: {target_url}
Technologies: {technologies}
Detected Findings: {findings}
Additional Context: {context}

Provide a structured threat analysis including:
1. Attack surface analysis
2. Most critical vulnerabilities
3. Potential attack chains
4. Recommended mitigations

Format your response as JSON with keys: attack_surface, critical_vulnerabilities, attack_chains, mitigations""",
    ),
    PromptTemplate(
        name="payload_reasoning",
        category=PromptCategory.REASONING,
        description="Explain why a specific payload was selected for a target",
        version="1.0.0",
        variables=["payload", "category", "target_tech", "context"],
        template="""You are a security payload reasoning expert. Explain why this payload was selected:

Payload: {payload}
Category: {category}
Target Technology: {target_tech}
Context: {context}

Explain:
1. Why this payload is relevant to the target
2. What vulnerability it targets
3. Expected behavior on vulnerable systems
4. Potential WAF evasion techniques applied

Be concise and technical.""",
    ),
    PromptTemplate(
        name="risk_scoring",
        category=PromptCategory.RISK_ANALYSIS,
        description="Score and explain risk for a vulnerability finding",
        version="1.0.0",
        variables=["finding", "context"],
        template="""Analyze the risk of this vulnerability finding:

Finding: {finding}
Context: {context}

Provide a risk score (0-100), impact assessment, and likelihood.
Format as JSON with keys: risk_score, impact, likelihood, reasoning, recommendations""",
    ),
    PromptTemplate(
        name="executive_summary",
        category=PromptCategory.EXECUTIVE_REPORT,
        description="Generate an executive summary of scan results",
        version="1.0.0",
        variables=["target", "findings_summary", "risk_level", "recommendations"],
        template="""Generate an executive security summary for:

Target: {target}
Findings: {findings_summary}
Risk Level: {risk_level}
Recommendations: {recommendations}

Format as a brief executive report covering:
- Overall security posture
- Critical findings (if any)
- Business impact
- Recommended actions

Keep it clear, non-technical, and actionable.""",
    ),
    PromptTemplate(
        name="technical_report",
        category=PromptCategory.TECHNICAL_REPORT,
        description="Generate a detailed technical report",
        version="1.0.0",
        variables=["findings", "context", "technologies"],
        template="""Generate a technical vulnerability report for the following findings:

Findings: {findings}
Context: {context}
Technologies: {technologies}

Include: vulnerability type, affected component, exploitation steps, proof of concept, remediation, CVSS-like score.""",
    ),
    PromptTemplate(
        name="code_review",
        category=PromptCategory.CODE_REVIEW,
        description="Review code for security vulnerabilities",
        version="1.0.0",
        variables=["code", "language", "context"],
        template="""Review this code for security vulnerabilities:

Code ({language}):
{code}

Context: {context}

Identify: vulnerability type, line numbers, impact, and fix suggestions.""",
    ),
    PromptTemplate(
        name="remediation",
        category=PromptCategory.REMEDIATION,
        description="Generate remediation guidance for a vulnerability",
        version="1.0.0",
        variables=["vulnerability", "technology", "severity"],
        template="""Provide remediation guidance for:

Vulnerability: {vulnerability}
Technology: {technology}
Severity: {severity}

Include: immediate steps, permanent fix, code examples, testing guidance, and references.""",
    ),
    PromptTemplate(
        name="finding_summary",
        category=PromptCategory.SUMMARIZATION,
        description="Summarize a set of findings",
        version="1.0.0",
        variables=["findings"],
        template="""Summarize these security findings concisely:

{findings}

Group by category, count occurrences, highlight critical items.""",
    ),
    PromptTemplate(
        name="payload_classification",
        category=PromptCategory.CLASSIFICATION,
        description="Classify a payload by category and technique",
        version="1.0.0",
        variables=["payload", "context"],
        template="""Classify this payload:

Payload: {payload}
Context: {context}

Determine: category (SQLI/XSS/LFI/RCE/SSTI/SSRF/XXE/OTHER), technique, risk level, and WAF bypass potential.
Format as JSON.""",
    ),
    PromptTemplate(
        name="vulnerability_classification",
        category=PromptCategory.CLASSIFICATION,
        description="Classify a vulnerability finding",
        version="1.0.0",
        variables=["finding_text", "response_data"],
        template="""Classify this vulnerability finding:

Evidence: {finding_text}
Response Data: {response_data}

Determine: is it a true positive, false positive, or ambiguous? What is the severity? Format as JSON.""",
    ),
]


class PromptManager:
    def __init__(self):
        self._templates: Dict[str, PromptTemplate] = {}
        for pt in DEFAULT_PROMPTS:
            self._templates[pt.name] = pt

    def get(self, name: str) -> Optional[PromptTemplate]:
        return self._templates.get(name)

    def register(self, template: PromptTemplate) -> None:
        self._templates[template.name] = template

    def render(self, name: str, **kwargs: Any) -> Optional[str]:
        template = self.get(name)
        if not template:
            return None
        missing = template.validate(**kwargs)
        if missing:
            raise ValueError(f"Missing required variables: {missing}")
        return template.render(**kwargs)

    def list_by_category(self, category: PromptCategory) -> List[PromptTemplate]:
        return [t for t in self._templates.values() if t.category == category]

    def list_all(self) -> List[PromptTemplate]:
        return list(self._templates.values())

    def get_categories(self) -> List[str]:
        return [c.value for c in PromptCategory]
