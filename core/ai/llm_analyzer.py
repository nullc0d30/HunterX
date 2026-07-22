import json
from typing import List, Dict, Optional

try:
    import ollama
    HAS_OLLAMA = True
except ImportError:
    HAS_OLLAMA = False


class LLMAnalyzer:
    """Uses local LLM (via Ollama) for semantic analysis of anomalous responses."""

    def __init__(self, model: str = "llama3.2", endpoint: str = "http://localhost:11434"):
        self.model = model
        self.endpoint = endpoint
        self._client = None
        if HAS_OLLAMA:
            self._client = ollama.Client(host=endpoint)

    def analyze_finding(self, finding: Dict, context: Dict) -> Optional[Dict]:
        """Ask LLM to classify and explain a finding."""
        if not self._client:
            return None

        prompt = f"""You are a security analyst. Analyze this vulnerability finding:

Category: {finding.get('payload_category', 'Unknown')}
Payload: {finding.get('payload', '')}
Diff Score: {finding.get('diff_score', 0)}
Detections: {finding.get('findings', [])}

Target Context: {json.dumps(context, indent=2)}

Respond in JSON format:
{{"classification": "real/false_positive/ambiguous",
"severity": "low/medium/high/critical",
"explanation": "brief analysis",
"next_steps": ["step1", "step2"]}}"""

        try:
            resp = self._client.generate(model=self.model, prompt=prompt)
            text = resp.get("response", "")
            # Extract JSON from response
            json_start = text.find("{")
            json_end = text.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(text[json_start:json_end])
        except Exception:
            pass
        return None

    def batch_analyze(self, findings: List[Dict], context: Dict) -> List[Dict]:
        """Analyze multiple findings, returns enriched results."""
        enriched = []
        for f in findings:
            llm_result = self.analyze_finding(f, context)
            if llm_result:
                f["llm_analysis"] = llm_result
                enriched.append(f)
            else:
                enriched.append(f)
        return enriched

    def suggest_remediation(self, finding: Dict) -> Optional[str]:
        """Ask LLM for remediation advice."""
        if not self._client:
            return None

        prompt = f"""Suggest a fix for this vulnerability:
Category: {finding.get('payload_category', 'Unknown')}
Detail: {finding.get('findings', '')}
Payload: {finding.get('payload', '')}

Provide a concise remediation recommendation (2-3 sentences)."""

        try:
            resp = self._client.generate(model=self.model, prompt=prompt)
            return resp.get("response", "").strip()
        except Exception:
            return None
