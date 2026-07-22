# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
from typing import List, Dict

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


class HTMLAnalyzer:
    """Analyzes HTML responses using DOM parsing for structural changes."""

    def __init__(self):
        self.parser = "lxml" if HAS_BS4 else "html.parser"

    def analyze_structure(self, baseline_html: str, response_html: str) -> List[Dict]:
        """Compare DOM structure between baseline and response."""
        findings = []
        if not HAS_BS4:
            return findings

        try:
            base_soup = BeautifulSoup(baseline_html, self.parser)
            resp_soup = BeautifulSoup(response_html, self.parser)

            # Check for new script tags
            base_scripts = {s.get("src", "") for s in base_soup.find_all("script") if s.get("src")}
            resp_scripts = {s.get("src", "") for s in resp_soup.find_all("script") if s.get("src")}
            new_scripts = resp_scripts - base_scripts
            if new_scripts:
                findings.append({
                    "type": "dom_new_scripts",
                    "detail": f"New script tags found: {', '.join(new_scripts)}",
                })

            # Check for new iframes (XSS/HTML injection indicator)
            base_iframes = len(base_soup.find_all("iframe"))
            resp_iframes = len(resp_soup.find_all("iframe"))
            if resp_iframes > base_iframes:
                findings.append({
                    "type": "dom_new_iframes",
                    "detail": f"Iframe count changed: {base_iframes} -> {resp_iframes}",
                })

            # Check for form structure changes
            base_forms = len(base_soup.find_all("form"))
            resp_forms = len(resp_soup.find_all("form"))
            if resp_forms != base_forms:
                findings.append({
                    "type": "dom_form_change",
                    "detail": f"Form count changed: {base_forms} -> {resp_forms}",
                })

            # Tag count differential
            base_tags = len(base_soup.find_all())
            resp_tags = len(resp_soup.find_all())
            tag_diff = abs(resp_tags - base_tags)
            if tag_diff > 10:
                findings.append({
                    "type": "dom_tag_count",
                    "detail": f"Tag count changed by {tag_diff} ({base_tags} -> {resp_tags})",
                })

        except Exception:
            pass

        return findings

    def extract_forms(self, html: str) -> List[Dict]:
        """Extract form details for targeted fuzzing."""
        forms = []
        if not HAS_BS4:
            return forms
        try:
            soup = BeautifulSoup(html, self.parser)
            for form in soup.find_all("form"):
                form_data = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").upper(),
                    "inputs": [],
                }
                for inp in form.find_all("input"):
                    form_data["inputs"].append({
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
                forms.append(form_data)
        except Exception:
            pass
        return forms

    def find_comments(self, html: str) -> List[str]:
        """Extract HTML comments that may leak information."""
        comments = []
        if not HAS_BS4:
            return comments
        try:
            soup = BeautifulSoup(html, "html.parser")
            for comment in soup.find_all(string=lambda text: isinstance(text, str) and "<!--" in str(text)):
                comments.append(str(comment).strip())
        except Exception:
            pass
        return comments
