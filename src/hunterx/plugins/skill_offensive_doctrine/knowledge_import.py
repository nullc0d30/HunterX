from __future__ import annotations
"""Doctrine knowledge records."""

DOCTRINE_RECORDS = [
    {
        "id": "recon.pipeline",
        "title": "Standard Recon Pipeline",
        "tags": ["recon", "subdomain", "httpx"],
        "summary": "crt.sh → subfinder → assetfinder → dnsx → httpx → katana → waybackurls/gau → nuclei"
    },
    {
        "id": "chain.idor_to_modify",
        "title": "IDOR Read to Modify",
        "tags": ["chain", "idor"],
        "summary": "IDOR read → PUT/DELETE verb tampering / HPP"
    },
    {
        "id": "web3.scorecard",
        "title": "Immunefi GO/NO-GO Scorecard",
        "tags": ["web3", "immunefi"],
        "summary": "Max bounty >=$50K, TVL >$1M, program <30 days, custom math, recent commits"
    },
    {
        "id": "llm.injection",
        "title": "LLM Agent Injection Taxonomy",
        "tags": ["llm", "ai"],
        "summary": "Direct injection, indirect injection, zero-click markdown exfil, tool-use exfil"
    },
    {
        "id": "field.2026.saml",
        "title": "SAML 2025-2026 Wave",
        "tags": ["auth", "saml"],
        "summary": "WebLogic SAML bypass CVE-2026-60206, ruby saml_idp default key, IdP binding flaws"
    },
]
