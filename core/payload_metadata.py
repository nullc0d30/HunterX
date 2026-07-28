# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List



TECHNOLOGY_PATTERNS: Dict[str, List[str]] = {
    "PHP": [r"\.php", r"phpinfo", r"PHP_SESSION", r"laravel", r"wordpress", r"wp-content", r"joomla", r"drupal", r"symfony", r"codeigniter", r"cakephp", r"smarty", r"twig"],
    "ASP.NET": [r"\.asp", r"\.aspx", r"__VIEWSTATE", r"aspnet", r"iis", r"x-aspnet", r"\.dll"],
    "Java": [r"\.jsp", r"\.jspa", r"\.do", r"servlet", r"spring", r"struts", r"tomcat", r"jboss", r"weblogic", r"websphere", r"java\.lang", r"javax\.servlet"],
    "Python": [r"\.py", r"django", r"flask", r"fastapi", r"bottle", r"tornado", r"jinja", r"wsgi", r"uwsgi"],
    "Node.js": [r"\.js", r"express", r"node_modules", r"next\.js", r"nuxt", r"socket\.io", r"passport"],
    "Ruby": [r"\.rb", r"rails", r"ruby", r"rack", r"erb", r"sinatra"],
    "Go": [r"\.go", r"golang", r"gin", r"echo"],
    "Rust": [r"\.rs", r"actix", r"rocket", r"warp"],
    "Apache": [r"apache", r"\.htaccess", r"mod_"],
    "Nginx": [r"nginx"],
    "Tomcat": [r"tomcat", r"catalina"],
    "Cloudflare": [r"cloudflare", r"__cfduid", r"cf-ray"],
    "AWS": [r"aws", r"amazonaws", r"s3\.amazonaws", r"ec2"],
    "Azure": [r"azure", r"windows\.net", r"azurewebsites"],
    "GCP": [r"gcp", r"googleapis", r"appspot"],
    "Kubernetes": [r"kube", r"kubernetes"],
    "Docker": [r"docker", r"container"],
    "MySQL": [r"mysql", r"mariadb"],
    "PostgreSQL": [r"postgres", r"postgresql"],
    "MongoDB": [r"mongo", r"mongodb", r"nosql"],
    "Redis": [r"redis"],
    "GraphQL": [r"graphql", r"graphiql", r"__schema"],
    "WebSocket": [r"websocket", r"ws://", r"wss://"],
    "JWT": [r"jwt", r"json web token"],
    "OAuth": [r"oauth", r"openid"],
    "SAML": [r"saml"],
    "REST": [r"rest", r"restful", r"api/", r"api/v"],
    "SOAP": [r"soap", r"wsdl"],
    "Protobuf": [r"protobuf", r"grpc"],
}

FRAMEWORK_PATTERNS: Dict[str, List[str]] = {
    "Laravel": [r"laravel", r"artisan", r"\.env"],
    "Django": [r"django", r"csrfmiddlewaretoken", r"django\."],
    "Flask": [r"flask", r"flask\.", r"jinja2"],
    "Spring": [r"spring", r"springframework", r"@RequestMapping"],
    "Express": [r"express", r"express\.js"],
    "Rails": [r"rails", r"ruby on rails"],
    "Symfony": [r"symfony", r"twig"],
    "ASP.NET MVC": [r"mvc", r"aspnet mvc"],
    "WordPress": [r"wp-", r"wordpress", r"wp-content"],
    "Drupal": [r"drupal"],
    "Joomla": [r"joomla"],
    "Next.js": [r"next\.js", r"_next"],
    "Nuxt.js": [r"nuxt"],
    "Vue.js": [r"vue\.js", r"vuejs"],
    "React": [r"react", r"react\.js"],
    "Angular": [r"angular", r"ng-"],
}

LANGUAGE_PATTERNS: Dict[str, List[str]] = {
    "PHP": [r"<\?php", r"<\?", r"php"],
    "Python": [r"python", r"def \w+\(|import \w+|from \w+"],
    "JavaScript": [r"javascript", r"function\s*\(", r"var \w+|let \w+|const \w+"],
    "Java": [r"java", r"public class|private class|protected class"],
    "Ruby": [r"ruby|def \w+\s*\n|end\s*\n"],
    "C#": [r"c#|using System|namespace |class .*:"],
    "Go": [r"go|package main|func main"],
    "Rust": [r"rust|fn main|impl "],
    "SQL": [r"select |from |where |insert |update |delete |drop |union "],
    "Bash": [r"bash|sh |#!/|echo |chmod |chown |curl |wget "],
    "PowerShell": [r"powershell|Invoke-|Get-|Set-|Write-Host"],
}

OS_PATTERNS: Dict[str, List[str]] = {
    "Linux": [r"linux", r"unix", r"/etc/", r"/var/", r"/usr/", r"/bin/", r"/tmp/", r"bash", r"sh ", r"chmod", r"chown"],
    "Windows": [r"windows", r"win\.ini", r"c:\\", r"cmd\.exe", r"powershell", r".exe", r".dll"],
    "macOS": [r"macos", r"os x", r"darwin"],
    "Cross-Platform": [r"http", r"request", r"response", r"header", r"cookie"],
}

CONTEXT_PATTERNS: Dict[str, List[str]] = {
    "HTML": [r"<html|<body|<div|<span|<input|<form|<script|<\/"],
    "JSON": [r"\{.*\}|\[.*\]", r"\"\w+\":\s*"],
    "XML": [r"<[^>]+>", r"<!DOCTYPE", r"<\\?xml"],
    "URL": [r"https?://", r"url=|uri=|redirect="],
    "SQL": [r"select|from|where|union|order by|group by|having|insert|update|delete"],
    "JavaScript": [r"<script|javascript:|onerror=|onload=|onclick=|alert\(|console\."],
    "GraphQL": [r"query |mutation |subscription |__typename|__schema"],
    "LDAP": [r"ldap|cn=|dc=|ou="],
    "NoSQL": [r"\{\s*\$|\$gt|\$ne|\$where|\$regex"],
    "Template": [r"\{\{|\$\{|<%|<%=|#{"],
    "HTTP Header": [r"header|Cookie:|User-Agent:|Referer:|X-Forwarded"],
    "WebSocket": [r"ws://|wss://|websocket"],
    "Multipart": [r"multipart|boundary|Content-Disposition"],
}


@dataclass
class PayloadMetadata:
    category: str = ""
    technology: List[str] = field(default_factory=list)
    framework: List[str] = field(default_factory=list)
    language: List[str] = field(default_factory=list)
    os_targets: List[str] = field(default_factory=list)
    encoding: str = "plain"
    context: List[str] = field(default_factory=list)
    expected_response: str = "unknown"
    noise_level: float = 0.5
    danger_level: float = 0.3
    required_privileges: str = "none"
    execution_context: str = "remote"
    auth_requirement: str = "none"
    waf_compatibility: float = 0.5
    difficulty: str = "medium"
    complexity: str = "medium"
    reliability: float = 0.5
    references: List[str] = field(default_factory=list)
    related_cves: List[str] = field(default_factory=list)
    related_cwes: List[str] = field(default_factory=list)
    capec_ids: List[str] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    nist_controls: List[str] = field(default_factory=list)
    asvs_requirements: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class PayloadMetadataEngine:
    def __init__(self):
        self._technology_patterns = TECHNOLOGY_PATTERNS
        self._framework_patterns = FRAMEWORK_PATTERNS
        self._language_patterns = LANGUAGE_PATTERNS
        self._os_patterns = OS_PATTERNS
        self._context_patterns = CONTEXT_PATTERNS

    def analyze(
        self,
        filename: str,
        content: str,
        category: str = "",
        rel_path: str = "",
    ) -> PayloadMetadata:
        metadata = PayloadMetadata(category=category)

        content_lower = content.lower()
        filename_lower = filename.lower()

        for tech, patterns in self._technology_patterns.items():
            if any(re.search(p, content_lower) for p in patterns):
                metadata.technology.append(tech)
            elif any(tech.lower() in filename_lower for tech in tech.split(", ")):
                if tech not in metadata.technology:
                    metadata.technology.append(tech)

        for fw, patterns in self._framework_patterns.items():
            if any(re.search(p, content_lower) for p in patterns):
                metadata.framework.append(fw)
            elif fw.lower() in filename_lower:
                if fw not in metadata.framework:
                    metadata.framework.append(fw)

        for lang, patterns in self._language_patterns.items():
            if any(re.search(p, content_lower) for p in patterns):
                metadata.language.append(lang)

        for os_name, patterns in self._os_patterns.items():
            if any(re.search(p, content_lower) for p in patterns):
                metadata.os_targets.append(os_name)

        for ctx, patterns in self._context_patterns.items():
            if any(re.search(p, content_lower) for p in patterns):
                metadata.context.append(ctx)
                if ctx not in metadata.tags:
                    metadata.tags.append(ctx.lower().replace(" ", "_"))

        if category:
            metadata.tags.append(category.lower())
            metadata = self._apply_category_defaults(metadata, category)

        if filename:
            metadata.file_type = self._detect_file_type(filename)

        if content and len(content) > 10:
            metadata = self._assess(metadata, content)

        return metadata

    def _apply_category_defaults(self, metadata: PayloadMetadata, category: str) -> PayloadMetadata:
        cat_upper = category.upper()
        if cat_upper in ("RCE", "COMMAND_INJECTION", "CMDI"):
            metadata.danger_level = 0.95
            metadata.reliability = 0.7
            metadata.required_privileges = "low"
            metadata.related_cwes = ["CWE-78", "CWE-77", "CWE-94"]
            metadata.mitre_techniques = ["T1203"]
            metadata.owasp_categories = ["A03:2021-Injection"]
            metadata.nist_controls = ["SI-10"]
        elif cat_upper in ("SQLI", "SQL_INJECTION"):
            metadata.danger_level = 0.9
            metadata.reliability = 0.8
            metadata.related_cwes = ["CWE-89"]
            metadata.mitre_techniques = ["T1190"]
            metadata.capec_ids = ["CAPEC-66", "CAPEC-7"]
            metadata.owasp_categories = ["A03:2021-Injection"]
            metadata.nist_controls = ["SI-10"]
        elif cat_upper in ("LFI", "PATH_TRAVERSAL", "FILE_DISCLOSURE"):
            metadata.danger_level = 0.7
            metadata.reliability = 0.85
            metadata.related_cwes = ["CWE-22", "CWE-73"]
            metadata.mitre_techniques = ["T1005"]
            metadata.owasp_categories = ["A01:2021-Broken Access Control"]
        elif cat_upper in ("XSS", "CROSS_SITE_SCRIPTING"):
            metadata.danger_level = 0.6
            metadata.reliability = 0.65
            metadata.related_cwes = ["CWE-79"]
            metadata.mitre_techniques = ["T1059.007"]
            metadata.owasp_categories = ["A03:2021-Injection"]
            metadata.nist_controls = ["SI-10"]
        elif cat_upper in ("SSTI", "TEMPLATE_INJECTION"):
            metadata.danger_level = 0.85
            metadata.reliability = 0.7
            metadata.related_cwes = ["CWE-94", "CWE-1336"]
            metadata.mitre_techniques = ["T1203"]
        elif cat_upper in ("SSRF",):
            metadata.danger_level = 0.75
            metadata.reliability = 0.6
            metadata.related_cwes = ["CWE-918"]
            metadata.mitre_techniques = ["T1595.002"]
        elif cat_upper in ("XXE",):
            metadata.danger_level = 0.8
            metadata.reliability = 0.7
            metadata.related_cwes = ["CWE-611"]
            metadata.mitre_techniques = ["T1190"]

        return metadata

    def _assess(self, metadata: PayloadMetadata, content: str) -> PayloadMetadata:
        length = len(content)
        has_special = bool(re.search(r'[<>{}()\'"$;|`&]', content))
        has_encoding = bool(re.search(r'%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|&#[0-9]+;|&#x[0-9a-fA-F]+;', content))

        if length > 200:
            metadata.complexity = "high"
            metadata.noise_level = min(1.0, metadata.noise_level + 0.2)
        elif length > 50:
            metadata.complexity = "medium"
        else:
            metadata.complexity = "low"

        if has_special and has_encoding:
            metadata.difficulty = "hard"
        elif has_special:
            metadata.difficulty = "medium"
        else:
            metadata.difficulty = "easy"

        if has_encoding:
            metadata.encoding = "encoded"

        metadata.references = self._extract_references(content)

        return metadata

    def _detect_file_type(self, filename: str) -> str:
        ext = os.path.splitext(filename)[1].lower() if "." in filename else ""
        ext_map = {
            ".txt": "text", ".md": "markdown", ".json": "json",
            ".xml": "xml", ".html": "html", ".yaml": "yaml", ".yml": "yaml",
            ".py": "python", ".php": "php", ".js": "javascript",
            ".rb": "ruby", ".java": "java", ".cs": "csharp",
            ".go": "go", ".rs": "rust", ".sh": "shell",
            ".ps1": "powershell", ".sql": "sql", ".graphql": "graphql",
        }
        return ext_map.get(ext, "unknown")

    @staticmethod
    def _extract_references(content: str) -> List[str]:
        refs = []
        url_pattern = r'https?://[^\s<>"\'\)]+'
        refs.extend(re.findall(url_pattern, content))
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        refs.extend(re.findall(cve_pattern, content, re.IGNORECASE))
        return list(set(refs))
