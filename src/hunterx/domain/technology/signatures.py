# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-process technology signature database.

A deterministic, curated set of detection signatures consumed by the
:class:`~hunterx.domain.technology.detector.SignatureDetector` to recognise
technologies from HTTP evidence (headers, HTML, meta, cookies and TLS
certificates) without an external tool. Every signature is a pure pattern with
an evidence type and a relative strength so weak indicators never masquerade as
strong ones.

The database is intentionally small, auditable and golden-tested; it is the
fallback detector and the in-process execution path (like tcp-connect and
dnspython in earlier capabilities), not a replacement for tool-based
fingerprinting.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from hunterx.domain.technology.models import EvidenceStrength, EvidenceType


class SignatureMatchMode(StrEnum):
    """How a signature pattern is evaluated against its evidence."""

    REGEX = "regex"
    SUBSTRING = "substring"


@dataclass(frozen=True, slots=True)
class TechSignature:
    """One detection signature for a technology.

    Attributes:
        technology: canonical technology name this signature detects.
        evidence_type: the kind of evidence the pattern runs against.
        pattern: the substring or regular expression pattern.
        mode: ``regex`` or ``substring`` evaluation.
        strength: relative strength of the indicator.
        version_pattern: optional expression to extract a version. Use
            ``group:<n>`` to select a specific capture group (default group 1).
        version_strength: strength of the version indicator when present.

    """

    technology: str
    evidence_type: EvidenceType = EvidenceType.OTHER
    pattern: str = ""
    mode: SignatureMatchMode = SignatureMatchMode.SUBSTRING
    strength: EvidenceStrength = EvidenceStrength.MODERATE
    version_pattern: str = ""
    version_strength: EvidenceStrength = EvidenceStrength.WEAK

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_type", _evidence_type(self.evidence_type))
        object.__setattr__(self, "strength", _strength(self.strength))
        object.__setattr__(self, "mode", _mode(self.mode))
        object.__setattr__(self, "version_strength", _strength(self.version_strength))

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-safe dictionary."""
        return {
            "technology": self.technology,
            "evidence_type": self.evidence_type.value,
            "pattern": self.pattern,
            "mode": self.mode.value,
            "strength": self.strength.value,
            "version_pattern": self.version_pattern,
            "version_strength": self.version_strength.value,
        }


#: Response-header evidence type (patterns run against ``name: value`` lines).
RESPONSE_HEADER = EvidenceType.RESPONSE_HEADER
#: Cookie evidence type.
COOKIE = EvidenceType.COOKIE
#: HTML body evidence type.
HTML = EvidenceType.HTML
#: Meta-tag evidence type.
META = EvidenceType.META
#: TLS certificate subject/issuer evidence type.
TLS = EvidenceType.TLS_CERTIFICATE
#: HTTP status code evidence type.
HTTP_STATUS = EvidenceType.HTTP_STATUS
#: URL pattern evidence type.
URL_PATTERN = EvidenceType.URL_PATTERN
#: JavaScript asset evidence type.
JAVASCRIPT = EvidenceType.JAVASCRIPT


def _evidence_type(value: str) -> EvidenceType:
    try:
        return EvidenceType(value.lower())
    except ValueError:
        return EvidenceType.OTHER


def _strength(value: str) -> EvidenceStrength:
    try:
        return EvidenceStrength(value.lower())
    except ValueError:
        return EvidenceStrength.MODERATE


def _mode(value: str) -> SignatureMatchMode:
    try:
        return SignatureMatchMode(value.lower())
    except ValueError:
        return SignatureMatchMode.SUBSTRING

#: The canonical signature database: technology -> signatures.
SIGNATURES: dict[str, tuple[TechSignature, ...]] = {
    "Apache HTTP Server": (
        TechSignature("Apache HTTP Server", RESPONSE_HEADER, "server: apache", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG, r"Apache(?:/(\d+(?:\.\d+){0,2}))?", EvidenceStrength.MODERATE),
        TechSignature("Apache HTTP Server", HTML, "apache", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "Nginx": (
        TechSignature("Nginx", RESPONSE_HEADER, "server: nginx", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG, r"nginx(?:/(\d+(?:\.\d+){0,2}))?", EvidenceStrength.MODERATE),
        TechSignature("Nginx", META, "generator\" content=\"nginx", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "Microsoft IIS": (
        TechSignature("Microsoft IIS", RESPONSE_HEADER, "server: microsoft-iis", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG, r"Microsoft-IIS(?:/(\d+(?:\.\d+){0,2}))?", EvidenceStrength.MODERATE),
        TechSignature("Microsoft IIS", RESPONSE_HEADER, "server: microsoft-httpapi", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "LiteSpeed": (
        TechSignature("LiteSpeed", RESPONSE_HEADER, "server: litespeed", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG, r"LiteSpeed(?:/(\d+(?:\.\d+){0,2}))?", EvidenceStrength.MODERATE),
    ),
    "WordPress": (
        TechSignature("WordPress", HTML, "wp-content", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("WordPress", HTML, "wp-includes", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("WordPress", META, "generator\" content=\"WordPress", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG, r"WordPress\s*(\d+(?:\.\d+){0,2})?", EvidenceStrength.MODERATE),
        TechSignature("WordPress", HTML, "pingback", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("WordPress", COOKIE, "wordpress_", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("WordPress", COOKIE, "wp-settings", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Drupal": (
        TechSignature("Drupal", HTML, "drupal", SignatureMatchMode.REGEX, EvidenceStrength.MODERATE, r"Drupal\s*(\d+\.\d+)?", EvidenceStrength.WEAK),
        TechSignature("Drupal", META, "generator\" content=\"Drupal", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG, r"Drupal\s*(\d+\.\d+)?", EvidenceStrength.MODERATE),
        TechSignature("Drupal", HTML, "drupal.js", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Joomla": (
        TechSignature("Joomla", META, "generator\" content=\"Joomla", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG, r"Joomla!\s*(\d+(?:\.\d+){0,2})?", EvidenceStrength.MODERATE),
        TechSignature("Joomla", COOKIE, "joomla", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Joomla", HTML, "/media/system/js", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Django": (
        TechSignature("Django", RESPONSE_HEADER, "csrftoken", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Django", COOKIE, "csrftoken", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Django", RESPONSE_HEADER, "x-frame-options", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "Flask": (
        TechSignature("Flask", COOKIE, "session", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Flask", RESPONSE_HEADER, "server: werkzeug", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG, r"Werkzeug(?:/(\d+(?:\.\d+){0,3}))?", EvidenceStrength.MODERATE),
    ),
    "React": (
        TechSignature("React", HTML, "__react", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("React", HTML, "data-reactroot", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("React", HTML, "_next/static", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "Vue.js": (
        TechSignature("Vue.js", HTML, "data-v-", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Vue.js", HTML, "__vue__", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Vue.js", HTML, "vue.global", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Angular": (
        TechSignature("Angular", HTML, "ng-version", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG, r"ng-version=\"(\d+(?:\.\d+){0,2})\"", EvidenceStrength.MODERATE),
        TechSignature("Angular", HTML, "angular.js", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Next.js": (
        TechSignature("Next.js", HTML, "__next", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Next.js", HTML, "_next/static", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("Next.js", HTML, "next-head", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Nuxt": (
        TechSignature("Nuxt", HTML, "__NUXT__", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("Nuxt", META, "generator\" content=\"Nuxt", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "jQuery": (
        TechSignature("jQuery", HTML, "jquery", SignatureMatchMode.REGEX, EvidenceStrength.MODERATE, r"jquery(?:-(\d+(?:\.\d+){1,3}))?", EvidenceStrength.MODERATE),
        TechSignature("jQuery", HTML, "jQuery.fn.jquery", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Bootstrap": (
        TechSignature("Bootstrap", HTML, "bootstrap", SignatureMatchMode.REGEX, EvidenceStrength.MODERATE, r"bootstrap(?:/|-)(\d+(?:\.\d+){0,2})", EvidenceStrength.MODERATE),
        TechSignature("Bootstrap", HTML, "data-bs-", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Tailwind CSS": (
        TechSignature("Tailwind CSS", HTML, "tailwind", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
        TechSignature("Tailwind CSS", HTML, "text-sm", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "Webpack": (
        TechSignature("Webpack", HTML, "webpack", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
        TechSignature("Webpack", HTML, "__webpack", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Vite": (
        TechSignature("Vite", HTML, "vite", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
        TechSignature("Vite", HTML, "@vite", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "PHP": (
        TechSignature("PHP", RESPONSE_HEADER, "x-powered-by: php", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG, r"PHP/(\d+(?:\.\d+){0,2})", EvidenceStrength.MODERATE),
        TechSignature("PHP", HTML, "PHP", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "Node.js": (
        TechSignature("Node.js", RESPONSE_HEADER, "x-powered-by: express", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Node.js", HTML, "node.js", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "Python": (
        TechSignature("Python", RESPONSE_HEADER, "x-powered-by: python", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Python", RESPONSE_HEADER, "server: python", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "Cloudflare": (
        TechSignature("Cloudflare", RESPONSE_HEADER, "cf-ray", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("Cloudflare", RESPONSE_HEADER, "server: cloudflare", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("Cloudflare", COOKIE, "__cfduid", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Cloudflare", TLS, "cloudflare", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Cloudflare WAF": (
        TechSignature("Cloudflare WAF", RESPONSE_HEADER, "__cf_bm", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Cloudflare WAF", COOKIE, "__cf_bm", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Cloudflare WAF", HTML, "cloudflare", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "Amazon CloudFront": (
        TechSignature("Amazon CloudFront", RESPONSE_HEADER, "x-amz-cf-id", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("Amazon CloudFront", RESPONSE_HEADER, "x-amz-cf-pop", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("Amazon CloudFront", RESPONSE_HEADER, "via: http/1.1", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "Amazon ELB": (
        TechSignature("Amazon ELB", RESPONSE_HEADER, "x-amzn-requestid", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Amazon ELB", RESPONSE_HEADER, "server: awselb", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
    ),
    "Amazon ALB": (
        TechSignature("Amazon ALB", RESPONSE_HEADER, "server: awslb", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("Amazon ALB", RESPONSE_HEADER, "x-amzn-trace-id", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Fastly": (
        TechSignature("Fastly", RESPONSE_HEADER, "x-fastly-request-id", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("Fastly", RESPONSE_HEADER, "via: 1.1 varnish", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "Akamai": (
        TechSignature("Akamai", RESPONSE_HEADER, "x-akamai-transformed", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("Akamai", RESPONSE_HEADER, "server: akamaighost", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("Akamai", COOKIE, "ak_bmsc", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Nginx Reverse Proxy": (
        TechSignature("Nginx Reverse Proxy", RESPONSE_HEADER, "x-forwarded-for", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Nginx Reverse Proxy", RESPONSE_HEADER, "x-nginx-proxy", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
    ),
    "Varnish": (
        TechSignature("Varnish", RESPONSE_HEADER, "via: 1.1 varnish", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG, r"via: \d+\.\d+ varnish(?:-v(\d+(?:\.\d+){0,2}))?", EvidenceStrength.MODERATE),
        TechSignature("Varnish", RESPONSE_HEADER, "x-varnish", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
    ),
    "HAProxy": (
        TechSignature("HAProxy", RESPONSE_HEADER, "server: haproxy", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("HAProxy", RESPONSE_HEADER, "x-haproxy", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "ModSecurity": (
        TechSignature("ModSecurity", RESPONSE_HEADER, "mod_security", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("ModSecurity", RESPONSE_HEADER, "x-mod-sec", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
    "Google reCAPTCHA": (
        TechSignature("Google reCAPTCHA", HTML, "g-recaptcha", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("Google reCAPTCHA", HTML, "recaptcha/api", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
    ),
    "Google Analytics": (
        TechSignature("Google Analytics", HTML, "google-analytics", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("Google Analytics", HTML, "gtag(", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
        TechSignature("Google Analytics", HTML, "ga(", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "JWT": (
        TechSignature("JWT", RESPONSE_HEADER, "authorization: bearer eyj", SignatureMatchMode.SUBSTRING, EvidenceStrength.STRONG),
        TechSignature("JWT", HTML, "jwt", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
    ),
    "OAuth": (
        TechSignature("OAuth", HTML, "oauth", SignatureMatchMode.SUBSTRING, EvidenceStrength.WEAK),
        TechSignature("OAuth", RESPONSE_HEADER, "www-authenticate: bearer", SignatureMatchMode.SUBSTRING, EvidenceStrength.MODERATE),
    ),
}


def signatures_for(technology: str) -> tuple[TechSignature, ...]:
    """Return the signature set for a canonical technology (empty when unknown)."""
    return SIGNATURES.get(technology, ())


def all_signatures() -> tuple[TechSignature, ...]:
    """Return every signature in the database (deterministic order)."""
    ordered: list[TechSignature] = []
    for technology in sorted(SIGNATURES):
        ordered.extend(SIGNATURES[technology])
    return tuple(ordered)
