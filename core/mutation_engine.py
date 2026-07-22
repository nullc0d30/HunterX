# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import urllib.parse
from typing import List, Dict


class MutationEngine:
    """Generates payload variants for WAF evasion and broader coverage."""

    ENCODING_TECHNIQUES = [
        "url_encode",
        "double_url_encode",
        "unicode_encode",
        "hex_encode",
        "base64",
        "html_entity",
    ]

    def __init__(self, evasion_level: str = "medium"):
        self.evasion_level = evasion_level

    def mutate(self, payload: str, category: str = "GENERIC") -> List[Dict]:
        """Generate mutated variants of a payload."""
        variants = [{"payload": payload, "technique": "original"}]

        if self.evasion_level in ("medium", "high"):
            variants.append({
                "payload": urllib.parse.quote(payload, safe=""),
                "technique": "url_encode",
            })

        if self.evasion_level == "high":
            variants.append({
                "payload": urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""),
                "technique": "double_url_encode",
            })

            if "'" in payload:
                variants.append({
                    "payload": payload.replace("'", "%27"),
                    "technique": "hex_encode_quote",
                })

            if "/" in payload:
                variants.append({
                    "payload": payload.replace("/", "//"),
                    "technique": "path_double_slash",
                })
                variants.append({
                    "payload": payload.replace("/", "/./"),
                    "technique": "path_dot_slash",
                })

            if category == "SQLI":
                variants.append({
                    "payload": payload.replace(" ", "/**/"),
                    "technique": "sql_comment_whitespace",
                })
                variants.append({
                    "payload": payload.replace("=", ">"),
                    "technique": "sql_greater_than",
                })

            if category == "XSS":
                variants.append({
                    "payload": f"<script>{payload}</script>",
                    "technique": "xss_script_wrap",
                })
                variants.append({
                    "payload": f'<img src=x onerror="{payload}">',
                    "technique": "xss_img_onerror",
                })

            if category == "LFI":
                variants.append({
                    "payload": payload.replace("../", "....//....//"),
                    "technique": "lfi_double_dot_double_slash",
                })
                variants.append({
                    "payload": payload.replace("../", "..\\/..\\/"),
                    "technique": "lfi_backslash",
                })

        return variants
