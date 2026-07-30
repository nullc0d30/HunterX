# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import json
import random
import re
import urllib.parse
from typing import Dict, List


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

    ADVANCED_TECHNIQUES = [
        "json_encode",
        "json_unicode",
        "multipart",
        "chunked",
        "graphql_wrap",
        "websocket_frame",
        "unicode_normalize",
        "utf7_encode",
        "sql_case_mutation",
        "html_entity_all",
        "whitespace_injection",
        "unicode_escape_all",
    ]

    def __init__(self, evasion_level: str = "medium"):
        self.evasion_level = evasion_level

    def mutate(self, payload: str, category: str = "GENERIC") -> List[Dict]:
        """Generate mutated variants of a payload."""
        variants = [{"payload": payload, "technique": "original"}]

        if self.evasion_level in ("medium", "high"):
            variants.extend(self._url_mutations(payload))
            variants.extend(self._html_entity_mutations(payload))

        if self.evasion_level == "high":
            variants.extend(self._unicode_mutations(payload))
            variants.extend(self._category_specific(payload, category))
            variants.extend(self._waf_evasion_mutations(payload))
            variants.extend(self._json_mutations(payload))
            variants.extend(self._sql_case_mutations(payload))
            variants.extend(self._whitespace_injections(payload))
            variants.extend(self._multipart_mutations(payload))
            variants.extend(self._chunked_mutations(payload))
            variants.extend(self._graphql_mutations(payload))
            variants.extend(self._websocket_mutations(payload))

        return variants

    def mutate_advanced(self, payload: str, category: str = "GENERIC") -> List[Dict]:
        """Generate all known mutations including advanced techniques."""
        variants = self.mutate(payload, category)

        variants.extend(self._unicode_escape_all(payload))
        variants.extend(self._utf7_mutations(payload))
        variants.extend(self._json_unicode_mutations(payload))
        variants.extend(self._hex_encode_all(payload))

        seen = set()
        unique = []
        for v in variants:
            key = v["payload"]
            if key not in seen:
                seen.add(key)
                unique.append(v)
        return unique

    def _url_mutations(self, payload: str) -> List[Dict]:
        variants = []
        encoded = urllib.parse.quote(payload, safe="")
        if encoded != payload:
            variants.append({"payload": encoded, "technique": "url_encode"})
        double = urllib.parse.quote(encoded, safe="")
        if double != encoded:
            variants.append({"payload": double, "technique": "double_url_encode"})
        return variants

    def _html_entity_mutations(self, payload: str) -> List[Dict]:
        variants = []
        html_encoded = ""
        for ch in payload:
            html_encoded += f"&#{ord(ch)};"
        if html_encoded != payload:
            variants.append({"payload": html_encoded, "technique": "html_entity"})
        hex_encoded = ""
        for ch in payload:
            hex_encoded += f"&#x{ord(ch):02X};"
        if hex_encoded != payload:
            variants.append({"payload": hex_encoded, "technique": "html_entity_hex"})
        return variants

    def _unicode_mutations(self, payload: str) -> List[Dict]:
        variants = []
        unicode_map = {"<": "%u003C", ">": "%u003E", "'": "%u0027", '"': "%u0022",
                       "(": "%u0028", ")": "%u0029", "=": "%u003D"}
        encoded = ""
        for ch in payload:
            encoded += unicode_map.get(ch, ch)
        if encoded != payload:
            variants.append({"payload": encoded, "technique": "unicode_encode"})

        encoded2 = ""
        for ch in payload:
            encoded2 += f"\\u{ord(ch):04x}"
        if encoded2 != payload:
            variants.append({"payload": encoded2, "technique": "unicode_escape"})
        return variants

    def _json_mutations(self, payload: str) -> List[Dict]:
        variants = []
        # JSON string escape
        escaped = json.dumps(payload)[1:-1]
        if escaped != payload:
            variants.append({"payload": escaped, "technique": "json_escape"})
        # JSON unicode escape all non-ASCII
        json_uni = ""
        for ch in payload:
            if ord(ch) > 127 or ch in ('"', '\\', '\n', '\r', '\t'):
                json_uni += f"\\u{ord(ch):04x}"
            else:
                json_uni += ch
        if json_uni != payload:
            variants.append({"payload": json_uni, "technique": "json_unicode"})
        # JSON wrapped in object
        variants.append({"payload": json.dumps({"q": payload}), "technique": "json_wrap_object"})
        variants.append({"payload": json.dumps([payload]), "technique": "json_wrap_array"})
        return variants

    def _json_unicode_mutations(self, payload: str) -> List[Dict]:
        variants = []
        uni = ""
        for ch in payload:
            uni += f"\\u{ord(ch):04x}"
        if uni != payload:
            variants.append({"payload": uni, "technique": "json_unicode_all"})
        uni_surrogate = ""
        for ch in payload:
            cp = ord(ch)
            if cp < 0x10000:
                uni_surrogate += f"\\u{cp:04x}"
            else:
                cp -= 0x10000
                hi = 0xD800 | (cp >> 10)
                lo = 0xDC00 | (cp & 0x3FF)
                uni_surrogate += f"\\u{hi:04x}\\u{lo:04x}"
        if uni_surrogate != payload:
            variants.append({"payload": uni_surrogate, "technique": "json_surrogate_pair"})
        return variants

    def _multipart_mutations(self, payload: str) -> List[Dict]:
        variants = []
        boundary = f"----WebKitFormBoundary{random.randint(100000, 999999)}"
        multipart = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="input"\r\n\r\n'
            f"{payload}\r\n"
            f"--{boundary}--\r\n"
        )
        variants.append({"payload": multipart, "technique": "multipart_form"})
        # Multipart with filename
        multipart_file = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="payload.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"{payload}\r\n"
            f"--{boundary}--\r\n"
        )
        variants.append({"payload": multipart_file, "technique": "multipart_file_upload"})
        return variants

    def _chunked_mutations(self, payload: str) -> List[Dict]:
        variants = []
        # Simulate chunked transfer encoding body
        chunks = []
        for i in range(0, len(payload), 4):
            chunk = payload[i:i+4]
            chunks.append(f"{len(chunk):x}\r\n{chunk}\r\n")
        chunks.append("0\r\n\r\n")
        chunked = "".join(chunks)
        variants.append({"payload": chunked, "technique": "chunked_encoding"})
        # Chunked with trailing headers
        chunked_ext = (
            f"{len(payload):x}\r\n"
            f"{payload}\r\n"
            f"0\r\n"
            f"X-Hint: payload\r\n\r\n"
        )
        variants.append({"payload": chunked_ext, "technique": "chunked_trailer"})
        return variants

    def _graphql_mutations(self, payload: str) -> List[Dict]:
        variants = []
        # Wrap as GraphQL query variable
        variants.append({
            "payload": json.dumps({"query": f"query {{ test(input: \"{payload}\") {{ result }} }}"}),
            "technique": "graphql_query",
        })
        variants.append({
            "payload": json.dumps({"variables": {"input": payload}, "query": "query($input: String!) { test(input: $input) { result } }"}),
            "technique": "graphql_variables",
        })
        # GraphQL introspection
        variants.append({
            "payload": json.dumps({"query": "query { __typename }", "input": payload}),
            "technique": "graphql_introspect",
        })
        return variants

    def _websocket_mutations(self, payload: str) -> List[Dict]:
        variants = []
        payload_bytes = payload.encode("utf-8", errors="ignore")
        # WebSocket text frame (simulated)
        variants.append({
            "payload": f"\x81{chr(len(payload_bytes))}{payload}",
            "technique": "websocket_text_frame",
        })
        # WebSocket masked frame
        mask = bytes([random.randint(0, 255) for _ in range(4)])
        masked = bytes([payload_bytes[i] ^ mask[i % 4] for i in range(len(payload_bytes))])
        variants.append({
            "payload": f"\x81{chr(0x80 | len(payload_bytes))}{mask.decode('latin-1')}{masked.decode('latin-1')}",
            "technique": "websocket_masked_frame",
        })
        # JSON over WebSocket
        variants.append({
            "payload": json.dumps({"type": "message", "data": payload}),
            "technique": "websocket_json",
        })
        return variants

    def _sql_case_mutations(self, payload: str) -> List[Dict]:
        variants = []
        sql_keywords = ["select", "from", "where", "union", "insert", "update",
                        "delete", "drop", "and", "or", "order", "by", "group",
                        "having", "into", "values", "set", "alter", "create"]
        # Random case mutation
        mutated = payload
        for kw in sql_keywords:
            if kw in mutated.lower():
                replacement = random.choice([kw.upper(), kw.capitalize(), kw.lower()])
                mutated = re.sub(kw, replacement, mutated, flags=re.IGNORECASE)
        if mutated != payload:
            variants.append({"payload": mutated, "technique": "sql_case_mutation"})
        # All uppercase
        upper = payload.upper()
        if upper != payload:
            variants.append({"payload": upper, "technique": "sql_upper"})
        # All lowercase
        lower = payload.lower()
        if lower != payload:
            variants.append({"payload": lower, "technique": "sql_lower"})
        return variants

    def _whitespace_injections(self, payload: str) -> List[Dict]:
        variants = []
        if " " in payload:
            variants.append({"payload": payload.replace(" ", "\t"), "technique": "tab_whitespace"})
            variants.append({"payload": payload.replace(" ", "\r\n"), "technique": "crlf_whitespace"})
            variants.append({"payload": payload.replace(" ", "%09"), "technique": "url_tab"})
            variants.append({"payload": payload.replace(" ", "%0a"), "technique": "url_newline"})
            variants.append({"payload": payload.replace(" ", "%0d%0a"), "technique": "url_crlf"})
        return variants

    def _unicode_escape_all(self, payload: str) -> List[Dict]:
        variants = []
        uni = "".join(f"\\u{ord(c):04x}" for c in payload)
        if uni != payload:
            variants.append({"payload": uni, "technique": "unicode_escape_all"})
        uni_upper = "".join(f"\\u{ord(c):04X}" for c in payload)
        variants.append({"payload": uni_upper, "technique": "unicode_escape_upper"})
        return variants

    def _utf7_mutations(self, payload: str) -> List[Dict]:
        variants = []
        try:
            utf7 = payload.encode("utf-7").decode("ascii")
            if utf7 != payload:
                variants.append({"payload": utf7, "technique": "utf7"})
        except Exception:
            pass
        return variants

    def _hex_encode_all(self, payload: str) -> List[Dict]:
        variants = []
        hex_enc = "".join(f"\\x{ord(c):02x}" for c in payload)
        if hex_enc != payload:
            variants.append({"payload": hex_enc, "technique": "hex_escape_all"})
        hex_upper = "".join(f"\\x{ord(c):02X}" for c in payload)
        variants.append({"payload": hex_upper, "technique": "hex_escape_upper"})
        return variants

    def _waf_evasion_mutations(self, payload: str) -> List[Dict]:
        variants = []
        if "/" in payload:
            variants.append({"payload": payload.replace("/", "//"), "technique": "path_double_slash"})
            variants.append({"payload": payload.replace("/", "/./"), "technique": "path_dot_slash"})
            variants.append({"payload": payload.replace("/", "%2f"), "technique": "path_url_slash"})
            variants.append({"payload": payload.replace("/", "%252f"), "technique": "path_double_url_slash"})
        if "=" in payload:
            variants.append({"payload": payload.replace("=", "!="), "technique": "sql_not_equal"})
        if "'" in payload:
            variants.append({"payload": payload.replace("'", "%27"), "technique": "url_quote"})
            variants.append({"payload": payload.replace("'", "&#39;"), "technique": "html_quote"})
        return variants

    def _category_specific(self, payload: str, category: str) -> List[Dict]:
        variants = []
        if category == "SQLI":
            variants.append({"payload": payload.replace(" ", "/**/"), "technique": "sql_comment_ws"})
            variants.append({"payload": payload.replace("=", ">"), "technique": "sql_gt"})
            variants.append({"payload": payload.replace("=", "LIKE"), "technique": "sql_like"})
            variants.append({"payload": f"/*!{payload}*/", "technique": "sql_mysql_comment"})
            if "'" in payload:
                variants.append({"payload": payload.replace("'", "\\'"), "technique": "sql_backslash_escape"})
        elif category == "XSS":
            variants.append({"payload": f"<script>{payload}</script>", "technique": "xss_script_wrap"})
            variants.append({"payload": f'<img src=x onerror="{payload}">', "technique": "xss_img_onerror"})
            variants.append({"payload": f"<svg/onload={payload}>", "technique": "xss_svg_onload"})
            variants.append({"payload": f"<body onload={payload}>", "technique": "xss_body_onload"})
            variants.append({"payload": f"<details open ontoggle={payload}>", "technique": "xss_details_ontoggle"})
        elif category == "LFI":
            variants.append({"payload": payload.replace("../", "....//....//"), "technique": "lfi_double_dot"})
            variants.append({"payload": payload.replace("../", "..\\/..\\/"), "technique": "lfi_backslash"})
            variants.append({"payload": payload.replace("../", "..%252f..%252f"), "technique": "lfi_double_url"})
            variants.append({"payload": payload.replace("../", "..\\/..\\/"), "technique": "lfi_backslash"})
        elif category in ("SSTI", "TEMPLATE_INJECTION"):
            variants.append({"payload": payload.replace("{{", "{%"), "technique": "ssti_jinja_block"})
            variants.append({"payload": payload, "technique": "ssti_original"})
        return variants
