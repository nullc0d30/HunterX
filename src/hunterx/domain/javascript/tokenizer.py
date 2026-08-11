# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Safe JavaScript tokenizer.

A pure, dependency-free lexical scanner for JavaScript sources. The tokenizer
produces a flat, lossy-safe stream of tokens (strings, template literals,
identifiers, numbers, keywords, punctuation, comments) with precise line/column
locations so downstream analyzers can attach evidence locations without ever
executing or parsing the code.

Safety properties:

* no ``eval``, no AST construction, no code execution,
* strings/templates/comments are scanned to their terminator with escape
  handling, so adversarial input cannot break the scan,
* comments (line and block) and template interpolation are surfaced as tokens
  so secret/technology scanners can inspect them too.

The tokenizer is intentionally NOT a full ECMAScript parser: it is a
conservative lexer that never hangs on malformed input and always terminates
on any finite source.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class JSTokenType(StrEnum):
    """The lexical class of a :class:`JSToken`."""

    STRING = "string"
    TEMPLATE = "template"
    IDENTIFIER = "identifier"
    KEYWORD = "keyword"
    NUMBER = "number"
    PUNCTUATION = "punctuation"
    COMMENT = "comment"
    WHITESPACE = "whitespace"
    UNKNOWN = "unknown"
    EOF = "eof"


@dataclass(frozen=True, slots=True)
class JSToken:
    """A single lexical token.

    Attributes:
        token_type: :class:`JSTokenType`.
        value: the literal text of the token.
        line: 1-based line of the token start.
        column: 1-based column of the token start.
        offset: 0-based byte/char offset of the token start.
        raw: the raw source span (including quotes for strings).

    """

    token_type: JSTokenType
    value: str
    line: int = 1
    column: int = 1
    offset: int = 0
    raw: str = ""

    def location(self, file: str = "") -> str:
        """Return a ``file:line:col`` location string."""
        prefix = f"{file}:" if file else ""
        return f"{prefix}{self.line}:{self.column}"

    def is_value(self) -> bool:
        """Return ``True`` when the token can carry a scanned value."""
        return self.token_type in (JSTokenType.STRING, JSTokenType.TEMPLATE)


#: JavaScript reserved words treated as :class:`JSTokenType.KEYWORD`.
_KEYWORDS = frozenset(
    {
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "export",
        "extends",
        "false",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "let",
        "new",
        "null",
        "return",
        "super",
        "switch",
        "this",
        "throw",
        "true",
        "try",
        "typeof",
        "var",
        "void",
        "while",
        "with",
        "yield",
        "async",
        "await",
        "of",
        "static",
        "get",
        "set",
        "from",
        "as",
    }
)

_IDENTIFIER_START = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$_"
)
_IDENTIFIER_PART = _IDENTIFIER_START | set("0123456789")
_DIGITS = set("0123456789")
_HEX = _DIGITS | set("abcdefABCDEF")
_PUNCTUATION = frozenset(
    ["{", "}", "(", ")", "[", "]", ";", ",", ".", ":", "?", "!", "=", "+", "-", "*", "/", "%", "&", "|", "^", "~", "<", ">", "@", "#"]
)


class JSTokenizer:
    """Scan JavaScript source text into a token stream.

    Attributes:
        max_tokens: safety ceiling on the number of emitted tokens.

    """

    def __init__(self, *, max_tokens: int = 2_000_000) -> None:
        self.max_tokens = max_tokens

    def tokenize(self, source: str, *, file: str = "") -> list[JSToken]:
        """Tokenize ``source`` and return the token stream.

        Args:
            source: the JavaScript source text.
            file: optional file label used in evidence locations.

        Returns:
            The list of tokens, always ending with an EOF token.

        """
        tokens: list[JSToken] = []
        length = len(source)
        offset = 0
        line = 1
        column = 1

        def push(
            token_type: JSTokenType, value: str, start_line: int, start_col: int, start_offset: int
        ) -> None:
            tokens.append(
                JSToken(
                    token_type=token_type,
                    value=value,
                    line=start_line,
                    column=start_col,
                    offset=start_offset,
                    raw=source[start_offset : start_offset + len(value)],
                )
            )

        while offset < length and len(tokens) < self.max_tokens:
            char = source[offset]
            start_line, start_col, start_offset = line, column, offset

            if char in " \t\r\n\f\v":
                # whitespace run
                while offset < length and source[offset] in " \t\r\n\f\v":
                    if source[offset] == "\n":
                        line += 1
                        column = 1
                    else:
                        column += 1
                    offset += 1
                push(JSTokenType.WHITESPACE, source[start_offset:offset], start_line, start_col, start_offset)
                continue

            if char == "/" and offset + 1 < length:
                if source[offset + 1] == "/":
                    # line comment
                    offset += 2
                    column += 2
                    while offset < length and source[offset] != "\n":
                        offset += 1
                        column += 1
                    value = source[start_offset:offset]
                    push(JSTokenType.COMMENT, value, start_line, start_col, start_offset)
                    continue
                if source[offset + 1] == "*":
                    # block comment
                    offset += 2
                    column += 2
                    while offset < length:
                        if source[offset] == "*" and offset + 1 < length and source[offset + 1] == "/":
                            offset += 2
                            column += 2
                            break
                        if source[offset] == "\n":
                            line += 1
                            column = 1
                        else:
                            column += 1
                        offset += 1
                    value = source[start_offset:offset]
                    push(JSTokenType.COMMENT, value, start_line, start_col, start_offset)
                    continue

            if char in ("'", '"'):
                value, offset, line, column = _scan_string(source, offset, line, column)
                push(JSTokenType.STRING, value, start_line, start_col, start_offset)
                continue

            if char == "`":
                value, offset, line, column = _scan_template(source, offset, line, column)
                push(JSTokenType.TEMPLATE, value, start_line, start_col, start_offset)
                continue

            if char in _IDENTIFIER_START:
                offset += 1
                column += 1
                while offset < length and source[offset] in _IDENTIFIER_PART:
                    offset += 1
                    column += 1
                value = source[start_offset:offset]
                token_type = JSTokenType.KEYWORD if value in _KEYWORDS else JSTokenType.IDENTIFIER
                push(token_type, value, start_line, start_col, start_offset)
                continue

            if char in _DIGITS or (char == "." and offset + 1 < length and source[offset + 1] in _DIGITS):
                value, offset, line, column = _scan_number(source, offset, line, column)
                push(JSTokenType.NUMBER, value, start_line, start_col, start_offset)
                continue

            if char in _PUNCTUATION or char.isascii() and not char.isalnum():
                offset += 1
                column += 1
                push(JSTokenType.PUNCTUATION, char, start_line, start_col, start_offset)
                continue

            # non-ASCII (unicode identifiers, emoji, etc.): consume run as unknown
            while offset < length and source[offset].isascii() is False:
                offset += 1
                column += 1
            push(JSTokenType.UNKNOWN, source[start_offset:offset], start_line, start_col, start_offset)
            if offset == start_offset:
                # defensive: never stall on an unmapped character
                offset += 1
                column += 1

        tokens.append(
            JSToken(
                token_type=JSTokenType.EOF,
                value="",
                line=line,
                column=column,
                offset=offset,
                raw="",
            )
        )
        return tokens

    def values(self, source: str) -> list[str]:
        """Return the string/template literal values of ``source``."""
        return [
            token.value
            for token in self.tokenize(source)
            if token.is_value()
        ]

    def members(self, source: str) -> list[str]:
        """Return the identifier/member names referenced in ``source``.

        Handles dotted member chains and object shorthand keys. This is a
        lexical approximation — no scope analysis is performed.
        """
        members: list[str] = []
        for token in self.tokenize(source):
            if token.token_type is JSTokenType.IDENTIFIER:
                members.append(token.value)
        return members


def _scan_string(source: str, offset: int, line: int, column: int) -> tuple[str, int, int, int]:
    """Scan a quoted string; return ``(value, offset, line, column)``."""
    quote = source[offset]
    start = offset
    offset += 1
    column += 1
    while offset < len(source):
        char = source[offset]
        if char == "\\":
            offset += 2
            column += 2
            continue
        if char == quote:
            offset += 1
            column += 1
            return source[start + 1 : offset - 1], offset, line, column
        if char == "\n":
            line += 1
            column = 1
        else:
            column += 1
        offset += 1
    return source[start + 1 : offset], offset, line, column


def _scan_template(source: str, offset: int, line: int, column: int) -> tuple[str, int, int, int]:
    """Scan a template literal, including interpolation; return value tuple."""
    start = offset
    offset += 1
    column += 1
    while offset < len(source):
        char = source[offset]
        if char == "\\":
            offset += 2
            column += 2
            continue
        if char == "`":
            offset += 1
            column += 1
            return source[start + 1 : offset - 1], offset, line, column
        if char == "$" and offset + 1 < len(source) and source[offset + 1] == "{":
            # interpolation: skip balanced braces
            offset += 2
            column += 2
            depth = 1
            while offset < len(source) and depth:
                inner = source[offset]
                if inner == "{":
                    depth += 1
                elif inner == "}":
                    depth -= 1
                elif inner == "`":
                    # nested template
                    _value, offset, line, column = _scan_template(source, offset, line, column)
                    continue
                elif inner in ("'", '"'):
                    _value, offset, line, column = _scan_string(source, offset, line, column)
                    continue
                if inner == "\n":
                    line += 1
                    column = 1
                else:
                    column += 1
                offset += 1
            continue
        if char == "\n":
            line += 1
            column = 1
        else:
            column += 1
        offset += 1
    return source[start + 1 : offset], offset, line, column


def _scan_number(source: str, offset: int, line: int, column: int) -> tuple[str, int, int, int]:
    """Scan a numeric literal; return ``(value, offset, line, column)``."""
    start = offset
    if source[offset] == "0" and offset + 1 < len(source) and source[offset + 1] in ("x", "X"):
        offset += 2
        column += 2
        while offset < len(source) and source[offset] in _HEX:
            offset += 1
            column += 1
        return source[start:offset], offset, line, column
    seen_dot = False
    seen_exp = False
    while offset < len(source):
        char = source[offset]
        if char in _DIGITS:
            offset += 1
            column += 1
        elif char == "." and not seen_dot and not seen_exp:
            seen_dot = True
            offset += 1
            column += 1
        elif char in ("e", "E") and not seen_exp:
            seen_exp = True
            offset += 1
            column += 1
            if offset < len(source) and source[offset] in ("+", "-"):
                offset += 1
                column += 1
        else:
            break
    return source[start:offset], offset, line, column


def mask_template(value: str, *, keep: int = 40) -> str:
    """Return a truncated (masked) preview of a literal value.

    Long literals are truncated to ``keep`` characters with an ellipsis so
    evidence never carries megabytes of source.
    """
    if value is None:
        return ""
    return value if len(value) <= keep else f"{value[:keep]}..."
