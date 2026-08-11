# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-process API specification parsers.

Parse OpenAPI 2/3/3.1, GraphQL SDL, WebSocket, WSDL/SOAP and Postman
collections into canonical API intelligence observations. All parsing is
in-process and deterministic: YAML via ``pyyaml``, XML via ``xml.etree``, no
subprocess and no new parser dependency.
"""

from __future__ import annotations

from hunterx.domain.api.parsers.graphql import GraphQLParser, GraphQLParseResult
from hunterx.domain.api.parsers.hints import HintsParser, HintsParseResult
from hunterx.domain.api.parsers.openapi import OpenAPIParser, OpenAPIParseResult
from hunterx.domain.api.parsers.postman import PostmanParser, PostmanParseResult
from hunterx.domain.api.parsers.soap import SoapParser, SoapParseResult
from hunterx.domain.api.parsers.websocket import WebSocketParser, WebSocketParseResult

__all__ = [
    "GraphQLParseResult",
    "GraphQLParser",
    "HintsParseResult",
    "HintsParser",
    "OpenAPIParseResult",
    "OpenAPIParser",
    "PostmanParseResult",
    "PostmanParser",
    "SoapParseResult",
    "SoapParser",
    "WebSocketParseResult",
    "WebSocketParser",
]
