# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Web-layer Target Intelligence Database entities.

Technologies, HTTP surface, application structure and content entities. These
describe what an application exposes over HTTP(S) and power fingerprinting,
content discovery and API mapping in future capability waves.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities.tidb._base import TidbEntity


@dataclass(slots=True)
class Technology(TidbEntity):
    """A software technology detected on a service or web application.

    Attributes:
        name: technology name.
        category: web-server|framework|cms|waf|language|... .
        software_version: detected version.
        cpe: CPE 2.3 identifier when known.
        service_id: owning service when detected at network layer.
        url_id: owning URL when detected at web layer.
        confidence: detection confidence in ``[0, 1]``.
        detected_by: tool/plugin that identified it.

    """

    name: str
    category: str = "other"
    software_version: str | None = None
    cpe: str | None = None
    service_id: str | None = None
    url_id: str | None = None
    confidence: float = 1.0
    detected_by: str | None = None


@dataclass(slots=True)
class OperatingSystem(TidbEntity):
    """A detected operating system.

    Attributes:
        hostname_id: owning hostname.
        name: OS name (e.g. ``ubuntu``, ``windows-server``).
        software_version: OS version.
        kernel: kernel release string.
        cpe: CPE identifier when known.
        confidence: detection confidence in ``[0, 1]``.

    """

    hostname_id: str
    name: str
    software_version: str | None = None
    kernel: str | None = None
    cpe: str | None = None
    confidence: float = 1.0


@dataclass(slots=True)
class CMS(TidbEntity):
    """A content-management system.

    Attributes:
        name: CMS name (e.g. ``wordpress``, ``drupal``).
        software_version: detected version.
        url_id: owning web application URL.
        plugins: detected plugin name/version list.
        confidence: detection confidence in ``[0, 1]``.

    """

    name: str
    software_version: str | None = None
    url_id: str | None = None
    plugins: list[dict[str, object]] = field(default_factory=list)
    confidence: float = 1.0


@dataclass(slots=True)
class Framework(TidbEntity):
    """A web application framework.

    Attributes:
        name: framework name.
        software_version: detected version.
        language: primary language (``python``, ``javascript``, ...).
        url_id: owning web application URL.
        confidence: detection confidence in ``[0, 1]``.

    """

    name: str
    software_version: str | None = None
    language: str | None = None
    url_id: str | None = None
    confidence: float = 1.0


@dataclass(slots=True)
class ProgrammingLanguage(TidbEntity):
    """A detected programming language.

    Attributes:
        name: language name.
        software_version: detected version.
        url_id: owning web application URL when detected from content.

    """

    name: str
    software_version: str | None = None
    url_id: str | None = None


@dataclass(slots=True)
class WebServer(TidbEntity):
    """A web server software product.

    Attributes:
        name: server name (e.g. ``nginx``, ``apache``).
        software_version: detected version.
        software: free-form software string from the ``Server`` header.
        url_id: owning web application URL.
        confidence: detection confidence in ``[0, 1]``.

    """

    name: str
    software_version: str | None = None
    software: str | None = None
    url_id: str | None = None
    confidence: float = 1.0


@dataclass(slots=True)
class Header(TidbEntity):
    """An HTTP response/request header observed on an asset.

    Attributes:
        asset_id: owning asset (URL, endpoint or hostname).
        name: header name.
        value: header value.
        direction: ``request`` | ``response``.
        discovered_by: tool/step that captured it.

    """

    asset_id: str
    name: str
    value: str = ""
    direction: str = "response"
    discovered_by: str | None = None


@dataclass(slots=True)
class Cookie(TidbEntity):
    """An HTTP cookie observed on a web application.

    Attributes:
        asset_id: owning URL or endpoint.
        name: cookie name.
        value: cookie value (may be masked).
        domain: cookie scope domain.
        path: cookie path.
        secure: ``Secure`` flag.
        httponly: ``HttpOnly`` flag.
        samesite: SameSite attribute value.
        expires: expiry timestamp.

    """

    asset_id: str
    name: str
    value: str | None = None
    domain: str | None = None
    path: str | None = None
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    expires: str | None = None


@dataclass(slots=True)
class URL(TidbEntity):
    """A normalized URL discovered within scope.

    Attributes:
        url: normalized absolute URL.
        scheme: URL scheme.
        host: URL host.
        path: URL path.
        query: query string.
        target_id: owning target.
        is_internal: whether the URL is internal to the target.
        status_code: last observed HTTP status.
        content_type: last observed content type.
        discovered_by: tool/step that discovered it.

    """

    url: str
    scheme: str = "https"
    host: str = ""
    path: str = ""
    query: str | None = None
    target_id: str | None = None
    is_internal: bool = False
    status_code: int | None = None
    content_type: str | None = None
    discovered_by: str | None = None


@dataclass(slots=True)
class Endpoint(TidbEntity):
    """An HTTP endpoint (method + path) under a URL.

    Attributes:
        url_id: owning URL.
        method: HTTP method (GET/POST/...).
        path: endpoint path.
        auth_required: whether authentication is required.
        content_type: response content type.
        response_meta: map of response metadata (status, headers, size).
        discovered_by: tool/step that discovered it.

    """

    url_id: str
    method: str = "GET"
    path: str = ""
    auth_required: bool = False
    content_type: str | None = None
    response_meta: dict[str, object] = field(default_factory=dict)
    discovered_by: str | None = None


@dataclass(slots=True)
class Route(TidbEntity):
    """A routing rule mapping a pattern to an endpoint/handler.

    Attributes:
        endpoint_id: owning endpoint.
        pattern: route pattern (may contain parameters).
        handler: handler/controller reference.
        order: route evaluation order.

    """

    endpoint_id: str
    pattern: str = ""
    handler: str | None = None
    order: int = 0


@dataclass(slots=True)
class Parameter(TidbEntity):
    """A request parameter of an endpoint.

    Attributes:
        endpoint_id: owning endpoint.
        name: parameter name.
        location: query|body|path|cookie|header.
        value: observed value (masked when sensitive).
        parameter_type: string|int|file|json|xml|... .
        is_interesting: session/id/file/upload-like parameter.

    """

    endpoint_id: str
    name: str
    location: str = "query"
    value: str | None = None
    parameter_type: str = "string"
    is_interesting: bool = False


@dataclass(slots=True)
class Form(TidbEntity):
    """An HTML form discovered on a URL.

    Attributes:
        url_id: owning URL.
        action: form action target.
        method: form submit method.
        fields: list of field maps ``{name, type, required, value}``.
        is_authenticated: whether the form requires a session.

    """

    url_id: str
    action: str = ""
    method: str = "GET"
    fields: list[dict[str, object]] = field(default_factory=list)
    is_authenticated: bool = False


@dataclass(slots=True)
class Directory(TidbEntity):
    """A discovered web directory.

    Attributes:
        target_id: owning target.
        path: directory path.
        parent_id: parent directory (self-referencing hierarchy).
        status_code: last observed status.
        title: page title when present.
        is_auth_required: whether the directory requires authentication.
        discovered_by: tool/step that discovered it.

    """

    target_id: str
    path: str
    parent_id: str | None = None
    status_code: int | None = None
    title: str | None = None
    is_auth_required: bool = False
    discovered_by: str | None = None


@dataclass(slots=True)
class File(TidbEntity):
    """A discovered file (static asset, download, backup, ...).

    Attributes:
        directory_id: owning directory (when known).
        path: file path.
        name: file name.
        extension: file extension.
        size: size in bytes.
        status_code: last observed status.
        content_type: observed content type.
        checksum: content checksum when computed.

    """

    directory_id: str | None = None
    path: str = ""
    name: str | None = None
    extension: str | None = None
    size: int | None = None
    status_code: int | None = None
    content_type: str | None = None
    checksum: str | None = None


@dataclass(slots=True)
class JavaScript(TidbEntity):
    """A JavaScript resource observed on a web application.

    Attributes:
        url_id: owning URL where the script was referenced.
        src: script source URL.
        content_hash: SHA-256 of the script content.
        size: size in bytes.
        rendered: whether the script was executed/rendered.

    """

    url_id: str
    src: str = ""
    content_hash: str | None = None
    size: int | None = None
    rendered: bool = False


@dataclass(slots=True)
class SensitiveFile(TidbEntity):
    """A file classified as sensitive.

    Attributes:
        file_id: owning file.
        category: backup|config|source-map|credentials|database-dump|... .
        content_hash: content hash when computed.
        discovered_by: tool/step that discovered it.

    """

    file_id: str
    category: str = "other"
    content_hash: str | None = None
    discovered_by: str | None = None


@dataclass(slots=True)
class Screenshot(TidbEntity):
    """A screenshot of a web resource.

    Attributes:
        evidence_id: owning evidence record.
        url: captured URL.
        viewport: viewport dimensions ``{width, height}``.
        full_page: whether the capture is full-page.
        dimensions: captured image dimensions ``{width, height}``.
        ocr_text: optional OCR text.
        file_ref: object-store reference.

    """

    evidence_id: str
    url: str = ""
    viewport: str | None = None
    full_page: bool = False
    dimensions: str | None = None
    ocr_text: str | None = None
    file_ref: str | None = None
