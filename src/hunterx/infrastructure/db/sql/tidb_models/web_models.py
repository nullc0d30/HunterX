# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""ORM models for TIDB web-layer entities (technologies, HTTP surface, content)."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from hunterx.infrastructure.db.sql.tidb_models._base import Base, TidbModelMixin


class TechnologyModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.Technology`."""

    __tablename__ = "tidb_technologies"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="other", index=True)
    software_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(255), nullable=True)
    service_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_services.id"), nullable=True, index=True
    )
    url_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_urls.id"), nullable=True, index=True
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    detected_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class OperatingSystemModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.OperatingSystem`."""

    __tablename__ = "tidb_operating_systems"

    hostname_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_hostnames.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    software_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    kernel: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(255), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)


class CMSModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.CMS`."""

    __tablename__ = "tidb_cms"

    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    software_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    url_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_urls.id"), nullable=True, index=True
    )
    plugins: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)


class FrameworkModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.Framework`."""

    __tablename__ = "tidb_frameworks"

    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    software_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    language: Mapped[str | None] = mapped_column(String(64), nullable=True)
    url_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_urls.id"), nullable=True, index=True
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)


class ProgrammingLanguageModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.ProgrammingLanguage`."""

    __tablename__ = "tidb_programming_languages"

    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    software_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    url_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_urls.id"), nullable=True, index=True
    )


class WebServerModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.WebServer`."""

    __tablename__ = "tidb_web_servers"

    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    software_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    software: Mapped[str | None] = mapped_column(String(255), nullable=True)
    url_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_urls.id"), nullable=True, index=True
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)


class HeaderModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.Header`."""

    __tablename__ = "tidb_headers"

    asset_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    direction: Mapped[str] = mapped_column(String(16), nullable=False, default="response")
    discovered_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class CookieModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.Cookie`."""

    __tablename__ = "tidb_cookies"

    asset_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    secure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    httponly: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    samesite: Mapped[str | None] = mapped_column(String(32), nullable=True)
    expires: Mapped[str | None] = mapped_column(String(32), nullable=True)


class URLModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.URL`."""

    __tablename__ = "tidb_urls"

    url: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    scheme: Mapped[str] = mapped_column(String(16), nullable=False, default="https")
    host: Mapped[str] = mapped_column(String(255), nullable=False, default="", index=True)
    path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    query: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(26), nullable=True, index=True)
    is_internal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    discovered_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class EndpointModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.Endpoint`."""

    __tablename__ = "tidb_endpoints"

    url_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_urls.id"), nullable=False, index=True
    )
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    auth_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    response_meta: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    discovered_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        UniqueConstraint("url_id", "method", "path", name="uq_tidb_endpoints_url_method_path"),
    )


class RouteModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.Route`."""

    __tablename__ = "tidb_routes"

    endpoint_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_endpoints.id"), nullable=False, index=True
    )
    pattern: Mapped[str] = mapped_column(Text, nullable=False, default="")
    handler: Mapped[str | None] = mapped_column(String(255), nullable=True)
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ParameterModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.Parameter`."""

    __tablename__ = "tidb_parameters"

    endpoint_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_endpoints.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    location: Mapped[str] = mapped_column(String(16), nullable=False, default="query")
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    parameter_type: Mapped[str] = mapped_column(String(32), nullable=False, default="string")
    is_interesting: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    __table_args__ = (
        UniqueConstraint("endpoint_id", "name", "location", name="uq_tidb_parameters_endpoint_name_loc"),
    )


class FormModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.Form`."""

    __tablename__ = "tidb_forms"

    url_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_urls.id"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(Text, nullable=False, default="")
    method: Mapped[str] = mapped_column(String(16), nullable=False, default="GET")
    fields: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False, default=list)
    is_authenticated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class DirectoryModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.Directory`."""

    __tablename__ = "tidb_directories"

    target_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    path: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    parent_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_directories.id"), nullable=True
    )
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_auth_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    discovered_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        UniqueConstraint("target_id", "path", name="uq_tidb_directories_target_path"),
    )


class FileModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.File`."""

    __tablename__ = "tidb_files"

    directory_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("tidb_directories.id"), nullable=True, index=True
    )
    path: Mapped[str] = mapped_column(Text, nullable=False, default="", index=True)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    extension: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)


class JavaScriptModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.JavaScript`."""

    __tablename__ = "tidb_javascript"

    url_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_urls.id"), nullable=False, index=True
    )
    src: Mapped[str] = mapped_column(Text, nullable=False, default="")
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rendered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class SensitiveFileModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.SensitiveFile`."""

    __tablename__ = "tidb_sensitive_files"

    file_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("tidb_files.id"), nullable=False, index=True
    )
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="other", index=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    discovered_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class ScreenshotModel(TidbModelMixin, Base):
    """ORM view of :class:`~hunterx.domain.entities.tidb.web.Screenshot`."""

    __tablename__ = "tidb_screenshots"

    evidence_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    viewport: Mapped[str | None] = mapped_column(String(64), nullable=True)
    full_page: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    dimensions: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ocr_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
