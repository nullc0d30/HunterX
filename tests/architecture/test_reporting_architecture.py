# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Architecture tests for the professional reporting capability.

Enforces domain purity, application/ports separation, reporting adapter and
exporter separation, template separation, evidence immutability, dependency
direction, no direct tool execution from reporting and no AI bypass around QA.
"""

from __future__ import annotations

import inspect

from hunterx.application.professional_reporting import ProfessionalReportingService
from hunterx.domain.ports.reporting import ReportExporterPort
from hunterx.domain.reporting import models as reporting_models
from hunterx.domain.reporting.evidence import EvidenceBundleBuilder
from hunterx.reporting.exporter import ReportExporter


def test_application_depends_on_port_not_renderers() -> None:
    """The application service depends on the exporter port, never on the
    concrete reporting renderers."""
    signature = inspect.signature(ProfessionalReportingService.__init__)
    annotation = str(signature.parameters["exporter"].annotation)
    assert "ReportExporterPort" in annotation
    import hunterx.application.professional_reporting as module

    source = inspect.getsource(module)
    assert "from hunterx.reporting" not in source
    assert "import report_renderers" not in source


def test_exporter_adapter_implements_port() -> None:
    """The reporting adapter implements the domain port contract."""
    assert issubclass(ReportExporter, ReportExporterPort)


def test_domain_reporting_is_pure() -> None:
    """The domain reporting package imports no infrastructure or application
    modules."""
    from hunterx.domain.reporting import classification, lifecycle, quality, severity

    for module in (classification, lifecycle, quality, severity, reporting_models):
        for name, value in inspect.getmembers(module, inspect.ismodule):
            if name.startswith("hunterx"):
                assert value.__name__.startswith("hunterx.domain."), (
                    f"{module.__name__} imports {value.__name__}"
                )


def test_evidence_bundles_are_immutable() -> None:
    """Evidence bundles are frozen/immutable."""
    import dataclasses

    from hunterx.domain.reporting.evidence import ArtifactInput

    builder = EvidenceBundleBuilder()
    bundle = builder.build(
        finding_id="f1",
        artifacts=(ArtifactInput(kind="observation", content="x", source="s"),),
    )
    assert dataclasses.is_dataclass(bundle)
    assert bundle.__dataclass_params__.frozen is True


def test_no_direct_tool_execution_from_reporting() -> None:
    """Reporting code never executes tools."""
    import hunterx.application.professional_reporting as app_module
    import hunterx.reporting as reporting_pkg

    for module in (reporting_pkg, app_module):
        source = inspect.getsource(module)
        assert "subprocess" not in source
        assert "os.system" not in source


def test_no_ai_bypass_around_qa() -> None:
    """AI claims are verified through the claim checker before the report can
    become submission-ready; the service never trusts AI output directly."""
    service_constructor = inspect.signature(ProfessionalReportingService.__init__)
    assert "ai" not in service_constructor.parameters
    import hunterx.application.professional_reporting as module

    source = inspect.getsource(module)
    assert "ClaimVerifier" in source
    assert "finalize_submission_ready" in source


def test_report_document_models_are_storage_agnostic() -> None:
    """Report domain models carry to_dict/from_dict and no SQL imports."""
    import hunterx.domain.reporting.models as models

    document = models.ReportDocument(title="x")
    payload = document.to_dict()
    rebuilt = models.ReportDocument.from_dict(payload)
    assert rebuilt.title == "x"
    source = inspect.getsource(models)
    assert "sqlalchemy" not in source
