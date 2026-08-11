# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Full Toolchain API routes.

Exposes the toolchain application service: tool catalog, knowledge contracts,
capabilities, health, versions, requirements, provenance, recommendations,
chains and guarded executions. Handlers resolve the
:class:`~hunterx.application.toolchain.ToolchainService` from the shared
dependency container.
"""

from __future__ import annotations

from typing import Any

from hunterx.api.router import ApiRouter
from hunterx.application.toolchain import ToolchainService


def build_tools_router() -> ApiRouter:
    """Build the ``/tools`` route group for the full toolchain."""
    router = ApiRouter(prefix="/tools")

    from hunterx.api.deps import get_container

    def _service() -> ToolchainService:
        return get_container().resolve(ToolchainService)

    def _not_found(detail: str) -> Any:
        from fastapi import HTTPException

        return HTTPException(status_code=404, detail=detail)

    # -- catalog -------------------------------------------------------------

    @router.get("", summary="List registered tools")
    def list_tools() -> list[dict[str, Any]]:
        return _service().list_tools()

    @router.get("/capabilities", summary="List the capability catalog")
    def capabilities(term: str = "", limit: int = 50) -> list[dict[str, Any]]:
        return _service().capabilities(term=term, limit=limit)

    @router.get("/contracts", summary="List consolidated machine-readable tool contracts")
    def contracts() -> list[dict[str, Any]]:
        return _service().contracts()

    @router.get("/{tool_id}", summary="Show a tool knowledge contract")
    def show_tool(tool_id: str) -> dict[str, Any]:
        try:
            return _service().show_tool(tool_id)
        except Exception as exc:
            from hunterx.domain.exceptions import ToolNotFoundError

            if isinstance(exc, ToolNotFoundError):
                raise _not_found(str(exc)) from exc
            raise

    @router.get("/{tool_id}/contract", summary="Show a tool's consolidated machine-readable contract")
    def tool_contract(tool_id: str) -> dict[str, Any]:
        try:
            return _service().contract(tool_id)
        except Exception as exc:
            from hunterx.domain.exceptions import ToolNotFoundError

            if isinstance(exc, ToolNotFoundError):
                raise _not_found(str(exc)) from exc
            raise

    @router.get("/{tool_id}/capabilities", summary="Show a tool's capabilities")
    def tool_capabilities(tool_id: str) -> list[str]:
        try:
            return _service().tool_capabilities(tool_id)
        except Exception as exc:
            from hunterx.domain.exceptions import ToolNotFoundError

            if isinstance(exc, ToolNotFoundError):
                raise _not_found(str(exc)) from exc
            raise

    @router.get("/{tool_id}/health", summary="Show a tool's health")
    def tool_health(tool_id: str) -> dict[str, Any]:
        try:
            return _service().health(tool_id)
        except Exception as exc:
            from hunterx.domain.exceptions import ToolNotFoundError

            if isinstance(exc, ToolNotFoundError):
                raise _not_found(str(exc)) from exc
            raise

    @router.get("/{tool_id}/versions", summary="Show a tool's version facts")
    def tool_versions(tool_id: str) -> dict[str, Any]:
        try:
            return _service().versions(tool_id)
        except Exception as exc:
            from hunterx.domain.exceptions import ToolNotFoundError

            if isinstance(exc, ToolNotFoundError):
                raise _not_found(str(exc)) from exc
            raise

    @router.get("/{tool_id}/requirements", summary="Show a tool's execution requirements")
    def tool_requirements(tool_id: str) -> dict[str, Any]:
        try:
            return _service().requirements(tool_id)
        except Exception as exc:
            from hunterx.domain.exceptions import ToolNotFoundError

            if isinstance(exc, ToolNotFoundError):
                raise _not_found(str(exc)) from exc
            raise

    @router.get("/{tool_id}/provenance", summary="Show a tool's parser/normalizer/adapter provenance")
    def tool_provenance(tool_id: str) -> dict[str, Any]:
        try:
            return _service().provenance(tool_id)
        except Exception as exc:
            from hunterx.domain.exceptions import ToolNotFoundError

            if isinstance(exc, ToolNotFoundError):
                raise _not_found(str(exc)) from exc
            raise

    # -- decision support ----------------------------------------------------

    @router.get("/recommend/{capability_id}", summary="Recommend tools for a capability")
    def recommend(capability_id: str) -> list[dict[str, Any]]:
        return _service().recommend(capability_id)

    @router.post("/chain", summary="Plan a dependency-aware tool chain")
    def plan_chain(payload: dict[str, Any]) -> dict[str, Any]:
        capabilities = payload.get("capabilities", [])
        if not isinstance(capabilities, list):
            raise _not_found("capabilities must be a list")
        return _service().chain(
            str(payload.get("objective", "")),
            [str(item) for item in capabilities],
            mission_id=str(payload.get("mission_id", "")),
            scope=str(payload.get("scope", "")),
        )

    @router.post("/chain/execute", summary="Plan and execute an end-to-end tool chain")
    def execute_chain(payload: dict[str, Any]) -> dict[str, Any]:
        capabilities = payload.get("capabilities", [])
        if not isinstance(capabilities, list):
            raise _not_found("capabilities must be a list")
        return _service().execute_chain(
            str(payload.get("objective", "")),
            [str(item) for item in capabilities],
            str(payload.get("target", "")),
            mission_id=str(payload.get("mission_id", "")),
            scope=str(payload.get("scope", "")),
            target_type=str(payload.get("target_type", "")),
            parameters=payload.get("parameters") if isinstance(payload.get("parameters"), dict) else {},
            timeout=float(payload.get("timeout", 0.0) or 0.0),
            allow_fallback=bool(payload.get("allow_fallback", True)),
        )

    # -- execution -----------------------------------------------------------

    @router.post("/execute", summary="Execute a tool against a target (structured)")
    def execute(payload: dict[str, Any]) -> dict[str, Any]:
        return _service().execute(
            str(payload.get("tool_id", "")),
            str(payload.get("target", "")),
            parameters=payload.get("parameters") if isinstance(payload.get("parameters"), dict) else {},
            mission_id=str(payload.get("mission_id", "")),
            scope=str(payload.get("scope", "")),
            target_type=str(payload.get("target_type", "")),
            profile=str(payload.get("profile", "")),
            timeout=float(payload.get("timeout", 0.0) or 0.0),
        )

    @router.get("/executions/{execution_id}/status", summary="Show an execution's status")
    def execution_status(execution_id: str) -> dict[str, Any]:
        try:
            return _service().execution_status(execution_id)
        except Exception as exc:
            from hunterx.domain.exceptions import ToolExecutionError

            if isinstance(exc, ToolExecutionError):
                raise _not_found(str(exc)) from exc
            raise

    @router.get("/executions/{execution_id}/output", summary="Show an execution's output")
    def execution_output(execution_id: str) -> dict[str, Any]:
        try:
            return _service().execution_output(execution_id)
        except Exception as exc:
            from hunterx.domain.exceptions import ToolExecutionError

            if isinstance(exc, ToolExecutionError):
                raise _not_found(str(exc)) from exc
            raise

    @router.get("/executions/{execution_id}/result", summary="Inspect a full execution result")
    def execution_result(execution_id: str) -> dict[str, Any]:
        try:
            return _service().inspect_result(execution_id)
        except Exception as exc:
            from hunterx.domain.exceptions import ToolExecutionError

            if isinstance(exc, ToolExecutionError):
                raise _not_found(str(exc)) from exc
            raise

    # -- offline replay ------------------------------------------------------

    @router.post("/parse", summary="Parse saved tool output offline")
    def parse(payload: dict[str, Any]) -> dict[str, Any]:
        return _service().parse(str(payload.get("tool_id", "")), str(payload.get("raw", "")), target=str(payload.get("target", "")))

    @router.post("/normalize", summary="Normalize parsed records offline")
    def normalize(payload: dict[str, Any]) -> dict[str, Any]:
        records = payload.get("records", [])
        if not isinstance(records, list):
            raise _not_found("records must be a list")
        return _service().normalize(str(payload.get("tool_id", "")), [item for item in records if isinstance(item, dict)])

    return router
