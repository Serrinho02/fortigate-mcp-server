"""
change.* MCP tools -- apply/rollback/list_pending/history for changes
proposed by the mutating resource tools (create_firewall_policy,
update_static_route, delete_virtual_ip, ...), which preview instead of
executing immediately as of Phase 3 (see architecture plan §9: every mode
requires preview+apply, with no single-shot fast path even in FULL).
"""
from __future__ import annotations

from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ...errors import (
    ChangeAlreadyResolvedError,
    ChangeDriftError,
    ChangeExpiredError,
    ChangeNotFoundError,
    ModeViolationError,
    RollbackNotPossibleError,
)
from ...infra.models_orm import ChangeRecord
from ...services.change_service import ChangeService


def _record_to_dict(record: ChangeRecord) -> dict:
    return {
        "change_id": record.change_id,
        "device_id": record.device_id,
        "vdom": record.vdom,
        "resource_type": record.resource_type,
        "resource_id": record.resource_id,
        "operation": record.operation,
        "status": record.status,
        "mode_at_request": record.mode_at_request,
        "created_at": record.created_at.isoformat(),
        "expires_at": record.expires_at.isoformat(),
        "applied_at": record.applied_at.isoformat() if record.applied_at else None,
    }


def register_change_tools(mcp: FastMCP, change_service: ChangeService) -> None:
    @mcp.tool(
        description=(
            "Apply a previously proposed change. Every mutating tool "
            "(create_firewall_policy, update_static_route, delete_virtual_ip, "
            "...) returns a change_id instead of executing immediately -- call "
            "this to actually run it. Re-validates the current operating mode "
            "and rejects if the live state has drifted since the preview was "
            "computed (re-run the original tool to get a fresh preview)."
        )
    )
    async def change_apply(
        change_id: Annotated[str, Field(description="The change_id returned by the preview")],
    ):
        try:
            result = await change_service.apply(change_id)
        except (
            ChangeNotFoundError,
            ChangeAlreadyResolvedError,
            ChangeExpiredError,
            ChangeDriftError,
            ModeViolationError,
            ValueError,
        ) as e:
            return {"error": str(e)}
        return {
            "change_id": result.change_id,
            "operation": result.operation,
            "resource_type": result.resource_type,
            "resource_id": result.resource_id,
            "applied_at": result.applied_at.isoformat(),
            "result": result.response,
        }

    @mcp.tool(
        description=(
            "Roll back a previously applied change, restoring the resource to "
            "its pre-change state where possible. Recreating a deleted "
            "resource may get a new identifier from FortiOS; rolling back a "
            "create can only auto-delete the resource if FortiOS's response "
            "included an identifiable key (mkey) at apply time."
        )
    )
    async def change_rollback(
        change_id: Annotated[str, Field(description="The change_id to roll back")],
    ):
        try:
            result = await change_service.rollback(change_id)
        except (
            ChangeNotFoundError,
            ChangeAlreadyResolvedError,
            RollbackNotPossibleError,
            ModeViolationError,
            ValueError,
        ) as e:
            return {"error": str(e)}
        return {"change_id": result.change_id, "operation": result.operation, "note": result.note}

    @mcp.tool(
        description="List proposed changes awaiting change.apply (not yet applied, not expired)."
    )
    async def change_list_pending():
        records = await change_service.list_pending()
        return [_record_to_dict(r) for r in records]

    @mcp.tool(
        description="Show recent change history (proposed/applied/rolled_back/expired), most recent first."
    )
    async def change_history(
        limit: Annotated[
            int, Field(description="Maximum number of records to return", default=20)
        ] = 20,
    ):
        records = await change_service.history(limit=limit)
        return [_record_to_dict(r) for r in records]
