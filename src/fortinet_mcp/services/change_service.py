"""
ChangeService -- the single gateway every mutating Service method passes
through (architecture plan §9). Owns mode enforcement, diff computation,
and the preview -> apply -> (optional) rollback lifecycle, persisted in
ChangeRecord/PolicySnapshot so `apply` can run later, in a possibly
different process (e.g. the HTTP transport) than the `preview` call that
proposed it -- nothing is kept only in memory.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.fortigate_mcp.core.fortigate import FortiGateManager

from ..adapters.base import FortinetProductAdapter
from ..domain.diff import compute_diff
from ..errors import (
    ChangeAlreadyResolvedError,
    ChangeDriftError,
    ChangeExpiredError,
    ChangeNotFoundError,
    RollbackNotPossibleError,
)
from ..infra.connection_manager import ConnectionManager
from ..infra.models_orm import ChangeRecord, PolicySnapshot, utcnow_naive
from . import change_dispatch
from .device_resolution import resolve_adapter
from .mode_policy import ModePolicy, OperationType

PREVIEW_TTL_SECONDS = 600  # 10 minutes, per architecture plan


def _canonical(data: Optional[dict[str, Any]]) -> Optional[str]:
    return None if data is None else json.dumps(data, sort_keys=True)


def _content_hash(canonical_json: Optional[str]) -> str:
    payload = (canonical_json or "null").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass
class ChangePreview:
    change_id: str
    operation: str
    resource_type: str
    device_id: str
    vdom: Optional[str]
    before: Optional[dict[str, Any]]
    after: Optional[dict[str, Any]]
    diff: dict[str, Any]
    expires_at: datetime


@dataclass
class ChangeApplyResult:
    change_id: str
    operation: str
    resource_type: str
    resource_id: Optional[str]
    response: Any
    applied_at: datetime


@dataclass
class ChangeRollbackResult:
    change_id: str
    operation: str
    note: str


class ChangeService:
    def __init__(
        self,
        fortigate_manager: FortiGateManager,
        session_factory: async_sessionmaker[AsyncSession],
        mode_policy: ModePolicy,
        connection_manager: Optional[ConnectionManager] = None,
    ):
        self._fortigate_manager = fortigate_manager
        self._session_factory = session_factory
        self._mode_policy = mode_policy
        self._connection_manager = connection_manager

    async def _get_adapter(self, device_id: str) -> FortinetProductAdapter:
        return await resolve_adapter(device_id, self._fortigate_manager, self._connection_manager)

    async def preview(
        self,
        *,
        device_id: str,
        vdom: Optional[str],
        resource_type: str,
        operation: OperationType,
        resource_id: Optional[str],
        proposed_data: Optional[dict[str, Any]],
    ) -> ChangePreview:
        """Raises ModeViolationError (mode forbids even previewing this
        operation) or ValueError (unknown device_id/resource_type)."""
        self._mode_policy.check(operation)

        adapter = await self._get_adapter(device_id)
        current = await change_dispatch.fetch_current(adapter, resource_type, resource_id, vdom)
        diff = compute_diff(operation.value, current, proposed_data)

        change_id = f"chg_{uuid.uuid4().hex[:12]}"
        now = utcnow_naive()
        expires_at = now + timedelta(seconds=PREVIEW_TTL_SECONDS)

        record = ChangeRecord(
            change_id=change_id,
            device_id=device_id,
            vdom=vdom,
            resource_type=resource_type,
            resource_id=resource_id,
            operation=operation.value,
            mode_at_request=self._mode_policy.mode.value,
            status="proposed",
            before_json=_canonical(current),
            after_json=_canonical(proposed_data),
            diff_json=json.dumps(diff, sort_keys=True),
            created_at=now,
            expires_at=expires_at,
        )
        async with self._session_factory() as session:
            session.add(record)
            await session.commit()

        return ChangePreview(
            change_id=change_id,
            operation=operation.value,
            resource_type=resource_type,
            device_id=device_id,
            vdom=vdom,
            before=current,
            after=proposed_data,
            diff=diff,
            expires_at=expires_at,
        )

    async def _load_record(self, session: AsyncSession, change_id: str) -> ChangeRecord:
        record = (
            await session.execute(select(ChangeRecord).where(ChangeRecord.change_id == change_id))
        ).scalar_one_or_none()
        if record is None:
            raise ChangeNotFoundError(change_id)
        return record

    async def apply(self, change_id: str) -> ChangeApplyResult:
        """Raises ChangeNotFoundError, ChangeAlreadyResolvedError,
        ChangeExpiredError, ChangeDriftError, or ModeViolationError."""
        async with self._session_factory() as session:
            record = await self._load_record(session, change_id)

            now = utcnow_naive()
            if record.status != "proposed":
                raise ChangeAlreadyResolvedError(change_id, record.status)
            if now > record.expires_at:
                record.status = "expired"
                await session.commit()
                raise ChangeExpiredError(change_id)

            self._mode_policy.check(OperationType(record.operation))

            adapter = await self._get_adapter(record.device_id)
            current_now = await change_dispatch.fetch_current(
                adapter, record.resource_type, record.resource_id, record.vdom
            )
            if _canonical(current_now) != record.before_json:
                raise ChangeDriftError(change_id)

            proposed_data = json.loads(record.after_json) if record.after_json else None
            response = await change_dispatch.execute(
                adapter,
                record.resource_type,
                record.operation,
                record.resource_id,
                proposed_data,
                record.vdom,
            )

            if record.operation == "create" and record.resource_id is None:
                new_id = change_dispatch.extract_created_resource_id(response)
                if new_id is not None:
                    record.resource_id = new_id

            record.status = "applied"
            record.applied_at = now

            session.add(
                PolicySnapshot(
                    device_id=record.device_id,
                    vdom=record.vdom,
                    resource_type=record.resource_type,
                    resource_id=record.resource_id,
                    taken_at=now,
                    content_hash=_content_hash(record.before_json),
                    content_json=record.before_json,
                    change_id=change_id,
                )
            )
            await session.commit()

            return ChangeApplyResult(
                change_id=change_id,
                operation=record.operation,
                resource_type=record.resource_type,
                resource_id=record.resource_id,
                response=response,
                applied_at=now,
            )

    async def rollback(self, change_id: str) -> ChangeRollbackResult:
        """Best-effort undo of an applied change. Raises ChangeNotFoundError,
        ChangeAlreadyResolvedError (not currently 'applied'), or
        RollbackNotPossibleError (a CREATE whose assigned id was never
        captured -- FortiOS's response didn't include `mkey`)."""
        async with self._session_factory() as session:
            record = await self._load_record(session, change_id)

            if record.status != "applied":
                raise ChangeAlreadyResolvedError(change_id, record.status)

            adapter = await self._get_adapter(record.device_id)
            before_data = json.loads(record.before_json) if record.before_json else None

            if record.operation == "create":
                if record.resource_id is None:
                    raise RollbackNotPossibleError(
                        change_id,
                        "FortiOS's create response didn't include an identifiable key "
                        "(mkey), so the created resource can't be located to delete it. "
                        "Remove it manually.",
                    )
                await change_dispatch.execute(
                    adapter, record.resource_type, "delete", record.resource_id, None, record.vdom
                )
                note = "Created resource deleted."
            elif record.operation == "update":
                await change_dispatch.execute(
                    adapter, record.resource_type, "update", record.resource_id, before_data, record.vdom
                )
                note = "Resource restored to its pre-change values."
            elif record.operation == "delete":
                await change_dispatch.execute(
                    adapter, record.resource_type, "create", None, before_data, record.vdom
                )
                note = (
                    "Resource re-created from its pre-delete state. FortiOS may assign it "
                    "a new identifier, so this is a best-effort restore, not an exact undo."
                )
            else:
                raise ValueError(f"Unknown operation '{record.operation}'")

            record.status = "rolled_back"
            await session.commit()

            return ChangeRollbackResult(change_id=change_id, operation=record.operation, note=note)

    async def list_pending(self) -> list[ChangeRecord]:
        async with self._session_factory() as session:
            now = utcnow_naive()
            result = await session.execute(
                select(ChangeRecord)
                .where(ChangeRecord.status == "proposed", ChangeRecord.expires_at > now)
                .order_by(ChangeRecord.created_at.desc())
            )
            return list(result.scalars().all())

    async def history(self, limit: int = 20) -> list[ChangeRecord]:
        async with self._session_factory() as session:
            result = await session.execute(
                select(ChangeRecord).order_by(ChangeRecord.created_at.desc()).limit(limit)
            )
            return list(result.scalars().all())
