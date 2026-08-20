"""
ConnectionManager -- lazy-connect, cache, and resolve device sessions.

Phase 1 scope: a single product type (fortios) via `FortiOSAdapter`, real
device resolution against the inventory DB, and a real in-memory session
cache. Idle-eviction is a synchronous helper a caller can invoke
periodically (`evict_idle`) rather than a background asyncio sweep task --
keeps this phase's scope contained; see architecture plan's Open Questions.

The manager takes a session *factory*, not a single bound session: the
adapter-session cache (`_sessions`) must outlive any one database
transaction, so every inventory lookup opens and closes its own short-lived
`AsyncSession` rather than sharing one across the server's lifetime (SQLAlchemy's
`AsyncSession` is not safe for concurrent/long-lived reuse across unrelated
calls). `Device` rows are read with the relationships used here
(`site`, `site.customer`) eagerly loaded, so they stay usable after their
session closes.

The manager never caches a decrypted secret: `CredentialManager.resolve`
is called once per new session build, the value is handed straight to the
adapter's underlying client constructor, and the local reference is
dropped when `_build_session` returns.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.fortigate_mcp.config.models import FortiGateDeviceConfig
from src.fortigate_mcp.core.fortigate import FortiGateAPI

from ..adapters.base import FortinetProductAdapter
from ..adapters.registry import AdapterRegistry
from ..errors import CredentialNotProvisionedError, DeviceConnectionError
from ..infra.models_orm import Device
from ..repositories.inventory_repository import InventoryRepository
from .credential_manager import CredentialManager
from .device_resolver import DeviceResolver


@dataclass
class ConnectionSession:
    """Denormalized, in-memory-only view of a live device connection."""

    device_id: str
    vdom: str
    adapter: FortinetProductAdapter
    customer_name: str
    site_name: str
    device_name: str
    mgmt_host: str
    product_type: str
    model: Optional[str] = None
    serial: Optional[str] = None
    fortios_version: Optional[str] = None
    ha_role: Optional[str] = None
    state: str = "connected"
    opened_at: float = field(default_factory=time.monotonic)
    last_used_at: float = field(default_factory=time.monotonic)
    timeout: int = 30

    def touch(self) -> None:
        self.last_used_at = time.monotonic()


class ConnectionManager:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        credentials: CredentialManager,
        registry: AdapterRegistry,
    ):
        self._session_factory = session_factory
        self._credentials = credentials
        self._registry = registry
        self._sessions: dict[tuple[str, str], ConnectionSession] = {}

    async def resolve_target(self, target: str) -> list[Device]:
        async with self._session_factory() as session:
            resolver = DeviceResolver(InventoryRepository(session))
            return await resolver.resolve(target)

    async def list_all_devices(self) -> list[Device]:
        """Every device in the inventory, unscoped -- used by fleet
        operations (Phase 6) that default to the whole estate when no
        target is given (e.g. `fleet.search_object` with no scoping target)."""
        async with self._session_factory() as session:
            return await InventoryRepository(session).list_devices()

    async def connect(self, target: str, vdom: Optional[str] = None) -> ConnectionSession:
        """Resolve `target` to exactly one device and return a (possibly
        cached) live session for it.

        Raises:
            AmbiguousTargetError: `target` matches more than one device.
            DeviceNotFoundError: `target` matches no device.
            CredentialNotProvisionedError: the device's credential has no
                secret in the OS keyring yet.
            DeviceConnectionError: the adapter's health probe failed.
        """
        async with self._session_factory() as session:
            resolver = DeviceResolver(InventoryRepository(session))
            device = await resolver.resolve_one(target)
        return await self.get_session(device, vdom=vdom)

    async def get_session(self, device: Device, vdom: Optional[str] = None) -> ConnectionSession:
        effective_vdom = vdom or device.default_vdom
        cache_key = (device.id, effective_vdom)

        cached = self._sessions.get(cache_key)
        if cached is not None:
            cached.touch()
            return cached

        session = await self._build_session(device, effective_vdom)
        self._sessions[cache_key] = session
        return session

    async def _build_session(self, device: Device, vdom: str) -> ConnectionSession:
        if device.credential_id is None or not self._credentials.is_provisioned(
            device.credential_id
        ):
            raise CredentialNotProvisionedError(device.credential_id or "<none>")

        secret = self._credentials.resolve(device.credential_id)
        assert secret is not None  # guaranteed by the is_provisioned check above

        device_config = FortiGateDeviceConfig(
            host=device.mgmt_host,
            port=device.mgmt_port,
            username=secret.get("username"),
            password=secret.get("password"),
            api_token=secret.get("api_token"),
            vdom=vdom,
            verify_ssl=device.verify_ssl,
            timeout=device.timeout,
        )
        client = FortiGateAPI(device.id, device_config)
        # `secret`/`device_config` fall out of scope here -- nothing above
        # this method ever holds the decoded credential values.

        adapter = self._registry.create(device.product_type, client)

        if not await adapter.test_connection():
            await adapter.close()
            raise DeviceConnectionError(device.name, device.mgmt_host)

        return ConnectionSession(
            device_id=device.id,
            vdom=vdom,
            adapter=adapter,
            customer_name=device.site.customer.name,
            site_name=device.site.name,
            device_name=device.name,
            mgmt_host=device.mgmt_host,
            product_type=device.product_type,
            model=device.model,
            serial=device.serial,
            fortios_version=device.fortios_version,
            ha_role=device.ha_role,
            timeout=device.timeout,
        )

    async def disconnect(self, device_id: str, vdom: Optional[str] = None) -> None:
        if vdom is None:
            keys = [k for k in self._sessions if k[0] == device_id]
        else:
            keys = [(device_id, vdom)]
        for key in keys:
            session = self._sessions.pop(key, None)
            if session is not None:
                await session.adapter.close()

    async def disconnect_all(self) -> None:
        for key in list(self._sessions):
            session = self._sessions.pop(key)
            await session.adapter.close()

    def list_active(self) -> list[ConnectionSession]:
        return list(self._sessions.values())

    def evict_idle(self, idle_timeout_seconds: float) -> list[ConnectionSession]:
        """Drop cache entries idle beyond `idle_timeout_seconds` and return
        them. Closing is the caller's responsibility (`await session.adapter
        .close()`) since this method is synchronous by design -- callers
        that want a fully automatic sweep can await-close the returned list."""
        now = time.monotonic()
        evicted = []
        for key, session in list(self._sessions.items()):
            if now - session.last_used_at > idle_timeout_seconds:
                evicted.append(self._sessions.pop(key))
        return evicted
