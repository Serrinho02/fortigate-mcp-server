"""
Inventory schema: Customer -> Site -> Device -> VDOM, plus HACluster and
CredentialRef bookkeeping. Mirrors the data model agreed in the
architecture plan (§5). `Device` deliberately has no secret fields --
`credential_id` is an opaque pointer resolved through `CredentialManager`
at connection time, never a value stored or passed around here.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow_naive() -> datetime:
    """Naive UTC timestamp for columns that get compared with `<`/`>` at
    runtime (expiry checks, drift windows). SQLite/aiosqlite silently drops
    tzinfo on round-trip regardless of `DateTime(timezone=True)`, so mixing
    aware and naive datetimes in a comparison raises `TypeError` -- naive
    throughout sidesteps that instead of fighting the driver."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("cus"))
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    tags: Mapped[Optional[str]] = mapped_column(String(500), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    sites: Mapped[list["Site"]] = relationship(back_populates="customer", cascade="all, delete-orphan")


class Site(Base):
    __tablename__ = "sites"
    __table_args__ = (UniqueConstraint("customer_id", "name", name="uq_site_customer_name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("site"))
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    location: Mapped[Optional[str]] = mapped_column(String(200), default=None)

    customer: Mapped["Customer"] = relationship(back_populates="sites")
    devices: Mapped[list["Device"]] = relationship(back_populates="site", cascade="all, delete-orphan")


class HACluster(Base):
    __tablename__ = "ha_clusters"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ha"))
    site_id: Mapped[str] = mapped_column(ForeignKey("sites.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    mode: Mapped[Optional[str]] = mapped_column(String(50), default=None)


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("site_id", "name", name="uq_device_site_name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("dev"))
    site_id: Mapped[str] = mapped_column(ForeignKey("sites.id"), index=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    mgmt_host: Mapped[str] = mapped_column(String(255), index=True)
    mgmt_port: Mapped[int] = mapped_column(Integer, default=443)
    product_type: Mapped[str] = mapped_column(String(50), default="fortios")
    model: Mapped[Optional[str]] = mapped_column(String(100), default=None)
    serial: Mapped[Optional[str]] = mapped_column(String(100), default=None)
    fortios_version: Mapped[Optional[str]] = mapped_column(String(50), default=None)
    ha_role: Mapped[Optional[str]] = mapped_column(String(50), default=None)
    ha_cluster_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("ha_clusters.id"), nullable=True, default=None
    )
    default_vdom: Mapped[str] = mapped_column(String(100), default="root")
    # Opaque pointer into the OS keyring -- never a secret value itself.
    credential_id: Mapped[Optional[str]] = mapped_column(String(64), default=None)
    verify_ssl: Mapped[bool] = mapped_column(Boolean, default=True)
    timeout: Mapped[int] = mapped_column(Integer, default=30)
    tags: Mapped[Optional[str]] = mapped_column(String(500), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    site: Mapped["Site"] = relationship(back_populates="devices")
    vdoms: Mapped[list["VDOM"]] = relationship(back_populates="device", cascade="all, delete-orphan")


class VDOM(Base):
    __tablename__ = "vdoms"
    __table_args__ = (UniqueConstraint("device_id", "name", name="uq_vdom_device_name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("vdom"))
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)

    device: Mapped["Device"] = relationship(back_populates="vdoms")


class CredentialRef(Base):
    """Bookkeeping only -- the real secret lives in the OS keyring, never here."""

    __tablename__ = "credential_refs"

    credential_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    auth_type: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=None)


class ChangeRecord(Base):
    """One row per preview -> apply -> (optional) rollback lifecycle.

    `device_id` deliberately is NOT a foreign key to `devices.id`: Phase 2's
    services still resolve devices through the legacy FortiGateManager
    (config.json-backed, arbitrary string ids like "default"), not through
    this inventory DB's Device rows -- unifying those two device-identity
    systems is a known, separately tracked piece of follow-up work, not
    something to paper over here with a constraint that would be wrong for
    most of today's callers.
    """

    __tablename__ = "change_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("chgrec"))
    change_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    device_id: Mapped[str] = mapped_column(String(200), index=True)
    vdom: Mapped[Optional[str]] = mapped_column(String(100), default=None)
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[Optional[str]] = mapped_column(String(200), default=None)
    operation: Mapped[str] = mapped_column(String(20))
    mode_at_request: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="proposed")
    before_json: Mapped[Optional[str]] = mapped_column(Text, default=None)
    after_json: Mapped[Optional[str]] = mapped_column(Text, default=None)
    diff_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow_naive)
    expires_at: Mapped[datetime] = mapped_column(DateTime())
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(), default=None)


class PolicySnapshot(Base):
    """Point-in-time capture of a resource's pre-change state, recorded
    whenever a ChangeRecord is applied. Distinct from ChangeRecord's own
    before_json/after_json: this is the durable audit trail queried on its
    own (e.g. "show me every version of policy 35 we've seen"), not tied to
    inspecting one specific change."""

    __tablename__ = "policy_snapshots"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("snap"))
    device_id: Mapped[str] = mapped_column(String(200), index=True)
    vdom: Mapped[Optional[str]] = mapped_column(String(100), default=None)
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[Optional[str]] = mapped_column(String(200), default=None)
    taken_at: Mapped[datetime] = mapped_column(DateTime(), default=utcnow_naive)
    content_hash: Mapped[str] = mapped_column(String(64))
    content_json: Mapped[Optional[str]] = mapped_column(Text, default=None)
    change_id: Mapped[Optional[str]] = mapped_column(String(32), default=None)
