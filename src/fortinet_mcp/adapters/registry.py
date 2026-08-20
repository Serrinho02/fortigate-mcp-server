"""
AdapterRegistry — keyed by `product_type` (e.g. "fortios", "fortimanager").

This is the whole mechanism that lets new Fortinet products be added later
without touching services, domain engines, or MCP tools: the
`ConnectionManager` looks up `Device.product_type` and asks the registry to
build the matching adapter. Nothing else needs to know adapters exist.
"""
from __future__ import annotations

from typing import Callable

from .base import FortinetProductAdapter


class AdapterRegistry:
    """Maps a product_type string to a factory that builds its adapter."""

    def __init__(self) -> None:
        self._factories: dict[str, Callable[..., FortinetProductAdapter]] = {}

    def register(
        self, product_type: str, factory: Callable[..., FortinetProductAdapter]
    ) -> None:
        """Register the factory used to build adapters for `product_type`.

        Raises:
            ValueError: if `product_type` is already registered.
        """
        if product_type in self._factories:
            raise ValueError(
                f"Adapter for product_type '{product_type}' is already registered"
            )
        self._factories[product_type] = factory

    def create(self, product_type: str, *args: object, **kwargs: object) -> FortinetProductAdapter:
        """Build a new adapter instance for `product_type`.

        Raises:
            ValueError: if no adapter is registered for `product_type`.
        """
        try:
            factory = self._factories[product_type]
        except KeyError:
            raise ValueError(
                f"No adapter registered for product_type '{product_type}'. "
                f"Known product types: {self.known_product_types()}"
            ) from None
        return factory(*args, **kwargs)

    def known_product_types(self) -> list[str]:
        return sorted(self._factories)
