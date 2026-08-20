"""
Vendor adapter layer — the plugin boundary of the platform.

Nothing above this package (services, domain, repositories, MCP tools) may
import a product-specific client directly. New Fortinet products are added
by implementing `FortinetProductAdapter` and registering a factory in an
`AdapterRegistry`; everything above stays untouched.
"""
