"""
Service layer -- sits between the MCP tool functions in server.py/
server_http.py and the FortiOS adapter. Each service resolves a legacy
device_id against the existing FortiGateManager, wraps the resulting
FortiGateAPI client in a FortiOSAdapter, and calls the adapter's Protocol
methods instead of FortiGateAPI methods directly -- this is Phase 2 of the
staged migration, replacing tools/*.py one domain at a time while keeping
every MCP tool's signature and output format identical.
"""
