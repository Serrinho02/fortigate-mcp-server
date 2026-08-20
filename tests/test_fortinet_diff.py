"""Tests for the DiffEngine (domain/diff.py)."""
import pytest

from src.fortinet_mcp.domain.diff import compute_diff


class TestCreateDiff:
    def test_create_shows_added_fields(self):
        diff = compute_diff("create", None, {"name": "web1", "subnet": "10.0.0.0/24"})
        assert diff == {"operation": "create", "added": {"name": "web1", "subnet": "10.0.0.0/24"}}

    def test_create_with_no_proposed_data_shows_empty_added(self):
        diff = compute_diff("create", None, None)
        assert diff == {"operation": "create", "added": {}}


class TestDeleteDiff:
    def test_delete_shows_removed_fields(self):
        diff = compute_diff("delete", {"name": "web1"}, None)
        assert diff == {"operation": "delete", "removed": {"name": "web1"}}


class TestUpdateDiff:
    def test_update_shows_only_changed_fields(self):
        before = {"name": "web1", "extip": "1.2.3.4", "extintf": "wan1"}
        after = {"name": "web1", "extip": "5.6.7.8", "extintf": "wan1"}

        diff = compute_diff("update", before, after)

        assert diff == {
            "operation": "update",
            "changed_fields": {"extip": {"before": "1.2.3.4", "after": "5.6.7.8"}},
        }

    def test_update_detects_added_and_removed_keys(self):
        before = {"name": "vip1", "extport": "443"}
        after = {"name": "vip1", "mappedport": "8443"}

        diff = compute_diff("update", before, after)

        assert diff["changed_fields"] == {
            "extport": {"before": "443", "after": None},
            "mappedport": {"before": None, "after": "8443"},
        }

    def test_update_with_no_changes_returns_empty_changed_fields(self):
        data = {"name": "web1", "subnet": "10.0.0.0/24"}
        diff = compute_diff("update", data, dict(data))
        assert diff == {"operation": "update", "changed_fields": {}}

    def test_update_handles_none_before(self):
        diff = compute_diff("update", None, {"name": "web1"})
        assert diff == {"operation": "update", "changed_fields": {"name": {"before": None, "after": "web1"}}}


class TestUnknownOperation:
    def test_unknown_operation_raises(self):
        with pytest.raises(ValueError, match="Unknown operation"):
            compute_diff("frobnicate", {}, {})
