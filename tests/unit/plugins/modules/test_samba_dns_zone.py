# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_dns_zone orchestration and pure logic.

The samba I/O is faked, so these run without the bindings. Importing the module
must also not require samba."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_zone_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_dns_zone


class FakeIO:
    """Records calls and simulates a zone store; no samba required."""

    def __init__(self, zones=None):
        # zones: set of existing zone names (lowercased)
        self.zones = set(zones or [])
        self.calls = []

    def zone_exists(self, name):
        return name in self.zones

    def create(self, name, replication):
        self.calls.append(("create", name, replication))
        if name in self.zones:
            return False
        self.zones.add(name)
        return True

    def delete(self, name):
        self.calls.append(("delete", name))
        if name not in self.zones:
            return False
        self.zones.discard(name)
        return True


def make_params(**over):
    params = {"name": "example.com", "replication": "domain", "state": "present"}
    params.update(over)
    return params


def call_names(fake):
    return [call[0] for call in fake.calls]


def test_module_imports_without_samba():
    assert hasattr(samba_dns_zone, "main")
    assert hasattr(samba_dns_zone, "SambaDnsZoneIO")


def test_present_creates_forward_zone():
    fake = FakeIO()
    result = logic.run(make_params(name="example.com"), False, fake)
    assert result["changed"] is True
    assert result["zone"]["state"] == "present"
    assert ("create", "example.com", "domain") in fake.calls


def test_present_creates_reverse_zone():
    fake = FakeIO()
    result = logic.run(make_params(name="2.0.192.in-addr.arpa"), False, fake)
    assert result["changed"] is True
    assert ("create", "2.0.192.in-addr.arpa", "domain") in fake.calls


def test_present_forest_replication_passed_through():
    fake = FakeIO()
    result = logic.run(make_params(name="forest.example.com", replication="forest"), False, fake)
    assert result["changed"] is True
    assert ("create", "forest.example.com", "forest") in fake.calls
    assert result["zone"]["replication"] == "forest"


def test_present_existing_zone_is_idempotent():
    fake = FakeIO(zones={"example.com"})
    result = logic.run(make_params(name="example.com"), False, fake)
    assert result["changed"] is False
    assert call_names(fake) == []


def test_present_existing_zone_name_is_lowercased():
    # samba stores zones lowercased; a mixed-case request must match.
    fake = FakeIO(zones={"example.com"})
    result = logic.run(make_params(name="Example.COM"), False, fake)
    assert result["changed"] is False


def test_present_existing_zone_does_not_reconcile_replication():
    # Decision: present on an existing zone ensures existence only; the
    # replication scope is fixed at creation and is not changed (changed:false).
    fake = FakeIO(zones={"example.com"})
    result = logic.run(make_params(name="example.com", replication="forest"), False, fake)
    assert result["changed"] is False
    assert "create" not in call_names(fake)


def test_absent_deletes_existing_zone():
    fake = FakeIO(zones={"example.com"})
    result = logic.run(make_params(state="absent"), False, fake)
    assert result["changed"] is True
    assert result["zone"]["state"] == "absent"
    assert ("delete", "example.com") in fake.calls


def test_absent_on_missing_zone_is_noop():
    fake = FakeIO()
    result = logic.run(make_params(state="absent"), False, fake)
    assert result["changed"] is False
    assert call_names(fake) == []


@pytest.mark.parametrize("bad", ["", "has space", ".leading", "trailing.", "a..b"])
def test_invalid_zone_name_fails(bad):
    fake = FakeIO()
    with pytest.raises(logic.SambaDnsZoneError):
        logic.run(make_params(name=bad), False, fake)
    assert call_names(fake) == []


def test_check_mode_present_does_not_write():
    fake = FakeIO()
    result = logic.run(make_params(), True, fake)
    assert result["changed"] is True
    assert call_names(fake) == []
    assert "example.com" not in fake.zones


def test_check_mode_absent_does_not_write():
    fake = FakeIO(zones={"example.com"})
    result = logic.run(make_params(state="absent"), True, fake)
    assert result["changed"] is True
    assert call_names(fake) == []
    assert "example.com" in fake.zones


def test_create_race_already_exists_reports_unchanged():
    class CollisionIO(FakeIO):
        def create(self, name, replication):
            self.calls.append(("create", name, replication))
            return False

    fake = CollisionIO()
    result = logic.run(make_params(), False, fake)
    assert "create" in call_names(fake)
    assert result["changed"] is False
    assert result["zone"]["state"] == "present"


def test_delete_race_already_gone_reports_unchanged():
    class VanishedIO(FakeIO):
        def delete(self, name):
            self.calls.append(("delete", name))
            return False

    fake = VanishedIO(zones={"example.com"})
    result = logic.run(make_params(state="absent"), False, fake)
    assert "delete" in call_names(fake)
    assert result["changed"] is False
    assert result["zone"]["state"] == "absent"
