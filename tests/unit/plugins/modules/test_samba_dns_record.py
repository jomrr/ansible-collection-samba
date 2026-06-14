# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_dns_record orchestration and pure logic.

The samba I/O is faked, so these run without the bindings. Importing the module
must also not require samba."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_record_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_dns_record


class FakeIO:
    """Records calls and simulates a per-name record store; no samba required."""

    def __init__(self, zone=True, existing=None):
        self.zone = zone
        self.existing = existing  # None = name absent; list = record specs present
        self.calls = []

    def zone_exists(self, zone):
        return self.zone

    def read(self, zone, name):
        return self.existing

    def add(self, zone, name, spec):
        self.calls.append(("add", spec["type"], spec["value"]))
        if self.existing and any(logic.records_equal(spec, e) for e in self.existing):
            return False
        if self.existing is None:
            self.existing = []
        self.existing.append(spec)
        return True

    def remove(self, zone, name, spec):
        self.calls.append(("remove", spec["type"], spec["value"]))
        if not self.existing:
            return False
        kept = [e for e in self.existing if not logic.records_equal(spec, e)]
        changed = len(kept) != len(self.existing)
        self.existing = kept
        return changed


def make_params(**over):
    params = {
        "zone": "example.com",
        "name": "www",
        "type": "A",
        "value": "192.0.2.10",
        "preference": None,
        "priority": None,
        "weight": None,
        "port": None,
        "ttl": 900,
        "state": "present",
    }
    params.update(over)
    return params


def call_names(fake):
    return [call[0] for call in fake.calls]


# Per-type parameter sets and a matching existing spec for each.
TYPE_CASES = {
    "A": (dict(type="A", value="192.0.2.10"), {"type": "A", "value": "192.0.2.10", "ttl": 900}),
    "AAAA": (dict(type="AAAA", value="2001:db8::10"),
             {"type": "AAAA", "value": "2001:0db8:0000:0000:0000:0000:0000:0010", "ttl": 900}),
    "CNAME": (dict(type="CNAME", value="www.example.com"),
              {"type": "CNAME", "value": "www.example.com.", "ttl": 900}),
    "PTR": (dict(type="PTR", value="host.example.com"),
            {"type": "PTR", "value": "host.example.com.", "ttl": 900}),
    "NS": (dict(type="NS", value="ns1.example.com"),
           {"type": "NS", "value": "ns1.example.com.", "ttl": 900}),
    "MX": (dict(type="MX", value="mail.example.com", preference=10),
           {"type": "MX", "value": "mail.example.com.", "preference": 10, "ttl": 900}),
    "SRV": (dict(type="SRV", value="dc1.example.com", priority=0, weight=100, port=389),
            {"type": "SRV", "value": "dc1.example.com.", "priority": 0, "weight": 100, "port": 389, "ttl": 900}),
    "TXT": (dict(type="TXT", value="v=spf1 -all"),
            {"type": "TXT", "value": "v=spf1 -all", "ttl": 900}),
}


def test_module_imports_without_samba():
    assert hasattr(samba_dns_record, "main")
    assert hasattr(samba_dns_record, "SambaDnsRecordIO")


@pytest.mark.parametrize("rtype", list(TYPE_CASES))
def test_present_creates_each_type(rtype):
    over = TYPE_CASES[rtype][0]
    fake = FakeIO(existing=None)
    result = logic.run(make_params(**over), False, fake)
    assert result["changed"] is True
    assert result["record"]["state"] == "present"
    assert "add" in call_names(fake)


@pytest.mark.parametrize("rtype", list(TYPE_CASES))
def test_present_idempotent_each_type(rtype):
    over, existing = TYPE_CASES[rtype]
    fake = FakeIO(existing=[dict(existing)])
    result = logic.run(make_params(**over), False, fake)
    assert result["changed"] is False
    assert call_names(fake) == []


@pytest.mark.parametrize("rtype", list(TYPE_CASES))
def test_absent_removes_each_type(rtype):
    over, existing = TYPE_CASES[rtype]
    fake = FakeIO(existing=[dict(existing)])
    result = logic.run(make_params(state="absent", **over), False, fake)
    assert result["changed"] is True
    assert result["record"]["state"] == "absent"
    assert "remove" in call_names(fake)


@pytest.mark.parametrize("rtype", list(TYPE_CASES))
def test_absent_missing_is_noop(rtype):
    over = TYPE_CASES[rtype][0]
    fake = FakeIO(existing=None)
    result = logic.run(make_params(state="absent", **over), False, fake)
    assert result["changed"] is False
    assert call_names(fake) == []


def test_present_other_value_same_type_adds():
    # A record with a different value is a different record: it is added, the
    # existing one is left in place (no purge).
    fake = FakeIO(existing=[{"type": "A", "value": "192.0.2.1", "ttl": 900}])
    result = logic.run(make_params(value="192.0.2.2"), False, fake)
    assert result["changed"] is True
    assert {"type": "A", "value": "192.0.2.1", "ttl": 900} in fake.existing
    assert any(e["value"] == "192.0.2.2" for e in fake.existing)


def test_mx_different_preference_is_a_different_record():
    fake = FakeIO(existing=[{"type": "MX", "value": "mail.example.com", "preference": 20, "ttl": 900}])
    result = logic.run(make_params(type="MX", value="mail.example.com", preference=10), False, fake)
    assert result["changed"] is True
    assert "add" in call_names(fake)


def test_mx_same_preference_is_idempotent():
    fake = FakeIO(existing=[{"type": "MX", "value": "mail.example.com", "preference": 10, "ttl": 900}])
    result = logic.run(make_params(type="MX", value="mail.example.com", preference=10), False, fake)
    assert result["changed"] is False


def test_srv_different_priority_is_a_different_record():
    existing = [{"type": "SRV", "value": "dc1.example.com", "priority": 10, "weight": 100, "port": 389, "ttl": 900}]
    fake = FakeIO(existing=existing)
    result = logic.run(
        make_params(type="SRV", value="dc1.example.com", priority=0, weight=100, port=389), False, fake)
    assert result["changed"] is True


def test_aaaa_normalised_form_is_idempotent():
    # Stored in expanded form, requested compressed: still the same record.
    fake = FakeIO(existing=[{"type": "AAAA",
                             "value": "2001:0db8:0000:0000:0000:0000:0000:0001", "ttl": 900}])
    result = logic.run(make_params(type="AAAA", value="2001:db8::1"), False, fake)
    assert result["changed"] is False


def test_cname_trailing_dot_and_case_idempotent():
    fake = FakeIO(existing=[{"type": "CNAME", "value": "Host.Example.COM.", "ttl": 900}])
    result = logic.run(make_params(type="CNAME", value="host.example.com"), False, fake)
    assert result["changed"] is False


def test_invalid_ipv4_fails():
    fake = FakeIO(existing=None)
    with pytest.raises(logic.SambaDnsRecordError):
        logic.run(make_params(type="A", value="999.0.0.1"), False, fake)
    assert call_names(fake) == []


def test_invalid_ipv6_fails():
    fake = FakeIO(existing=None)
    with pytest.raises(logic.SambaDnsRecordError):
        logic.run(make_params(type="AAAA", value="not::an::ip"), False, fake)


def test_missing_value_fails():
    fake = FakeIO(existing=None)
    with pytest.raises(logic.SambaDnsRecordError):
        logic.run(make_params(value=""), False, fake)


def test_zone_missing_fails():
    fake = FakeIO(zone=False, existing=None)
    with pytest.raises(logic.SambaDnsRecordError):
        logic.run(make_params(), False, fake)


def test_check_mode_present_does_not_write():
    fake = FakeIO(existing=None)
    result = logic.run(make_params(), True, fake)
    assert result["changed"] is True
    assert call_names(fake) == []


def test_check_mode_absent_does_not_write():
    fake = FakeIO(existing=[{"type": "A", "value": "192.0.2.10", "ttl": 900}])
    result = logic.run(make_params(state="absent"), True, fake)
    assert result["changed"] is True
    assert call_names(fake) == []


def test_present_race_already_added_reports_unchanged():
    class CollisionIO(FakeIO):
        def add(self, zone, name, spec):
            self.calls.append(("add", spec["type"], spec["value"]))
            return False

    fake = CollisionIO(existing=None)
    result = logic.run(make_params(), False, fake)
    assert "add" in call_names(fake)
    assert result["changed"] is False
    # Desired state still reported as present.
    assert result["record"]["state"] == "present"


def test_absent_race_already_gone_reports_unchanged():
    class VanishedIO(FakeIO):
        def remove(self, zone, name, spec):
            self.calls.append(("remove", spec["type"], spec["value"]))
            return False

    fake = VanishedIO(existing=[{"type": "A", "value": "192.0.2.10", "ttl": 900}])
    result = logic.run(make_params(state="absent"), False, fake)
    assert "remove" in call_names(fake)
    assert result["changed"] is False
    assert result["record"]["state"] == "absent"


def test_records_equal_distinguishes_types():
    assert not logic.records_equal(
        {"type": "A", "value": "192.0.2.1"}, {"type": "AAAA", "value": "192.0.2.1"})


def test_public_state_includes_structure_for_srv():
    spec = logic.validate(make_params(type="SRV", value="dc.example.com", priority=0, weight=100, port=389))
    state = logic.public_state(spec, "example.com", "_ldap._tcp", True)
    assert state["priority"] == 0 and state["weight"] == 100 and state["port"] == 389
