# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_dns_zone orchestration and pure logic.

The samba I/O is faked, so these run without the bindings. Importing the module
must also not require samba."""

from __future__ import annotations

import pytest
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_zone_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_dns_zone

#: The aging properties samba stores on a zone created through the RPC
#: (verified against samba 4.22 and 4.24): one-week intervals, aging off.
CREATED = {"norefresh_interval": 168, "refresh_interval": 168, "aging": 0}
#: The properties samba-tool dns zoneoptions set on a seeded zone.
SEEDED = {"norefresh_interval": 24, "refresh_interval": 48, "aging": 1}
#: RPC property name -> stored parameter, for the fake's writes.
_PARAM = {option.rpc_property: option.param for option in logic.ZONE_OPTIONS}


class FakeIO:
    """Records calls and simulates a zone store; no samba required."""

    def __init__(self, zones=None):
        # zones: existing zone names (lowercased) -> stored aging properties
        self.zones = {name: dict(stored) for name, stored in (zones or {}).items()}
        self.calls = []

    def read_options(self, name):
        stored = self.zones.get(name)
        return None if stored is None else dict(stored)

    def create(self, name, replication):
        self.calls.append(("create", name, replication))
        if name in self.zones:
            return False
        self.zones[name] = dict(CREATED)
        return True

    def delete(self, name):
        self.calls.append(("delete", name))
        if name not in self.zones:
            return False
        del self.zones[name]
        return True

    def set_properties(self, name, writes):
        self.calls.append(("set", name, list(writes)))
        for rpc_property, value in writes:
            self.zones[name][_PARAM[rpc_property]] = value


def make_params(**over):
    params = {
        "name": "example.com", "replication": "domain", "state": "present",
        "aging": None, "norefresh_interval": None, "refresh_interval": None,
    }
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
    fake = FakeIO(zones={"example.com": CREATED})
    result = logic.run(make_params(name="example.com"), False, fake)
    assert result["changed"] is False
    assert call_names(fake) == []


def test_present_existing_zone_name_is_lowercased():
    # samba stores zones lowercased; a mixed-case request must match.
    fake = FakeIO(zones={"example.com": CREATED})
    result = logic.run(make_params(name="Example.COM"), False, fake)
    assert result["changed"] is False


def test_present_existing_zone_does_not_reconcile_replication():
    # Decision: present on an existing zone ensures existence only; the
    # replication scope is fixed at creation and is not changed (changed:false).
    fake = FakeIO(zones={"example.com": CREATED})
    result = logic.run(make_params(name="example.com", replication="forest"), False, fake)
    assert result["changed"] is False
    assert "create" not in call_names(fake)


def test_absent_deletes_existing_zone():
    fake = FakeIO(zones={"example.com": CREATED})
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
    fake = FakeIO(zones={"example.com": CREATED})
    result = logic.run(make_params(state="absent"), True, fake)
    assert result["changed"] is True
    assert call_names(fake) == []
    assert "example.com" in fake.zones


def test_create_race_already_exists_reports_unchanged():
    class CollisionIO(FakeIO):
        def create(self, name, replication):
            # Another run created the zone between the read and the create.
            self.calls.append(("create", name, replication))
            self.zones[name] = dict(CREATED)
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

    fake = VanishedIO(zones={"example.com": CREATED})
    result = logic.run(make_params(state="absent"), False, fake)
    assert "delete" in call_names(fake)
    assert result["changed"] is False
    assert result["zone"]["state"] == "absent"


# --- aging options (samba-tool dns zoneoptions) ---

def test_present_creates_zone_then_writes_requested_options_in_order():
    fake = FakeIO()
    result = logic.run(make_params(aging=True, norefresh_interval=72, refresh_interval=96), False, fake)
    assert result["changed"] is True
    # The intervals go first, so aging never starts with the previous ones.
    assert fake.calls == [
        ("create", "example.com", "domain"),
        ("set", "example.com", [("NoRefreshInterval", 72), ("RefreshInterval", 96), ("Aging", 1)]),
    ]
    assert result["zone"] == {
        "name": "example.com", "state": "present", "replication": "domain",
        "norefresh_interval": 72, "refresh_interval": 96, "aging": True,
    }


def test_existing_zone_writes_only_the_differing_options():
    fake = FakeIO(zones={"example.com": CREATED})
    result = logic.run(make_params(aging=True, norefresh_interval=24, refresh_interval=168), False, fake)
    assert result["changed"] is True
    assert fake.calls == [("set", "example.com", [("NoRefreshInterval", 24), ("Aging", 1)])]
    assert result["diff"] == {
        "before": {"name": "example.com", "norefresh_interval": 168, "refresh_interval": 168, "aging": False},
        "after": {"name": "example.com", "norefresh_interval": 24, "refresh_interval": 168, "aging": True},
    }


def test_matching_options_are_unchanged_on_the_second_run():
    fake = FakeIO(zones={"example.com": CREATED})
    params = make_params(aging=True, norefresh_interval=24, refresh_interval=48)
    assert logic.run(params, False, fake)["changed"] is True
    fake.calls.clear()
    result = logic.run(params, False, fake)
    assert result["changed"] is False
    assert fake.calls == []
    assert result["diff"]["before"] == result["diff"]["after"]


def test_unset_options_are_not_managed():
    fake = FakeIO(zones={"example.com": SEEDED})
    result = logic.run(make_params(aging=False), False, fake)
    assert fake.calls == [("set", "example.com", [("Aging", 0)])]
    assert fake.zones["example.com"] == {"norefresh_interval": 24, "refresh_interval": 48, "aging": False}
    assert result["zone"]["norefresh_interval"] == 24
    assert result["zone"]["refresh_interval"] == 48


def test_a_property_the_zone_does_not_store_counts_as_zero():
    # _msdcs zones carry no dNSProperty at all; the DNS server reads 0 there.
    fake = FakeIO(zones={"example.com": {}})
    result = logic.run(make_params(aging=False, norefresh_interval=0, refresh_interval=0), False, fake)
    assert result["changed"] is False
    assert fake.calls == []


def test_check_mode_on_an_existing_zone_predicts_without_writing():
    fake = FakeIO(zones={"example.com": CREATED})
    result = logic.run(make_params(aging=True), True, fake)
    assert result["changed"] is True
    assert fake.calls == []
    assert fake.zones["example.com"] == CREATED
    assert result["zone"]["aging"] is True


def test_check_mode_create_reports_unset_options_as_unknown():
    fake = FakeIO()
    result = logic.run(make_params(aging=True), True, fake)
    assert result["changed"] is True
    assert fake.calls == []
    assert result["zone"]["aging"] is True
    assert result["zone"]["norefresh_interval"] is None
    assert result["zone"]["refresh_interval"] is None


def test_options_with_state_absent_fail():
    fake = FakeIO(zones={"example.com": CREATED})
    with pytest.raises(logic.SambaDnsZoneError, match="state=present"):
        logic.run(make_params(state="absent", aging=False), False, fake)
    assert fake.calls == []


@pytest.mark.parametrize("param", ["norefresh_interval", "refresh_interval"])
@pytest.mark.parametrize("value", [-1, logic.MAX_INTERVAL_HOURS + 1])
def test_interval_out_of_range_fails(param, value):
    fake = FakeIO(zones={"example.com": CREATED})
    with pytest.raises(logic.SambaDnsZoneError, match=param):
        logic.run(make_params(**{param: value}), False, fake)
    assert fake.calls == []


@pytest.mark.parametrize("value", [0, logic.MAX_INTERVAL_HOURS])
def test_interval_bounds_are_accepted(value):
    fake = FakeIO(zones={"example.com": CREATED})
    logic.run(make_params(refresh_interval=value), False, fake)
    assert fake.zones["example.com"]["refresh_interval"] == value


def test_created_zone_missing_on_read_back_fails():
    class LostIO(FakeIO):
        def create(self, name, replication):
            self.calls.append(("create", name, replication))
            return True

    fake = LostIO()
    with pytest.raises(logic.SambaDnsZoneError, match="read back"):
        logic.run(make_params(aging=True), False, fake)
    assert call_names(fake) == ["create"]


# --- read-mirror helpers (used by samba_dns_zone_info) ---

def test_decode_replication_domain_partition():
    dn = "DC=example.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=com"
    assert logic.decode_replication(dn) == "domain"


def test_decode_replication_forest_partition():
    dn = "DC=forest.example.com,CN=MicrosoftDNS,DC=ForestDnsZones,DC=example,DC=com"
    assert logic.decode_replication(dn) == "forest"


def test_decode_replication_is_case_insensitive():
    dn = "DC=z,CN=MicrosoftDNS,DC=forestdnszones,DC=example,DC=com"
    assert logic.decode_replication(dn) == "forest"


@pytest.mark.parametrize("name,reverse", [
    ("example.com", False),
    ("2.0.192.in-addr.arpa", True),
    ("0.8.b.d.0.1.0.0.2.ip6.arpa", True),
    ("FORWARD.EXAMPLE.COM", False),
])
def test_is_reverse(name, reverse):
    assert logic.is_reverse(name) is reverse


def test_zone_info_roundtrips_as_write_input():
    # A returned zone's fields are exactly what samba_dns_zone takes as input (the read mirror of the write semantics; scope from the partition).
    dn = "DC=2.0.192.in-addr.arpa,CN=MicrosoftDNS,DC=ForestDnsZones,DC=example,DC=com"
    info = logic.zone_info("2.0.192.in-addr.arpa", dn, SEEDED)
    assert info == {
        "name": "2.0.192.in-addr.arpa",
        "replication": "forest",
        "norefresh_interval": 24,
        "refresh_interval": 48,
        "aging": True,
        "reverse": True,
        "dn": dn,
    }
    # name, replication and the aging options line up with the write module's
    # accepted parameters.
    assert info["replication"] in logic.REPLICATION_CHOICES
    assert logic.validate({"name": info["name"]}) == info["name"]
    assert logic.requested_options(make_params(**{o.param: info[o.param] for o in logic.ZONE_OPTIONS})) == SEEDED
