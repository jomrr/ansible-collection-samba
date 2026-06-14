# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the read-only samba_dns_zone_info module.

The shared samba read helpers are faked, so these run without the bindings.
Importing the module must also not require samba."""

from __future__ import annotations

import pytest

from ansible.module_utils import basic
from ansible.module_utils.testing import patch_module_args

from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_zone_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.modules import samba_dns_zone_info as info

DOMAIN_DN = "DC=example.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=com"
FOREST_DN = "DC=forest.example.com,CN=MicrosoftDNS,DC=ForestDnsZones,DC=example,DC=com"
REVERSE_DN = "DC=2.0.192.in-addr.arpa,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=com"


def test_module_imports_without_samba():
    assert hasattr(info, "main")


def test_query_single_domain_zone(monkeypatch):
    monkeypatch.setattr(samba_dns_io, "list_zone_entries",
                        lambda samdb, name: [("example.com", DOMAIN_DN)])
    zones = info.query(None, "example.com")
    assert len(zones) == 1
    assert zones[0]["name"] == "example.com"
    assert zones[0]["replication"] == "domain"
    assert zones[0]["reverse"] is False
    assert zones[0]["dn"] == DOMAIN_DN


def test_query_single_forest_zone(monkeypatch):
    monkeypatch.setattr(samba_dns_io, "list_zone_entries",
                        lambda samdb, name: [("forest.example.com", FOREST_DN)])
    zones = info.query(None, "forest.example.com")
    assert zones[0]["replication"] == "forest"
    assert zones[0]["reverse"] is False


def test_query_missing_zone_is_empty(monkeypatch):
    # Non-existence is not an error when querying (read-only convention).
    monkeypatch.setattr(samba_dns_io, "list_zone_entries", lambda samdb, name: [])
    assert info.query(None, "nope.example.com") == []


def test_query_all_zones_mixed_scopes(monkeypatch):
    monkeypatch.setattr(samba_dns_io, "list_zone_entries", lambda samdb, name: [
        ("example.com", DOMAIN_DN),
        ("forest.example.com", FOREST_DN),
        ("2.0.192.in-addr.arpa", REVERSE_DN),
    ])
    zones = info.query(None, None)
    assert [z["name"] for z in zones] == ["example.com", "forest.example.com", "2.0.192.in-addr.arpa"]
    assert [z["replication"] for z in zones] == ["domain", "forest", "domain"]
    assert [z["reverse"] for z in zones] == [False, False, True]


def test_info_zone_roundtrips_as_write_input(monkeypatch):
    # A returned entry carries the field names samba_dns_zone takes as input.
    monkeypatch.setattr(samba_dns_io, "list_zone_entries",
                        lambda samdb, name: [("example.com", DOMAIN_DN)])
    zone = info.query(None, "example.com")[0]
    assert logic.validate({"name": zone["name"]}) == zone["name"]
    assert zone["replication"] in logic.REPLICATION_CHOICES


# --- list_zone_entries: real filter construction (escaping regression) ---

class FakeMessage:
    """Stand-in for an ldb search result message."""

    def __init__(self, name, dn):
        self._attrs = {"name": [name]}
        self.dn = dn

    def get(self, attr):
        return self._attrs.get(attr)


class FakeLdb:
    """Records escaping calls and provides the symbols list_zone_entries uses."""

    SCOPE_SUBTREE = 2

    def __init__(self):
        self.encoded = []

    def binary_encode(self, value):
        self.encoded.append(value)
        return "ESC(%s)" % value


class FakeSamDB:
    """Captures the search expression and returns canned messages."""

    def __init__(self, result=None):
        self.result = [] if result is None else result
        self.captured = {}

    def search(self, base, scope, expression, attrs, controls):
        self.captured = {"base": base, "expression": expression, "controls": controls}
        return self.result


def test_list_zone_entries_escapes_filter_value(monkeypatch):
    fake_ldb = FakeLdb()
    monkeypatch.setattr(samba_user_io, "load_ldb", lambda: fake_ldb)
    samdb = FakeSamDB(result=[])
    samba_dns_io.list_zone_entries(samdb, "evil)(objectClass=*)")
    assert "evil)(objectClass=*)" in fake_ldb.encoded
    assert "(name=ESC(evil)(objectClass=*))" in samdb.captured["expression"]
    # The phantom-root control is set so the DNS application partitions are reached.
    assert samdb.captured["controls"] == ["search_options:0:2"]


def test_list_zone_entries_all_uses_objectclass_filter(monkeypatch):
    fake_ldb = FakeLdb()
    monkeypatch.setattr(samba_user_io, "load_ldb", lambda: fake_ldb)
    samdb = FakeSamDB(result=[FakeMessage("example.com", DOMAIN_DN)])
    entries = samba_dns_io.list_zone_entries(samdb, None)
    assert entries == [("example.com", DOMAIN_DN)]
    assert samdb.captured["expression"] == "(objectClass=dnsZone)"
    assert fake_ldb.encoded == []


class AnsibleExitJson(Exception):
    """Raised by the patched exit_json to capture the module result."""


def _exit_json(*args, **kwargs):
    raise AnsibleExitJson(kwargs)


def _run_main(monkeypatch, check_mode):
    monkeypatch.setattr(samba_dns_io, "list_zone_entries",
                        lambda samdb, name: [("example.com", DOMAIN_DN)])
    monkeypatch.setattr(info, "connect_samdb", lambda module: object())
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", _exit_json)
    args = {
        "server": "dc.example.com", "bind_username": "Administrator", "bind_password": "secret",
        "name": "example.com", "_ansible_check_mode": check_mode,
    }
    with patch_module_args(args):
        with pytest.raises(AnsibleExitJson) as raised:
            info.main()
    return raised.value.args[0]


def test_changed_is_false_and_check_mode_matches(monkeypatch):
    normal = _run_main(monkeypatch, False)
    check = _run_main(monkeypatch, True)
    assert normal["changed"] is False
    assert check["changed"] is False
    assert normal["zones"] == check["zones"]
