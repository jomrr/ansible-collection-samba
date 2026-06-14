# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the read-only samba_dns_record_info module.

The shared samba read helpers are faked, so these run without the bindings.
Importing the module must also not require samba."""

from __future__ import annotations

import pytest

from ansible.module_utils import basic
from ansible.module_utils.testing import patch_module_args

from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_record_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_dns_record_info as info


def test_module_imports_without_samba():
    assert hasattr(info, "main")


def test_query_single_name_decodes_each_type(monkeypatch):
    monkeypatch.setattr(samba_dns_io, "find_zone_dn", lambda samdb, zone: "ZONE_DN")
    specs = [
        {"type": "A", "value": "192.0.2.1", "ttl": 900},
        {"type": "MX", "value": "mail.example.com", "preference": 10, "ttl": 900},
        {"type": "SRV", "value": "s.example.com", "priority": 0, "weight": 100, "port": 389, "ttl": 600},
    ]
    monkeypatch.setattr(samba_dns_io, "read_name_specs", lambda samdb, zone_dn, name: list(specs))
    records = info.query(None, "example.com", "host", None)

    assert {r["type"] for r in records} == {"A", "MX", "SRV"}
    for record in records:
        assert record["zone"] == "example.com" and record["name"] == "host"
    mx = next(r for r in records if r["type"] == "MX")
    assert mx["preference"] == 10 and mx["value"] == "mail.example.com"
    srv = next(r for r in records if r["type"] == "SRV")
    assert (srv["priority"], srv["weight"], srv["port"]) == (0, 100, 389)
    # Plain types carry no structured fields.
    a_record = next(r for r in records if r["type"] == "A")
    assert "preference" not in a_record and "priority" not in a_record


def test_query_whole_zone(monkeypatch):
    monkeypatch.setattr(samba_dns_io, "find_zone_dn", lambda samdb, zone: "ZONE_DN")
    monkeypatch.setattr(samba_dns_io, "enumerate_zone_specs", lambda samdb, zone_dn: [
        ("www", {"type": "A", "value": "192.0.2.1", "ttl": 900}),
        ("@", {"type": "MX", "value": "mail.example.com", "preference": 10, "ttl": 900}),
        ("_ldap._tcp", {"type": "SRV", "value": "dc.example.com", "priority": 0, "weight": 100, "port": 389, "ttl": 900}),
    ])
    records = info.query(None, "example.com", None, None)
    assert [(r["name"], r["type"]) for r in records] == [("www", "A"), ("@", "MX"), ("_ldap._tcp", "SRV")]


def test_type_filter_restricts_results(monkeypatch):
    monkeypatch.setattr(samba_dns_io, "find_zone_dn", lambda samdb, zone: "ZONE_DN")
    monkeypatch.setattr(samba_dns_io, "read_name_specs", lambda samdb, zone_dn, name: [
        {"type": "A", "value": "192.0.2.1", "ttl": 900},
        {"type": "AAAA", "value": "2001:db8::1", "ttl": 900},
    ])
    records = info.query(None, "example.com", "www", "A")
    assert [r["type"] for r in records] == ["A"]


def test_name_without_records_is_empty(monkeypatch):
    monkeypatch.setattr(samba_dns_io, "find_zone_dn", lambda samdb, zone: "ZONE_DN")
    monkeypatch.setattr(samba_dns_io, "read_name_specs", lambda samdb, zone_dn, name: None)
    assert info.query(None, "example.com", "ghost", None) == []


def test_zone_missing_fails(monkeypatch):
    monkeypatch.setattr(samba_dns_io, "find_zone_dn", lambda samdb, zone: None)
    with pytest.raises(logic.SambaDnsRecordError):
        info.query(None, "nope.example.com", None, None)


@pytest.mark.parametrize("spec", [
    {"type": "A", "value": "192.0.2.1", "ttl": 900},
    {"type": "CNAME", "value": "www.example.com", "ttl": 900},
    {"type": "MX", "value": "mail.example.com", "preference": 10, "ttl": 900},
    {"type": "SRV", "value": "s.example.com", "priority": 0, "weight": 100, "port": 389, "ttl": 900},
    {"type": "TXT", "value": "v=spf1 -all", "ttl": 900},
], ids=lambda s: s["type"])
def test_info_record_roundtrips_as_write_input(spec):
    # An info record's per-type fields are exactly what samba_dns_record takes as
    # input: feeding them through the write module's validate() yields the same
    # record (the read mirror of the write semantics).
    record = info.public_record("example.com", "host", spec)
    params = {"type": record["type"], "value": record["value"], "ttl": record["ttl"],
              "preference": record.get("preference"), "priority": record.get("priority"),
              "weight": record.get("weight"), "port": record.get("port")}
    assert logic.records_equal(logic.validate(params), spec)


class AnsibleExitJson(Exception):
    """Raised by the patched exit_json to capture the module result."""


def _exit_json(*args, **kwargs):
    raise AnsibleExitJson(kwargs)


def _run_main(monkeypatch, check_mode):
    monkeypatch.setattr(samba_dns_io, "find_zone_dn", lambda samdb, zone: "ZONE_DN")
    monkeypatch.setattr(
        samba_dns_io, "read_name_specs",
        lambda samdb, zone_dn, name: [{"type": "A", "value": "192.0.2.1", "ttl": 900}],
    )
    monkeypatch.setattr(info, "connect_samdb", lambda module: object())
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", _exit_json)
    with patch_module_args({"zone": "example.com", "name": "www", "_ansible_check_mode": check_mode}):
        with pytest.raises(AnsibleExitJson) as raised:
            info.main()
    return raised.value.args[0]


def test_changed_is_false_and_check_mode_matches(monkeypatch):
    normal = _run_main(monkeypatch, False)
    check = _run_main(monkeypatch, True)
    assert normal["changed"] is False
    assert check["changed"] is False
    assert normal["records"] == check["records"]
