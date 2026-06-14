# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the read-only samba_group_info module.

A fake ``ldb`` module and SamDB are injected, so these run without the samba
bindings. Importing the module must also not require samba."""

from __future__ import annotations

import pytest

from ansible.module_utils import basic
from ansible.module_utils.testing import patch_module_args

from ansible_collections.jomrr.samba.plugins.module_utils import samba_group_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.modules import samba_group_info


class FakeMessage:
    """Stand-in for an ldb search result message."""

    def __init__(self, attrs, dn):
        self._attrs = attrs
        self.dn = dn

    def get(self, attr):
        return self._attrs.get(attr)


class FakeLdb:
    """Records escaping calls and provides the symbols the module uses."""

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

    def domain_dn(self):
        return "DC=example,DC=com"

    def search(self, base, scope, expression, attrs):
        self.captured = {"expression": expression, "scope": scope, "attrs": attrs}
        return self.result


def group_msg(name, group_type_value, **attrs):
    data = {"sAMAccountName": [name], "groupType": [str(group_type_value)]}
    for key, value in attrs.items():
        data[key] = value if isinstance(value, list) else [value]
    return FakeMessage(data, "CN=%s,CN=Users,DC=example,DC=com" % name)


def test_module_imports_without_samba():
    assert hasattr(samba_group_info, "main")


def test_query_escapes_filter_value(monkeypatch):
    fake_ldb = FakeLdb()
    monkeypatch.setattr(samba_user_io, "load_ldb", lambda: fake_ldb)
    samdb = FakeSamDB(result=[])
    samba_group_info.query(samdb, "evil)(uid=*)")
    assert "evil)(uid=*)" in fake_ldb.encoded
    assert "(objectClass=group)(sAMAccountName=ESC(evil)(uid=*))" in samdb.captured["expression"]


def test_query_all_groups_uses_objectclass_filter(monkeypatch):
    fake_ldb = FakeLdb()
    monkeypatch.setattr(samba_user_io, "load_ldb", lambda: fake_ldb)
    samdb = FakeSamDB(result=[group_msg("a", logic.group_type("global", "security"))])
    groups = samba_group_info.query(samdb, None)
    assert [g["name"] for g in groups] == ["a"]
    assert samdb.captured["expression"] == "(objectClass=group)"
    assert fake_ldb.encoded == []


def test_query_single_decodes_scope_and_category(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    samdb = FakeSamDB(result=[
        group_msg(
            "engineers", logic.group_type("global", "security"),
            description="staff", member=["CN=jdoe,DC=example,DC=com"],
        ),
    ])
    groups = samba_group_info.query(samdb, "engineers")
    assert len(groups) == 1
    group = groups[0]
    assert group["name"] == "engineers"
    assert group["scope"] == "global"
    assert group["category"] == "security"
    assert group["description"] == "staff"
    assert group["members"] == ["CN=jdoe,DC=example,DC=com"]
    assert group["state"] == "present"


@pytest.mark.parametrize("scope", ["global", "domain_local", "universal"])
@pytest.mark.parametrize("category", ["security", "distribution"])
def test_query_decode_roundtrip_matches_samba_group_encoding(monkeypatch, scope, category):
    # The info decode must agree with the encode samba_group uses as input.
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    samdb = FakeSamDB(result=[group_msg("g", logic.group_type(scope, category))])
    group = samba_group_info.query(samdb, "g")[0]
    assert (group["scope"], group["category"]) == (scope, category)


def test_query_decodes_signed_group_type(monkeypatch):
    # groupType stored signed (-2147483646) must decode to global/security.
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    samdb = FakeSamDB(result=[group_msg("g", -2147483646)])
    group = samba_group_info.query(samdb, "g")[0]
    assert (group["scope"], group["category"]) == ("global", "security")


def test_query_missing_group_is_empty(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    assert samba_group_info.query(FakeSamDB(result=[]), "ghost") == []


def test_query_returns_gid_number(monkeypatch):
    # Field name matches the samba_group write param, so _info round-trips back.
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    samdb = FakeSamDB(result=[
        group_msg("engineers", logic.group_type("global", "security"), gidNumber="10000"),
    ])
    group = samba_group_info.query(samdb, "engineers")[0]
    assert group["gid_number"] == 10000


def test_query_missing_gid_number_is_none(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    samdb = FakeSamDB(result=[group_msg("g", logic.group_type("global", "security"))])
    assert samba_group_info.query(samdb, "g")[0]["gid_number"] is None


class AnsibleExitJson(Exception):
    """Raised by the patched exit_json to capture the module result."""


def _exit_json(*args, **kwargs):
    raise AnsibleExitJson(kwargs)


def _run_main(monkeypatch, check_mode):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    monkeypatch.setattr(
        samba_group_info, "connect_samdb",
        lambda module: FakeSamDB(result=[group_msg("engineers", logic.group_type("global", "security"))]),
    )
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", _exit_json)
    with patch_module_args({"server": "dc.example.com", "bind_username": "Administrator", "bind_password": "secret", "_ansible_check_mode": check_mode}):
        with pytest.raises(AnsibleExitJson) as raised:
            samba_group_info.main()
    return raised.value.args[0]


def test_changed_is_false_and_check_mode_matches(monkeypatch):
    normal = _run_main(monkeypatch, False)
    check = _run_main(monkeypatch, True)
    assert normal["changed"] is False
    assert check["changed"] is False
    assert normal["groups"] == check["groups"]
