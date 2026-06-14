# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the read-only samba_ou_info module.

A fake ``ldb`` module and SamDB are injected, so these run without the samba
bindings. Importing the module must also not require samba."""

from __future__ import annotations

import pytest

from ansible.module_utils import basic
from ansible.module_utils.testing import patch_module_args

from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.modules import samba_ou_info


class FakeLdbError(Exception):
    """Stand-in for ldb.LdbError; args are (code, message)."""


class FakeDn:
    """Minimal ldb.Dn stand-in: name comes from the RDN, path from the parent."""

    def __init__(self, dn):
        self._dn = dn

    def __str__(self):
        return self._dn

    def get_rdn_value(self):
        return self._dn.split(",", 1)[0].split("=", 1)[1]

    def parent(self):
        return FakeDn(self._dn.split(",", 1)[1])


class FakeMessage:
    """Stand-in for an ldb search result message."""

    def __init__(self, attrs, dn):
        self._attrs = attrs
        self.dn = FakeDn(dn)

    def get(self, attr):
        return self._attrs.get(attr)


class FakeLdb:
    """Records escaping calls and provides the symbols the module uses."""

    SCOPE_ONELEVEL = 1
    SCOPE_SUBTREE = 2
    ERR_NO_SUCH_OBJECT = 32
    LdbError = FakeLdbError

    def __init__(self):
        self.encoded = []

    def binary_encode(self, value):
        self.encoded.append(value)
        return "ESC(%s)" % value


class FakeSamDB:
    """Captures the search arguments and returns canned messages."""

    def __init__(self, result=None, search_error=None):
        self.result = [] if result is None else result
        self.search_error = search_error
        self.captured = {}

    def domain_dn(self):
        return "DC=example,DC=com"

    def search(self, base, scope, expression, attrs):
        self.captured = {"base": base, "scope": scope, "expression": expression, "attrs": attrs}
        if self.search_error is not None:
            raise self.search_error
        return self.result


def ou_msg(dn, description=None):
    attrs = {} if description is None else {"description": [description]}
    return FakeMessage(attrs, dn)


def test_module_imports_without_samba():
    assert hasattr(samba_ou_info, "main")


def test_query_escapes_filter_value(monkeypatch):
    # The attacker-controlled name must go through the escaper, and the filter
    # must carry the escaped form rather than the raw injection.
    fake_ldb = FakeLdb()
    monkeypatch.setattr(samba_user_io, "load_ldb", lambda: fake_ldb)
    samdb = FakeSamDB(result=[])
    samba_ou_info.query(samdb, "evil)(uid=*)", "DC=example,DC=com")
    assert "evil)(uid=*)" in fake_ldb.encoded
    assert "(objectClass=organizationalUnit)(ou=ESC(evil)(uid=*))" in samdb.captured["expression"]
    assert samdb.captured["scope"] == FakeLdb.SCOPE_ONELEVEL
    assert samdb.captured["base"] == "DC=example,DC=com"


def test_query_single_existing(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    samdb = FakeSamDB(result=[ou_msg("OU=Staff,DC=example,DC=com", description="All staff")])
    ous = samba_ou_info.query(samdb, "Staff", "DC=example,DC=com")
    assert len(ous) == 1
    assert ous[0]["name"] == "Staff"
    assert ous[0]["path"] == "DC=example,DC=com"
    assert ous[0]["dn"] == "OU=Staff,DC=example,DC=com"
    assert ous[0]["description"] == "All staff"
    assert ous[0]["state"] == "present"


def test_query_single_missing_is_empty(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    assert samba_ou_info.query(FakeSamDB(result=[]), "ghost", "DC=example,DC=com") == []


def test_query_missing_base_is_empty(monkeypatch):
    # A non-existent search base raises NO_SUCH_OBJECT, reported as no matches.
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    samdb = FakeSamDB(search_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    assert samba_ou_info.query(samdb, "x", "OU=Missing,DC=example,DC=com") == []


def test_query_all_ous_returns_list(monkeypatch):
    fake_ldb = FakeLdb()
    monkeypatch.setattr(samba_user_io, "load_ldb", lambda: fake_ldb)
    samdb = FakeSamDB(result=[
        ou_msg("OU=a,DC=example,DC=com"),
        ou_msg("OU=b,OU=a,DC=example,DC=com"),
    ])
    ous = samba_ou_info.query(samdb, None, None)
    assert [o["name"] for o in ous] == ["a", "b"]
    assert ous[1]["path"] == "OU=a,DC=example,DC=com"
    # No name filter, no escaping, subtree scope, domain root as the default base.
    assert samdb.captured["expression"] == "(objectClass=organizationalUnit)"
    assert samdb.captured["scope"] == FakeLdb.SCOPE_SUBTREE
    assert samdb.captured["base"] == "DC=example,DC=com"
    assert fake_ldb.encoded == []


def test_query_all_under_explicit_path(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    samdb = FakeSamDB(result=[])
    samba_ou_info.query(samdb, None, "OU=Staff,DC=example,DC=com")
    assert samdb.captured["base"] == "OU=Staff,DC=example,DC=com"
    assert samdb.captured["scope"] == FakeLdb.SCOPE_SUBTREE


class AnsibleExitJson(Exception):
    """Raised by the patched exit_json to capture the module result."""


def _exit_json(*args, **kwargs):
    raise AnsibleExitJson(kwargs)


def _run_main(monkeypatch, check_mode):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    monkeypatch.setattr(
        samba_ou_info, "connect_samdb",
        lambda module: FakeSamDB(result=[ou_msg("OU=Staff,DC=example,DC=com", description="All staff")]),
    )
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", _exit_json)
    with patch_module_args({"server": "dc.example.com", "bind_username": "Administrator", "bind_password": "secret", "_ansible_check_mode": check_mode}):
        with pytest.raises(AnsibleExitJson) as raised:
            samba_ou_info.main()
    return raised.value.args[0]


def test_changed_is_false_and_check_mode_matches(monkeypatch):
    normal = _run_main(monkeypatch, False)
    check = _run_main(monkeypatch, True)
    assert normal["changed"] is False
    assert check["changed"] is False
    assert normal["ous"] == check["ous"]
