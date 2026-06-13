# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the read-only samba_user_info module.

A fake ``ldb`` module and SamDB are injected, so these run in the sanity/units
container WITHOUT the samba bindings. Importing the module must also not require
samba."""

from __future__ import annotations

import pytest

from ansible.module_utils import basic
from ansible.module_utils.testing import patch_module_args

from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.modules import samba_user_info


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


def user_msg(name, **attrs):
    data = {"sAMAccountName": [name], "userAccountControl": ["512"]}
    for key, value in attrs.items():
        data[key] = [value]
    return FakeMessage(data, "CN=%s,CN=Users,DC=example,DC=com" % name)


def test_module_imports_without_samba():
    assert hasattr(samba_user_info, "main")


def test_query_escapes_filter_value(monkeypatch):
    fake_ldb = FakeLdb()
    monkeypatch.setattr(samba_user_io, "load_ldb", lambda: fake_ldb)
    samdb = FakeSamDB(result=[])
    samba_user_info.query(samdb, "evil)(uid=*)")
    # The raw value went through the escaper, and the filter carries the escaped
    # form rather than the raw injection.
    assert "evil)(uid=*)" in fake_ldb.encoded
    assert "(sAMAccountName=ESC(evil)(uid=*))" in samdb.captured["expression"]


def test_query_single_existing_user(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    samdb = FakeSamDB(result=[user_msg("jdoe", givenName="Jane", sn="Doe")])
    users = samba_user_info.query(samdb, "jdoe")
    assert len(users) == 1
    assert users[0]["username"] == "jdoe"
    assert users[0]["given_name"] == "Jane"
    assert users[0]["state"] == "present"


def test_query_single_missing_user_is_empty(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    assert samba_user_info.query(FakeSamDB(result=[]), "ghost") == []


def test_query_all_users_returns_list(monkeypatch):
    fake_ldb = FakeLdb()
    monkeypatch.setattr(samba_user_io, "load_ldb", lambda: fake_ldb)
    samdb = FakeSamDB(result=[user_msg("alice"), user_msg("bob")])
    users = samba_user_info.query(samdb, None)
    assert [u["username"] for u in users] == ["alice", "bob"]
    # No name filter and no escaping when listing all users.
    assert "sAMAccountName" not in samdb.captured["expression"]
    assert fake_ldb.encoded == []


class AnsibleExitJson(Exception):
    """Raised by the patched exit_json to capture the module result."""


def _exit_json(*args, **kwargs):
    raise AnsibleExitJson(kwargs)


def _run_main(monkeypatch, check_mode):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    monkeypatch.setattr(
        samba_user_info, "connect_samdb",
        lambda module: FakeSamDB(result=[user_msg("jdoe", givenName="Jane")]),
    )
    monkeypatch.setattr(basic.AnsibleModule, "exit_json", _exit_json)
    with patch_module_args({"_ansible_check_mode": check_mode}):
        with pytest.raises(AnsibleExitJson) as raised:
            samba_user_info.main()
    return raised.value.args[0]


def test_changed_is_false_and_check_mode_matches(monkeypatch):
    normal = _run_main(monkeypatch, False)
    check = _run_main(monkeypatch, True)
    assert normal["changed"] is False
    assert check["changed"] is False
    assert normal["users"] == check["users"]
