# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_group LDB I/O layer.

A fake ``ldb`` module is injected (via samba_user_io.load_ldb), so these run
without the samba bindings while exercising the real escaping, the groupType
write encoding, and the concurrent-change (race) handling."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_group_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.modules import samba_group


class FakeLdbError(Exception):
    """Stand-in for ldb.LdbError; args are (code, message)."""


class FakeMessage:
    """Minimal stand-in for ldb.Message (write) and search result (read)."""

    def __init__(self, attrs=None, dn=None):
        self._attrs = attrs or {}
        self.dn = dn
        self.elements = {}

    def get(self, attr):
        return self._attrs.get(attr)

    def __setitem__(self, key, value):
        self.elements[key] = value


class FakeLdb:
    """Provides the symbols SambaGroupIO uses; records escaping calls."""

    SCOPE_SUBTREE = 2
    FLAG_MOD_ADD = 1
    FLAG_MOD_REPLACE = 2
    FLAG_MOD_DELETE = 3
    ERR_NO_SUCH_OBJECT = 32
    ERR_ENTRY_ALREADY_EXISTS = 68
    ERR_ATTRIBUTE_OR_VALUE_EXISTS = 20
    ERR_NO_SUCH_ATTRIBUTE = 16
    ERR_UNWILLING_TO_PERFORM = 53
    ERR_CONSTRAINT_VIOLATION = 19
    LdbError = FakeLdbError

    def __init__(self):
        self.encoded = []

    def binary_encode(self, value):
        self.encoded.append(value)
        return "ESC(%s)" % value

    def Message(self):
        return FakeMessage()

    def Dn(self, samdb, dn):
        return ("DN", dn)

    def MessageElement(self, value, flag, name):
        return (value, flag, name)


class FakeSamDB:
    """Configurable fake SamDB; *_error inject errors for the race tests."""

    def __init__(self, search_result=None, newgroup_error=None, modify_error=None, delete_error=None):
        self.search_result = [] if search_result is None else search_result
        self.newgroup_error = newgroup_error
        self.modify_error = modify_error
        self.delete_error = delete_error
        self.captured = {}
        self.modified = []
        self.deleted = []
        self.created = []

    def domain_dn(self):
        return "DC=example,DC=com"

    def search(self, base, scope, expression, attrs):
        self.captured = {"base": base, "scope": scope, "expression": expression, "attrs": attrs}
        return self.search_result

    def newgroup(self, name, grouptype=None, description=None):
        if self.newgroup_error is not None:
            raise self.newgroup_error
        self.created.append((name, grouptype, description))

    def modify(self, message):
        if self.modify_error is not None:
            raise self.modify_error
        self.modified.append(message)

    def delete(self, dn):
        if self.delete_error is not None:
            raise self.delete_error
        self.deleted.append(dn)


@pytest.fixture(autouse=True)
def _patch_ldb(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)


def make_io(samdb):
    return samba_group.SambaGroupIO(samdb)


def test_read_current_escapes_filter_and_parses():
    msg = FakeMessage(
        {
            "sAMAccountName": ["engineers"],
            "groupType": ["-2147483646"],
            "description": ["staff"],
            "member": ["CN=a,DC=example,DC=com", "CN=b,DC=example,DC=com"],
        },
        "CN=engineers,DC=example,DC=com",
    )
    samdb = FakeSamDB(search_result=[msg])
    current = make_io(samdb).read_current("ev)(il")
    assert "(objectClass=group)(sAMAccountName=ESC(ev)(il))" in samdb.captured["expression"]
    assert current["group_type"] == -2147483646
    assert current["description"] == "staff"
    assert current["members"] == ["CN=a,DC=example,DC=com", "CN=b,DC=example,DC=com"]


def test_read_current_absent_returns_none():
    assert make_io(FakeSamDB(search_result=[])).read_current("ghost") is None


def test_resolve_member_escapes_and_returns_dn():
    msg = FakeMessage(dn="CN=jdoe,DC=example,DC=com")
    samdb = FakeSamDB(search_result=[msg])
    dn = make_io(samdb).resolve_member("jd)(oe")
    assert dn == "CN=jdoe,DC=example,DC=com"
    assert samdb.captured["expression"] == "(sAMAccountName=ESC(jd)(oe))"


def test_resolve_member_not_found_raises():
    with pytest.raises(logic.SambaGroupError):
        make_io(FakeSamDB(search_result=[])).resolve_member("ghost")


def test_create_group_collision_raises_clean():
    samdb = FakeSamDB(newgroup_error=FakeLdbError(FakeLdb.ERR_ENTRY_ALREADY_EXISTS, "exists"))
    with pytest.raises(logic.SambaGroupError):
        make_io(samdb).create_group("engineers", logic.group_type("global", "security"), None)


def test_set_group_type_writes_signed_form():
    samdb = FakeSamDB()
    make_io(samdb).set_group_type("CN=g,DC=example,DC=com", logic.group_type("global", "security"))
    written = samdb.modified[0].elements["groupType"]
    assert written == ("-2147483646", FakeLdb.FLAG_MOD_REPLACE, "groupType")


def test_set_group_type_invalid_transition_raises_clean():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_UNWILLING_TO_PERFORM, "no"))
    with pytest.raises(logic.SambaGroupError):
        make_io(samdb).set_group_type("CN=g,DC=example,DC=com", logic.group_type("universal", "security"))


def test_set_gid_number_writes_decimal_string():
    samdb = FakeSamDB()
    make_io(samdb).set_gid_number("CN=g,DC=example,DC=com", 10000)
    written = samdb.modified[0].elements["gidNumber"]
    assert written == ("10000", FakeLdb.FLAG_MOD_REPLACE, "gidNumber")


def test_set_gid_number_vanished_raises_clean():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    with pytest.raises(logic.SambaGroupError):
        make_io(samdb).set_gid_number("CN=g,DC=example,DC=com", 10000)


def test_read_current_parses_gid_number():
    msg = FakeMessage(
        {"sAMAccountName": ["g"], "groupType": ["-2147483646"], "gidNumber": ["10000"]},
        "CN=g,DC=example,DC=com",
    )
    current = make_io(FakeSamDB(search_result=[msg])).read_current("g")
    assert current["gid_number"] == 10000


def test_add_member_collision_is_noop():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_ATTRIBUTE_OR_VALUE_EXISTS, "exists"))
    assert make_io(samdb).add_member("CN=g,DC=example,DC=com", "CN=a,DC=example,DC=com") is False


def test_remove_member_vanished_is_noop():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_ATTRIBUTE, "gone"))
    assert make_io(samdb).remove_member("CN=g,DC=example,DC=com", "CN=a,DC=example,DC=com") is False


def test_member_op_group_vanished_raises_clean():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    with pytest.raises(logic.SambaGroupError):
        make_io(samdb).add_member("CN=g,DC=example,DC=com", "CN=a,DC=example,DC=com")


def test_add_member_success_returns_true():
    samdb = FakeSamDB()
    assert make_io(samdb).add_member("CN=g,DC=example,DC=com", "CN=a,DC=example,DC=com") is True
    assert samdb.modified


def test_delete_group_already_gone_returns_false():
    samdb = FakeSamDB(delete_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    assert make_io(samdb).delete_group("CN=g,DC=example,DC=com") is False


def test_delete_group_success_returns_true():
    samdb = FakeSamDB()
    assert make_io(samdb).delete_group("CN=g,DC=example,DC=com") is True
    assert samdb.deleted
