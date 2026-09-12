# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_group LDB I/O layer.

A fake ``ldb`` module is injected (via samba_ldb.load_ldb), so these run
without the samba bindings while exercising the real escaping, the groupType
write encoding, and the concurrent-change (race) handling."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_group_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb
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

    SCOPE_BASE = 0
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
        if "INVALID" in dn:
            raise ValueError("not a valid dn")
        return ("DN", dn)

    def MessageElement(self, value, flag, name):
        return (value, flag, name)


class FakeSamDB:
    """Configurable fake SamDB; *_error inject errors for the race tests."""

    def __init__(self, search_result=None, newgroup_error=None, modify_error=None, delete_error=None, lookups=None):
        self.search_result = [] if search_result is None else search_result
        #: Base-scoped reads: DN text -> messages; a DN not listed does not exist.
        self.lookups = lookups or {}
        self.newgroup_error = newgroup_error
        self.modify_error = modify_error
        self.delete_error = delete_error
        self.captured = {}
        self.modified = []
        self.deleted = []
        self.created = []
        self.searches = []

    def domain_dn(self):
        return "DC=example,DC=com"

    def search(self, base, scope, expression=None, attrs=None):
        self.captured = {"base": base, "scope": scope, "expression": expression, "attrs": attrs}
        self.searches.append(self.captured)
        if scope == FakeLdb.SCOPE_BASE:
            if base[1] not in self.lookups:
                raise FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "no such object")
            return self.lookups[base[1]]
        return self.search_result

    def newgroup(self, name, groupou=None, grouptype=None, description=None, gidnumber=None):
        if self.newgroup_error is not None:
            raise self.newgroup_error
        self.created.append((name, groupou, grouptype, description, gidnumber))

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
    monkeypatch.setattr(samba_ldb, "load_ldb", FakeLdb)


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


def _account(name, dn):
    return FakeMessage({"sAMAccountName": [name]}, dn)


def test_resolve_members_one_escaped_or_search_for_all_names():
    samdb = FakeSamDB(search_result=[
        _account("jd)(oe", "CN=jdoe,DC=example,DC=com"),
        _account("asmith", "CN=asmith,DC=example,DC=com"),
    ])
    dns = make_io(samdb).resolve_members(["jd)(oe", "asmith"])
    assert dns == ["CN=jdoe,DC=example,DC=com", "CN=asmith,DC=example,DC=com"]
    # One search for all names, every name escaped inside the OR filter.
    assert len(samdb.searches) == 1
    assert samdb.captured["expression"] == "(|(sAMAccountName=ESC(jd)(oe))(sAMAccountName=ESC(asmith)))"


def test_resolve_members_maps_results_back_case_insensitively():
    samdb = FakeSamDB(search_result=[_account("jdoe", "CN=jdoe,DC=example,DC=com")])
    assert make_io(samdb).resolve_members(["JDoe"]) == ["CN=jdoe,DC=example,DC=com"]


def test_resolve_members_reports_every_missing_name_at_once():
    samdb = FakeSamDB(search_result=[_account("jdoe", "CN=jdoe,DC=example,DC=com")])
    with pytest.raises(logic.SambaGroupError) as raised:
        make_io(samdb).resolve_members(["jdoe", "ghost1", "ghost2"])
    assert "ghost1" in str(raised.value)
    assert "ghost2" in str(raised.value)


def test_resolve_members_takes_dns_in_the_directory_spelling():
    # A DN (samba_group_info's output) is looked up once, base-scoped, and
    # returned as the directory spells it; a name still goes through the search.
    samdb = FakeSamDB(
        search_result=[_account("jdoe", "CN=jdoe,DC=example,DC=com")],
        lookups={"cn=other, ou=eng,dc=example,dc=com": [FakeMessage(dn="CN=Other,OU=Eng,DC=example,DC=com")]},
    )
    dns = make_io(samdb).resolve_members(["cn=other, ou=eng,dc=example,dc=com", "jdoe"])
    assert dns == ["CN=Other,OU=Eng,DC=example,DC=com", "CN=jdoe,DC=example,DC=com"]
    scopes = [search["scope"] for search in samdb.searches]
    assert scopes.count(FakeLdb.SCOPE_BASE) == 1
    assert scopes.count(FakeLdb.SCOPE_SUBTREE) == 1


def test_resolve_members_reports_a_missing_dn_like_a_missing_name():
    samdb = FakeSamDB(search_result=[_account("jdoe", "CN=jdoe,DC=example,DC=com")])
    with pytest.raises(logic.SambaGroupError) as raised:
        make_io(samdb).resolve_members(["jdoe", "CN=Ghost,DC=example,DC=com"])
    assert "CN=Ghost,DC=example,DC=com" in str(raised.value)


def test_resolve_members_rejects_a_malformed_dn():
    with pytest.raises(logic.SambaGroupError):
        make_io(FakeSamDB()).resolve_members(["INVALID=DN"])


def test_resolve_members_batches_large_lists(monkeypatch):
    monkeypatch.setattr(samba_group.SambaGroupIO, "_RESOLVE_BATCH", 2)
    samdb = FakeSamDB(search_result=[
        _account("a", "CN=a,DC=example,DC=com"),
        _account("b", "CN=b,DC=example,DC=com"),
        _account("c", "CN=c,DC=example,DC=com"),
    ])
    make_io(samdb).resolve_members(["a", "b", "c"])
    assert len(samdb.searches) == 2


def test_create_group_collision_raises_clean():
    samdb = FakeSamDB(newgroup_error=FakeLdbError(FakeLdb.ERR_ENTRY_ALREADY_EXISTS, "exists"))
    with pytest.raises(logic.SambaGroupError):
        make_io(samdb).create_group("engineers", logic.group_type("global", "security"), None, None, None)


def test_create_group_passes_gid_and_type_to_newgroup():
    # gidNumber goes onto the add itself (newgroup takes it); no modify follows.
    samdb = FakeSamDB()
    make_io(samdb).create_group("engineers", logic.group_type("global", "security"), "staff", None, 10000)
    assert samdb.created == [("engineers", None, logic.group_type("global", "security"), "staff", 10000)]
    assert samdb.modified == []


def test_set_group_type_writes_signed_form():
    samdb = FakeSamDB()
    make_io(samdb).set_group_type("CN=g,DC=example,DC=com", logic.group_type("global", "security"))
    written = samdb.modified[0].elements["groupType"]
    assert written == ("-2147483646", FakeLdb.FLAG_MOD_REPLACE, "groupType")


def test_set_group_type_invalid_transition_raises_clean():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_UNWILLING_TO_PERFORM, "no"))
    with pytest.raises(logic.SambaGroupError):
        make_io(samdb).set_group_type("CN=g,DC=example,DC=com", logic.group_type("universal", "security"))


def test_set_description_none_removes_the_attribute():
    samdb = FakeSamDB()
    make_io(samdb).set_description("CN=g,DC=example,DC=com", None)
    assert samdb.modified[0].elements["description"] == ([], FakeLdb.FLAG_MOD_DELETE, "description")


def test_set_description_remove_of_absent_attribute_is_noop():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_ATTRIBUTE, "no such attribute"))
    make_io(samdb).set_description("CN=g,DC=example,DC=com", None)


def test_set_description_replace_does_not_swallow_no_such_attribute():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_ATTRIBUTE, "odd"))
    with pytest.raises(FakeLdbError):
        make_io(samdb).set_description("CN=g,DC=example,DC=com", "new")


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


def test_delete_already_gone_returns_false():
    samdb = FakeSamDB(delete_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    assert make_io(samdb).delete("CN=g,DC=example,DC=com") is False


def test_delete_success_returns_true():
    samdb = FakeSamDB()
    assert make_io(samdb).delete("CN=g,DC=example,DC=com") is True
    assert samdb.deleted
