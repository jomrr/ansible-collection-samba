# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_ou LDB I/O layer.

A fake ``ldb`` module is injected (via samba_ldb.load_ldb), so these run
without the samba bindings while exercising the safe DN construction and the
concurrent-change (race) handling."""

from __future__ import annotations

import pytest
from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_ou_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_ou


class FakeLdbError(Exception):
    """Stand-in for ldb.LdbError; args are (code, message)."""


class FakeDn:
    """Records set_component calls so tests can prove the name is escaped, not concatenated."""

    def __init__(self, text):
        self.components = [text]
        self.base = None
        self.set_calls = []

    def set_component(self, num, name, value):
        self.set_calls.append((num, name, value))
        self.components[num] = f"{name}={value}"

    def add_base(self, parent):
        self.base = parent

    def __str__(self):
        text = ",".join(self.components)
        return text + "," + str(self.base) if self.base is not None else text


class FakeMessage:
    def __init__(self, attrs=None, dn=None):
        self._attrs = attrs or {}
        self.dn = dn
        self.elements = {}

    def get(self, attr):
        return self._attrs.get(attr)

    def __setitem__(self, key, value):
        self.elements[key] = value


class FakeLdb:
    SCOPE_BASE = 0
    SCOPE_ONELEVEL = 1
    FLAG_MOD_REPLACE = 2
    FLAG_MOD_DELETE = 3
    ERR_NO_SUCH_ATTRIBUTE = 16
    ERR_NO_SUCH_OBJECT = 32
    ERR_INSUFFICIENT_ACCESS_RIGHTS = 50
    ERR_UNWILLING_TO_PERFORM = 53
    ERR_ENTRY_ALREADY_EXISTS = 68
    ERR_NOT_ALLOWED_ON_NON_LEAF = 66
    LdbError = FakeLdbError

    def Dn(self, samdb, text):
        if "INVALID" in text:
            raise ValueError("not a valid dn")
        return FakeDn(text)

    def Message(self):
        return FakeMessage()

    def MessageElement(self, value, flag, name):
        return (value, flag, name)


class FakeSamDB:
    def __init__(self, search_result=None, search_error=None, create_error=None,
                 modify_error=None, delete_error=None):
        self.search_result = [] if search_result is None else search_result
        self.search_error = search_error
        self.create_error = create_error
        self.modify_error = modify_error
        self.delete_error = delete_error
        self.created = []
        self.deleted = []
        self.modified = []

    def search(self, base, scope, attrs):
        if self.search_error is not None:
            raise self.search_error
        return self.search_result

    def create_ou(self, dn, description=None):
        if self.create_error is not None:
            raise self.create_error
        self.created.append((str(dn), description))

    def modify(self, message):
        if self.modify_error is not None:
            raise self.modify_error
        self.modified.append(message)

    def delete(self, dn):
        if self.delete_error is not None:
            raise self.delete_error
        self.deleted.append(str(dn))


@pytest.fixture(autouse=True)
def _patch_ldb(monkeypatch):
    monkeypatch.setattr(samba_ldb, "load_ldb", FakeLdb)


def make_io(samdb):
    return samba_ou.SambaOuIO(samdb)


def test_dn_built_via_set_component_escapes_name():
    # The attacker-controlled name must go through set_component (which ldb
    # escapes), never raw string concatenation into the DN.
    dn = make_io(FakeSamDB())._ou_dn("ev,il=x", "DC=example,DC=com")
    assert (0, "OU", "ev,il=x") in dn.set_calls


def test_invalid_path_raises_clean():
    with pytest.raises(logic.SambaOuError):
        make_io(FakeSamDB())._ou_dn("Staff", "INVALID PATH")


def test_parent_exists_true_and_false():
    present = FakeSamDB(search_result=[FakeMessage(dn="OU=Staff,DC=example,DC=com")])
    assert make_io(present).parent_exists("OU=Staff,DC=example,DC=com") is True
    samdb = FakeSamDB(search_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    assert make_io(samdb).parent_exists("OU=Missing,DC=example,DC=com") is False


def test_parent_exists_invalid_path_raises_clean():
    with pytest.raises(logic.SambaOuError):
        make_io(FakeSamDB()).parent_exists("INVALID PATH")


def test_read_current_absent_returns_none():
    samdb = FakeSamDB(search_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    assert make_io(samdb).read_current("Staff", "DC=example,DC=com") is None


def test_read_current_parses_description():
    msg = FakeMessage({"description": ["staff"]}, dn="OU=Staff,DC=example,DC=com")
    current = make_io(FakeSamDB(search_result=[msg])).read_current("Staff", "DC=example,DC=com")
    assert current["description"] == "staff"
    assert current["_dn"] == "OU=Staff,DC=example,DC=com"


def test_create_collision_raises_clean():
    samdb = FakeSamDB(create_error=FakeLdbError(FakeLdb.ERR_ENTRY_ALREADY_EXISTS, "exists"))
    with pytest.raises(logic.SambaOuError):
        make_io(samdb).create_ou("Staff", "DC=example,DC=com", None)


def test_create_missing_parent_raises_clean():
    samdb = FakeSamDB(create_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "no parent"))
    with pytest.raises(logic.SambaOuError):
        make_io(samdb).create_ou("Staff", "OU=Missing,DC=example,DC=com", None)


def test_set_description_vanished_raises_clean():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    with pytest.raises(logic.SambaOuError):
        make_io(samdb).set_description("OU=Staff,DC=example,DC=com", "new")


def test_set_description_none_removes_the_attribute():
    samdb = FakeSamDB()
    make_io(samdb).set_description("OU=Staff,DC=example,DC=com", None)
    assert samdb.modified[0].elements["description"] == ([], FakeLdb.FLAG_MOD_DELETE, "description")


def test_set_description_remove_of_absent_attribute_is_noop():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_ATTRIBUTE, "no such attribute"))
    make_io(samdb).set_description("OU=Staff,DC=example,DC=com", None)


def test_set_description_replace_does_not_swallow_no_such_attribute():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_ATTRIBUTE, "odd"))
    with pytest.raises(FakeLdbError):
        make_io(samdb).set_description("OU=Staff,DC=example,DC=com", "new")


def test_delete_already_gone_returns_false():
    samdb = FakeSamDB(delete_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    assert make_io(samdb).delete_ou("OU=Staff,DC=example,DC=com") is False


def test_delete_non_empty_raises_clean():
    samdb = FakeSamDB(delete_error=FakeLdbError(FakeLdb.ERR_NOT_ALLOWED_ON_NON_LEAF, "not leaf"))
    with pytest.raises(logic.SambaOuError):
        make_io(samdb).delete_ou("OU=Staff,DC=example,DC=com")


def test_delete_protected_by_system_flags_raises_clean():
    samdb = FakeSamDB(delete_error=FakeLdbError(
        FakeLdb.ERR_UNWILLING_TO_PERFORM, "objectclass: Cannot delete OU=Staff,DC=example,DC=com: protected"))
    with pytest.raises(logic.SambaOuError) as raised:
        make_io(samdb).delete_ou("OU=Staff,DC=example,DC=com")
    assert "protected" in str(raised.value)
    # The ldb message itself, not the (code, message) tuple.
    assert "(53, " not in str(raised.value)


def test_delete_without_permission_raises_clean():
    samdb = FakeSamDB(delete_error=FakeLdbError(FakeLdb.ERR_INSUFFICIENT_ACCESS_RIGHTS, "access denied"))
    with pytest.raises(logic.SambaOuError) as raised:
        make_io(samdb).delete_ou("OU=Staff,DC=example,DC=com")
    assert "may not delete" in str(raised.value)


def test_delete_success_returns_true():
    samdb = FakeSamDB()
    assert make_io(samdb).delete_ou("OU=Staff,DC=example,DC=com") is True
    assert samdb.deleted
