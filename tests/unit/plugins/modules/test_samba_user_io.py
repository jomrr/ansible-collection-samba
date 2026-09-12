# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_user LDB I/O layer.

A fake ``ldb`` module is injected, so these run without the samba bindings while
still exercising the real escaping and the concurrent-change (race) handling in
SambaUserIO."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_user


class FakeLdbError(Exception):
    """Stand-in for ldb.LdbError; args are (code, message)."""


class FakeMessage:
    """Minimal stand-in for ldb.Message."""

    def __init__(self):
        self.dn = None
        self.elements = {}

    def __setitem__(self, key, value):
        self.elements[key] = value


class FakeLdb:
    """Records escaping calls and provides the symbols SambaUserIO uses."""

    SCOPE_SUBTREE = 2
    SCOPE_BASE = 0
    FLAG_MOD_REPLACE = 2
    FLAG_MOD_DELETE = 3
    ERR_NO_SUCH_ATTRIBUTE = 16
    ERR_CONSTRAINT_VIOLATION = 19
    ERR_NO_SUCH_OBJECT = 32
    ERR_ENTRY_ALREADY_EXISTS = 68
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


class FoundMessage:
    """Stand-in for an ldb search result message."""

    def __init__(self, attrs, dn):
        self._attrs = attrs
        self.dn = dn

    def get(self, attr):
        return self._attrs.get(attr)


class FakeSamDB:
    """Configurable fake SamDB; raise_* inject errors for the race tests."""

    def __init__(self, search_result=None, newuser_error=None, modify_error=None, delete_error=None):
        self.search_result = [] if search_result is None else search_result
        self.newuser_error = newuser_error
        self.modify_error = modify_error
        self.delete_error = delete_error
        self.captured = {}
        self.modified = []
        self.deleted = []

    def domain_dn(self):
        return "DC=example,DC=com"

    def search(self, base, scope, expression, attrs):
        self.captured = {"base": base, "scope": scope, "expression": expression, "attrs": attrs}
        return self.search_result

    def newuser(self, username, password, **kwargs):
        if self.newuser_error is not None:
            raise self.newuser_error
        self.newuser_kwargs = kwargs

    def modify(self, message):
        if self.modify_error is not None:
            raise self.modify_error
        self.modified.append(message)

    def delete(self, dn):
        if self.delete_error is not None:
            raise self.delete_error
        self.deleted.append(dn)


_FAKE = {}


@pytest.fixture(autouse=True)
def _patch_ldb(monkeypatch):
    """Route the shared lazy ``ldb`` import to the fake ``make_io`` registers."""
    monkeypatch.setattr(samba_ldb, "load_ldb", lambda: _FAKE["ldb"])


def make_io(fake_ldb, samdb):
    _FAKE["ldb"] = fake_ldb
    return samba_user.SambaUserIO(samdb)


def test_read_current_escapes_filter_value():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB(search_result=[])
    make_io(fake_ldb, samdb).read_current("evil)(uid=*)")
    # The raw, attacker-controlled value must have been passed to the escaper...
    assert "evil)(uid=*)" in fake_ldb.encoded
    # ...and the filter must contain the escaped form, not the raw injection.
    assert "(sAMAccountName=ESC(evil)(uid=*))" in samdb.captured["expression"]
    assert samdb.captured["scope"] == fake_ldb.SCOPE_SUBTREE


def test_read_current_matches_only_user_accounts():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB(search_result=[])
    make_io(fake_ldb, samdb).read_current("DC1$")
    # Computer accounts carry objectClass=user too; the objectCategory clause
    # keeps them out, exactly like samba_user_info's query.
    assert "(objectCategory=person)" in samdb.captured["expression"]
    assert "(objectClass=user)" in samdb.captured["expression"]


def test_read_current_absent_returns_none():
    assert make_io(FakeLdb(), FakeSamDB(search_result=[])).read_current("ghost") is None


def test_read_current_parses_found_user():
    msg = FoundMessage(
        {
            "sAMAccountName": ["jdoe"],
            "givenName": ["Jane"],
            "userAccountControl": ["514"],  # 512 | 2 -> disabled
        },
        "CN=jdoe,DC=example,DC=com",
    )
    current = make_io(FakeLdb(), FakeSamDB(search_result=[msg])).read_current("jdoe")
    assert current["given_name"] == "Jane"
    assert current["enabled"] is False
    assert current["_dn"] == "CN=jdoe,DC=example,DC=com"
    assert current["_uac"] == 514


def test_create_user_collision_raises_clean():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB(newuser_error=FakeLdbError(FakeLdb.ERR_ENTRY_ALREADY_EXISTS, "exists"))
    with pytest.raises(logic.SambaUserError):
        make_io(fake_ldb, samdb).create_user("jdoe", "pw", None, {})


def test_create_user_other_ldberror_propagates():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB(newuser_error=FakeLdbError(999, "boom"))
    with pytest.raises(FakeLdbError):
        make_io(fake_ldb, samdb).create_user("jdoe", "pw", None, {})


def test_create_user_maps_attributes_onto_newuser():
    samdb = FakeSamDB()
    make_io(FakeLdb(), samdb).create_user(
        "jdoe", "pw", None,
        {"given_name": "Jane", "surname": "Doe", "email": "jane@example.com", "uid_number": 10001, "gecos": "Jane"},
    )
    assert samdb.newuser_kwargs == {
        "userou": None, "givenname": "Jane", "surname": "Doe", "mailaddress": "jane@example.com",
        "uidnumber": 10001, "gecos": "Jane",
    }


def test_create_attrs_match_what_the_io_maps():
    # The logic keeps display_name out of the add because newuser has no such
    # argument; the two lists must agree.
    assert set(logic.CREATE_ATTRS) == set(samba_user.SambaUserIO._NEWUSER_KWARGS)
    assert "display_name" not in logic.CREATE_ATTRS


def test_apply_attrs_vanished_raises_clean():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    with pytest.raises(logic.SambaUserError):
        make_io(fake_ldb, samdb).apply_attrs("CN=jdoe,DC=example,DC=com", {"given_name": "X"})


def test_set_enabled_vanished_raises_clean():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    with pytest.raises(logic.SambaUserError):
        make_io(fake_ldb, samdb).set_enabled("CN=jdoe,DC=example,DC=com", 512, False)


def test_delete_already_gone_returns_false():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB(delete_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    assert make_io(fake_ldb, samdb).delete("CN=jdoe,DC=example,DC=com") is False


def test_delete_success_returns_true():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB()
    assert make_io(fake_ldb, samdb).delete("CN=jdoe,DC=example,DC=com") is True
    assert samdb.deleted  # delete actually issued


def test_set_password_writes_unicode_pwd_by_dn():
    samdb = FakeSamDB()
    make_io(FakeLdb(), samdb).set_password("CN=jdoe,DC=example,DC=com", "pw")
    assert samdb.modified[0].dn == ("DN", "CN=jdoe,DC=example,DC=com")
    # samba's own encoding: the password in double quotes as UTF-16LE.
    assert samdb.modified[0].elements["unicodePwd"] == ('"pw"'.encode("utf-16-le"), FakeLdb.FLAG_MOD_REPLACE, "unicodePwd")


def test_set_password_vanished_raises_clean():
    # Written by DN, a concurrently removed user is ERR_NO_SUCH_OBJECT (an
    # error code, not the plain Exception samba's setpassword() raises).
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    with pytest.raises(logic.SambaUserError):
        make_io(FakeLdb(), samdb).set_password("CN=jdoe,DC=example,DC=com", "pw")


def test_set_password_policy_rejection_raises_clean():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_CONSTRAINT_VIOLATION, "0000052D: too short"))
    with pytest.raises(logic.SambaUserError):
        make_io(FakeLdb(), samdb).set_password("CN=jdoe,DC=example,DC=com", "pw")


def test_set_password_other_ldberror_propagates():
    samdb = FakeSamDB(modify_error=FakeLdbError(999, "boom"))
    with pytest.raises(FakeLdbError):
        make_io(FakeLdb(), samdb).set_password("CN=jdoe,DC=example,DC=com", "pw")


# --- removing attributes (empty string) ---

def test_apply_attrs_clears_with_an_empty_delete():
    samdb = FakeSamDB()
    make_io(FakeLdb(), samdb).apply_attrs("CN=jdoe,DC=example,DC=com", {"given_name": "Jane", "description": None})
    # The replace goes in one modify, the removal in its own (so an attribute
    # that is already gone cannot fail the replace).
    assert samdb.modified[0].elements == {"givenName": ("Jane", FakeLdb.FLAG_MOD_REPLACE, "givenName")}
    assert samdb.modified[1].elements == {"description": ([], FakeLdb.FLAG_MOD_DELETE, "description")}


def test_apply_attrs_clear_of_absent_attribute_is_noop():
    samdb = FakeSamDB(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_ATTRIBUTE, "no such attribute"))
    make_io(FakeLdb(), samdb).apply_attrs("CN=jdoe,DC=example,DC=com", {"description": None})


# --- RFC2307/POSIX attributes ---

def test_message_to_state_normalises_posix_integers():
    msg = FoundMessage(
        {
            "sAMAccountName": ["jdoe"],
            "uidNumber": ["10001"],
            "gidNumber": ["10000"],
            "loginShell": ["/bin/bash"],
            "userAccountControl": ["512"],
        },
        "CN=jdoe,DC=example,DC=com",
    )
    state = samba_user_io.message_to_state(msg)
    # Integer attrs come back as int (so the diff is int-vs-int, no artifact)...
    assert state["uid_number"] == 10001
    assert isinstance(state["uid_number"], int)
    assert state["gid_number"] == 10000
    # ...string attrs as str, and unset attrs as None (no error).
    assert state["login_shell"] == "/bin/bash"
    assert state["unix_home_directory"] is None
    assert state["gecos"] is None


def test_apply_attrs_writes_integer_as_decimal_string():
    samdb = FakeSamDB()
    make_io(FakeLdb(), samdb).apply_attrs("CN=jdoe,DC=example,DC=com", {"uid_number": 10001})
    written = samdb.modified[0].elements["uidNumber"]
    assert written == ("10001", FakeLdb.FLAG_MOD_REPLACE, "uidNumber")


class ExistsSamDB:
    """Fake SamDB for the rfc2307 provisioning probe (base-scope existence)."""

    def __init__(self, exists):
        self.exists = exists
        self.searched = []

    def domain_dn(self):
        return "DC=example,DC=com"

    def search(self, base, scope, attrs):
        self.searched.append((base, scope))
        if not self.exists:
            raise FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "no such object")
        return [FoundMessage({}, "CN=ypServ30,CN=RpcServices,CN=System,DC=example,DC=com")]


def test_rfc2307_provisioned_true(monkeypatch):
    monkeypatch.setattr(samba_ldb, "load_ldb", FakeLdb)
    samdb = ExistsSamDB(exists=True)
    assert samba_ldb.rfc2307_provisioned(samdb) is True
    # Probed the well-known fake-ypserver container with a base-scope search.
    assert samdb.searched and samdb.searched[0][1] == FakeLdb.SCOPE_BASE


def test_rfc2307_provisioned_false(monkeypatch):
    monkeypatch.setattr(samba_ldb, "load_ldb", FakeLdb)
    assert samba_ldb.rfc2307_provisioned(ExistsSamDB(exists=False)) is False
