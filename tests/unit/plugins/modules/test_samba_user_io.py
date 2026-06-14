# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_user LDB I/O layer.

A fake ``ldb`` module is injected, so these run without the samba bindings while
still exercising the real escaping and the concurrent-change (race) handling in
SambaUserIO."""

from __future__ import annotations

import pytest

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

    def __init__(self, search_result=None, newuser_error=None, modify_error=None,
                 delete_error=None, setpassword_error=None):
        self.search_result = [] if search_result is None else search_result
        self.newuser_error = newuser_error
        self.modify_error = modify_error
        self.delete_error = delete_error
        self.setpassword_error = setpassword_error
        self.captured = {}
        self.modified = []
        self.deleted = []
        self.setpassword_filters = []

    def domain_dn(self):
        return "DC=example,DC=com"

    def search(self, base, scope, expression, attrs):
        self.captured = {"base": base, "scope": scope, "expression": expression, "attrs": attrs}
        return self.search_result

    def newuser(self, username, password):
        if self.newuser_error is not None:
            raise self.newuser_error

    def modify(self, message):
        if self.modify_error is not None:
            raise self.modify_error
        self.modified.append(message)

    def delete(self, dn):
        if self.delete_error is not None:
            raise self.delete_error
        self.deleted.append(dn)

    def setpassword(self, search_filter, password):
        if self.setpassword_error is not None:
            raise self.setpassword_error
        # Record only the filter, never the password.
        self.setpassword_filters.append(search_filter)


def make_io(fake_ldb, samdb):
    user_io = samba_user.SambaUserIO(samdb)
    user_io._ldb = lambda: fake_ldb
    return user_io


def test_read_current_escapes_filter_value():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB(search_result=[])
    make_io(fake_ldb, samdb).read_current("evil)(uid=*)")
    # The raw, attacker-controlled value must have been passed to the escaper...
    assert "evil)(uid=*)" in fake_ldb.encoded
    # ...and the filter must contain the escaped form, not the raw injection.
    assert "(sAMAccountName=ESC(evil)(uid=*))" in samdb.captured["expression"]
    assert samdb.captured["scope"] == fake_ldb.SCOPE_SUBTREE


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
        make_io(fake_ldb, samdb).create_user("jdoe", "pw")


def test_create_user_other_ldberror_propagates():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB(newuser_error=FakeLdbError(999, "boom"))
    with pytest.raises(FakeLdbError):
        make_io(fake_ldb, samdb).create_user("jdoe", "pw")


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


def test_delete_user_already_gone_returns_false():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB(delete_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    assert make_io(fake_ldb, samdb).delete_user("CN=jdoe,DC=example,DC=com") is False


def test_delete_user_success_returns_true():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB()
    assert make_io(fake_ldb, samdb).delete_user("CN=jdoe,DC=example,DC=com") is True
    assert samdb.deleted  # delete actually issued


def test_set_password_escapes_filter_value():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB()
    make_io(fake_ldb, samdb).set_password("evil)(uid=*)", "pw")
    # The raw value was passed through the escaper before entering the filter.
    assert fake_ldb.encoded == ["evil)(uid=*)"]
    assert samdb.setpassword_filters == ["(sAMAccountName=%s)" % ("ESC(%s)" % "evil)(uid=*)")]


def test_set_password_vanished_raises_clean():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB(setpassword_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    with pytest.raises(logic.SambaUserError):
        make_io(fake_ldb, samdb).set_password("jdoe", "pw")


def test_set_password_other_ldberror_propagates():
    fake_ldb = FakeLdb()
    samdb = FakeSamDB(setpassword_error=FakeLdbError(999, "boom"))
    with pytest.raises(FakeLdbError):
        make_io(fake_ldb, samdb).set_password("jdoe", "pw")


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
        return ["present"]


def test_rfc2307_provisioned_true(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    samdb = ExistsSamDB(exists=True)
    assert samba_user_io.rfc2307_provisioned(samdb) is True
    # Probed the well-known fake-ypserver container with a base-scope search.
    assert samdb.searched and samdb.searched[0][1] == FakeLdb.SCOPE_BASE


def test_rfc2307_provisioned_false(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    assert samba_user_io.rfc2307_provisioned(ExistsSamDB(exists=False)) is False
