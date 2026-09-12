# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the password policy I/O layer and the two modules' imports.

A fake ``ldb`` module and SamDB are injected, so these run without the samba
bindings while exercising the record conversion, the escaped PSO DN, the add
and modify messages and the subject resolution."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_password_policy_io as policy_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_password_policy_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_password_policy
from ansible_collections.jomrr.samba.plugins.modules import samba_password_settings


def test_modules_import_without_samba():
    assert hasattr(samba_password_policy, "main")
    assert hasattr(samba_password_settings, "main")


class FakeLdbError(Exception):
    """Stand-in for ldb.LdbError; args are (code, message)."""


class FakeDn:
    def __init__(self, text):
        self.text = text
        self.set_calls = []

    def set_component(self, num, name, value):
        self.set_calls.append((num, name, value))
        self.text = "%s=%s" % (name, value)

    def add_base(self, parent):
        self.text = self.text + "," + parent.text

    def __str__(self):
        return self.text


class FakeMessage:
    """A search result (``get``) or a message under construction (``__setitem__``)."""

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
    SCOPE_SUBTREE = 2
    FLAG_MOD_ADD = 1
    FLAG_MOD_REPLACE = 2
    ERR_NO_SUCH_OBJECT = 32
    ERR_ENTRY_ALREADY_EXISTS = 68
    LdbError = FakeLdbError

    def Dn(self, samdb, text):
        return FakeDn(text)

    def Message(self, dn):
        return FakeMessage(dn=dn)

    def MessageElement(self, values, flag, name):
        return (list(values), flag, name)

    def binary_encode(self, value):
        return "ESC(%s)" % value


class FakeSamDB:
    """Answers base reads from ``records`` and subject searches from ``subjects``."""

    def __init__(self, records=None, subjects=None, add_error=None, modify_error=None):
        self.records = records or {}
        self.subjects = subjects or {}
        self.add_error = add_error
        self.modify_error = modify_error
        self.added = []
        self.modified = []
        self.searches = []

    def domain_dn(self):
        return "DC=example,DC=com"

    def search(self, base, scope, expression=None, attrs=None):
        self.searches.append({"base": str(base), "scope": scope, "expression": expression, "attrs": attrs})
        if scope == FakeLdb.SCOPE_BASE:
            if str(base) not in self.records:
                raise FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "no such object")
            return [self.records[str(base)]]
        for name, result in self.subjects.items():
            if "(sAMAccountName=ESC(%s))" % name in expression:
                return result
        return []

    def add(self, message):
        if self.add_error is not None:
            raise self.add_error
        self.added.append(message)

    def modify(self, message):
        if self.modify_error is not None:
            raise self.modify_error
        self.modified.append(message)


@pytest.fixture(autouse=True)
def _patch_ldb(monkeypatch):
    monkeypatch.setattr(samba_ldb, "load_ldb", FakeLdb)


DOMAIN = FakeMessage(
    {"minPwdLength": ["7"], "pwdHistoryLength": ["24"], "minPwdAge": ["-864000000000"], "maxPwdAge": ["-36288000000000"],
     "lockoutThreshold": ["0"], "lockoutDuration": [str(logic.NEVER)], "lockOutObservationWindow": ["-18000000000"],
     "pwdProperties": ["1"]},
    dn="DC=example,DC=com",
)


def make_io(**kwargs):
    return policy_io.PasswordPolicyIO(FakeSamDB(**kwargs))


def test_read_domain_builds_a_text_record_with_dn():
    io = make_io(records={"DC=example,DC=com": DOMAIN})
    record = io.read_domain()
    assert record["_dn"] == "DC=example,DC=com"
    assert record["minPwdLength"] == ["7"]
    assert record["lockoutDuration"] == [str(logic.NEVER)]
    assert io.samdb.searches[0]["scope"] == FakeLdb.SCOPE_BASE


def test_pso_dn_escapes_the_name_via_set_component():
    io = make_io()
    dn = io.pso_dn("ev,il")
    assert dn == "CN=ev,il,CN=Password Settings Container,CN=System,DC=example,DC=com"
    # The escaping went through ldb.Dn.set_component, never string formatting.
    assert (0, "CN", "ev,il") in samba_ldb.build_child_dn(io.samdb, "CN", "ev,il", FakeDn("x")).set_calls


def test_read_pso_none_when_absent_and_a_record_when_present():
    io = make_io()
    assert io.read_pso("ghost") is None
    dn = "CN=admins,CN=Password Settings Container,CN=System,DC=example,DC=com"
    io = make_io(records={dn: FakeMessage({"msDS-PasswordSettingsPrecedence": ["10"]}, dn=dn)})
    record = io.read_pso("admins")
    assert record["_dn"] == dn
    assert record["msDS-PasswordSettingsPrecedence"] == ["10"]
    # An attribute the object lacks reads as an empty list, not an error.
    assert record["msDS-PSOAppliesTo"] == []


def test_add_builds_the_message_and_maps_a_collision():
    io = make_io()
    io.add("CN=x,DC=example,DC=com", {"objectClass": ["msDS-PasswordSettings"], "msDS-PSOAppliesTo": ["CN=a", "CN=b"]})
    message = io.samdb.added[0]
    assert str(message.dn) == "CN=x,DC=example,DC=com"
    assert message.elements["msDS-PSOAppliesTo"] == (["CN=a", "CN=b"], FakeLdb.FLAG_MOD_ADD, "msDS-PSOAppliesTo")
    with pytest.raises(logic.SambaPasswordPolicyError):
        make_io(add_error=FakeLdbError(FakeLdb.ERR_ENTRY_ALREADY_EXISTS, "exists")).add("CN=x,DC=example,DC=com", {})


def test_modify_replaces_values_including_an_empty_list():
    io = make_io()
    io.modify("CN=x,DC=example,DC=com", {"msDS-PSOAppliesTo": [], "msDS-MinimumPasswordLength": ["16"]})
    message = io.samdb.modified[0]
    assert message.elements["msDS-PSOAppliesTo"] == ([], FakeLdb.FLAG_MOD_REPLACE, "msDS-PSOAppliesTo")
    assert message.elements["msDS-MinimumPasswordLength"] == (["16"], FakeLdb.FLAG_MOD_REPLACE, "msDS-MinimumPasswordLength")


def test_modify_vanished_object_is_a_clean_error():
    io = make_io(modify_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    with pytest.raises(logic.SambaPasswordPolicyError):
        io.modify("CN=x,DC=example,DC=com", {"msDS-MinimumPasswordLength": ["16"]})


def test_resolve_subjects_escapes_restricts_and_sorts():
    io = make_io(subjects={
        "jd)(oe": [FakeMessage(dn="CN=jdoe,CN=Users,DC=example,DC=com")],
        "Domain Admins": [FakeMessage(dn="CN=Domain Admins,CN=Users,DC=example,DC=com")],
    })
    dns = io.resolve_subjects(["jd)(oe", "Domain Admins", "jd)(oe"])
    assert dns == ["CN=Domain Admins,CN=Users,DC=example,DC=com", "CN=jdoe,CN=Users,DC=example,DC=com"]
    expression = io.samdb.searches[0]["expression"]
    # Escaped, matched by name or DN, restricted to users and global security groups.
    assert "(sAMAccountName=ESC(jd)(oe))" in expression
    assert "(distinguishedName=ESC(jd)(oe))" in expression
    assert "(groupType=-2147483646)" in expression
    assert "(!(objectClass=computer))" in expression
    # A duplicate name is searched once.
    assert len(io.samdb.searches) == 2


def test_resolve_subjects_reports_every_unknown_name():
    io = make_io(subjects={"jdoe": [FakeMessage(dn="CN=jdoe,CN=Users,DC=example,DC=com")]})
    with pytest.raises(logic.SambaPasswordPolicyError) as raised:
        io.resolve_subjects(["jdoe", "ghost", "Engineers"])
    assert "ghost" in str(raised.value)
    assert "Engineers" in str(raised.value)
