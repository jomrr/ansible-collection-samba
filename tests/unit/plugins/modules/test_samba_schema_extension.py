# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_schema_extension I/O layer.

A fake ``ldb`` module and SamDB are injected, so these run without the samba
bindings while exercising the record conversion (binary GUIDs), the messages
built for adds and modifies, the transaction handling and the schema master
check."""

from __future__ import annotations

import uuid

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_schema_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_schema_extension

SCHEMA = "CN=Schema,CN=Configuration,DC=example,DC=com"
GUID = "67c03072-1721-4fcd-bf6a-42341060d6fa"
THIS_DC = "CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com"
OTHER_DC = THIS_DC.replace("CN=DC1,", "CN=DC2,")


def test_module_imports_without_samba():
    assert hasattr(samba_schema_extension, "main")
    assert hasattr(samba_schema_extension, "SambaSchemaIO")


class FakeLdbError(Exception):
    """Stand-in for ldb.LdbError; args are (code, message)."""


class FakeDn:
    def __init__(self, text):
        self.text = text

    def __eq__(self, other):
        return isinstance(other, FakeDn) and self.text.lower() == other.text.lower()

    def __hash__(self):
        return hash(self.text.lower())

    def __str__(self):
        return self.text


class FakeMessage:
    def __init__(self, attrs=None, dn=None):
        self._attrs = attrs or {}
        self.dn = dn
        self.elements = {}

    def get(self, attr):
        return self._attrs.get(attr)

    def __getitem__(self, attr):
        return self._attrs[attr]

    def __setitem__(self, key, value):
        self.elements[key] = value


class FakeLdb:
    SCOPE_BASE = 0
    SCOPE_ONELEVEL = 1
    FLAG_MOD_ADD = 1
    FLAG_MOD_REPLACE = 2
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
    """Answers searches from canned results; records adds, modifies and transactions."""

    def __init__(self, results=None, owner=THIS_DC, fail_modify=None):
        self.results = results or {}
        self.owner = owner
        self.fail_modify = fail_modify
        self.added = []
        self.modified = []
        self.transactions = []

    def get_schema_basedn(self):
        return FakeDn(SCHEMA)

    def get_config_basedn(self):
        return FakeDn("CN=Configuration,DC=example,DC=com")

    def get_dsServiceName(self):
        return THIS_DC

    def search(self, base, scope, expression=None, attrs=None):
        if scope == FakeLdb.SCOPE_BASE:
            return [FakeMessage({"fSMORoleOwner": [self.owner]}, dn=base)]
        return self.results.get(expression, [])

    def add(self, message):
        self.added.append(message)

    def modify(self, message):
        if self.fail_modify is not None:
            raise self.fail_modify
        self.modified.append(message)

    def transaction_start(self):
        self.transactions.append("start")

    def transaction_commit(self):
        self.transactions.append("commit")

    def transaction_cancel(self):
        self.transactions.append("cancel")


@pytest.fixture(autouse=True)
def _patch_ldb(monkeypatch):
    monkeypatch.setattr(samba_ldb, "load_ldb", FakeLdb)


def make_io(**kwargs):
    io = samba_schema_extension.SambaSchemaIO.__new__(samba_schema_extension.SambaSchemaIO)
    io.samdb = FakeSamDB(**kwargs)
    return io


def test_find_schema_converts_binary_guids_and_missing_attributes():
    message = FakeMessage(
        {"lDAPDisplayName": ["sshPublicKey"], "schemaIDGUID": [uuid.UUID(GUID).bytes_le]},
        dn="CN=sshPublicKey,%s" % SCHEMA,
    )
    io = make_io(results={"(lDAPDisplayName=ESC(sshPublicKey))": [message]})
    record = io.find_schema("sshPublicKey", ["lDAPDisplayName", "schemaIDGUID", "searchFlags"])
    assert record["_dn"] == "CN=sshPublicKey,%s" % SCHEMA
    assert record["schemaIDGUID"] == [GUID]
    assert record["searchFlags"] == []
    assert io.find_schema("ghost", ["searchFlags"]) is None


def test_apply_adds_and_modifies_in_one_transaction_with_binary_guids():
    io = make_io()
    io.apply([
        {"action": "add", "dn": "CN=x,%s" % SCHEMA, "label": "add x",
         "values": {"objectClass": ["attributeSchema"], "schemaIDGUID": [GUID], "searchFlags": ["8"]}},
        {"action": "modify", "dn": "CN=User,%s" % SCHEMA, "label": "modify user",
         "replace": {"searchFlags": ["8"]}, "add": {"auxiliaryClass": ["ldapPublicKey"]}},
    ])
    added = io.samdb.added[0]
    assert str(added.dn) == "CN=x,%s" % SCHEMA
    assert added.elements["schemaIDGUID"] == ([uuid.UUID(GUID).bytes_le], FakeLdb.FLAG_MOD_ADD, "schemaIDGUID")
    assert added.elements["searchFlags"] == (["8"], FakeLdb.FLAG_MOD_ADD, "searchFlags")
    modified = io.samdb.modified[0]
    assert modified.elements["searchFlags"] == (["8"], FakeLdb.FLAG_MOD_REPLACE, "searchFlags")
    assert modified.elements["auxiliaryClass"] == (["ldapPublicKey"], FakeLdb.FLAG_MOD_ADD, "auxiliaryClass")
    assert io.samdb.transactions == ["start", "commit"]


def test_apply_cancels_the_transaction_and_names_the_operation_on_failure():
    io = make_io(fail_modify=FakeLdbError(53, "objectclass: schema update not allowed"))
    with pytest.raises(logic.SambaSchemaError) as raised:
        io.apply([{"action": "modify", "dn": "CN=User,%s" % SCHEMA, "label": "modify classSchema user (auxiliaryClass)",
                   "replace": {}, "add": {"auxiliaryClass": ["ldapPublicKey"]}}])
    assert "modify classSchema user (auxiliaryClass) failed" in str(raised.value)
    assert "schema update not allowed" in str(raised.value)
    assert io.samdb.transactions == ["start", "cancel"]


def test_require_schema_master_compares_the_fsmo_owner_dn():
    make_io().require_schema_master()
    with pytest.raises(logic.SambaSchemaError):
        make_io(owner=OTHER_DC).require_schema_master()
