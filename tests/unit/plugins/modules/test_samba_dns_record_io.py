# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_dns_record LDB I/O layer (SambaDnsRecordIO).

Fake ``ldb``/``ndr``/``dnsp`` modules are injected, so these run without the
samba bindings while exercising the node write paths. The central case: a
tombstoned node (what samba leaves behind after the last record of a name was
removed) must be revived, never merely appended to, because the DNS server
ignores tombstoned nodes."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.modules import samba_dns_record


class FakeLdbError(Exception):
    """Stand-in for ldb.LdbError; args are (code, message)."""


class FakeDn:
    """Minimal ldb.Dn: only what build_child_dn needs."""

    def __init__(self, text):
        self.text = text

    def set_component(self, num, name, value):
        self.text = "%s=%s" % (name, value)

    def add_base(self, parent):
        self.text = self.text + "," + parent.text

    def __str__(self):
        return self.text


class FakeMessage:
    """Minimal stand-in for ldb.Message."""

    def __init__(self, dn=None):
        self.dn = dn
        self.elements = {}

    def __setitem__(self, key, value):
        self.elements[key] = value


class FakeLdb:
    """Provides the ldb symbols SambaDnsRecordIO and the shared DN helper use."""

    SCOPE_BASE = 0
    FLAG_MOD_ADD = 1
    FLAG_MOD_REPLACE = 2
    ERR_NO_SUCH_OBJECT = 32
    ERR_ATTRIBUTE_OR_VALUE_EXISTS = 20
    ERR_ENTRY_ALREADY_EXISTS = 68
    LdbError = FakeLdbError

    @staticmethod
    def Dn(samdb, text):
        return FakeDn(text)

    @staticmethod
    def Message(dn=None):
        return FakeMessage(dn)

    @staticmethod
    def MessageElement(value, flag, name):
        return (value, flag, name)


class FakeDnsp:
    """Minimal stand-in for samba.dcerpc.dnsp (all managed type constants)."""

    DNS_TYPE_TOMBSTONE = 0
    DNS_TYPE_A = 1
    DNS_TYPE_NS = 2
    DNS_TYPE_CNAME = 5
    DNS_TYPE_PTR = 12
    DNS_TYPE_MX = 15
    DNS_TYPE_TXT = 16
    DNS_TYPE_AAAA = 28
    DNS_TYPE_SRV = 33
    DNS_RANK_ZONE = 240

    class DnssrvRpcRecord:
        def __init__(self):
            self.wType = None
            self.rank = None
            self.dwSerial = None
            self.dwTtlSeconds = None
            self.data = None


class FakeNdr:
    """The stored "raw values" are the record objects themselves."""

    @staticmethod
    def ndr_unpack(record_cls, value):
        return value

    @staticmethod
    def ndr_pack(rec):
        return rec


class FoundMessage:
    """Stand-in for an ldb search result message."""

    def __init__(self, attrs):
        self._attrs = attrs

    def get(self, attr):
        return self._attrs.get(attr)


class FakeSamDB:
    """Fake SamDB holding one node; records every write it receives."""

    def __init__(self, node=None):
        self.node = node  # None = node absent; else attr -> list of values
        self.added = []
        self.modified = []
        self.replaced = []

    def search(self, base, scope, attrs, expression=None):
        if self.node is None:
            raise FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "no such object")
        return [FoundMessage(self.node)]

    def add(self, message):
        self.added.append(message)

    def modify(self, message):
        self.modified.append(message)

    def dns_replace_by_dn(self, dn, records):
        self.replaced.append((str(dn), records))


@pytest.fixture(autouse=True)
def _patch_bindings(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    monkeypatch.setattr(samba_dns_io, "load_ndr", lambda: FakeNdr)
    monkeypatch.setattr(samba_dns_io, "load_dnsp", lambda: FakeDnsp)


ZONE = "example.com"
SPEC = {"type": "A", "value": "192.0.2.10", "ttl": 900}


def a_record(value, ttl=900):
    rec = FakeDnsp.DnssrvRpcRecord()
    rec.wType = FakeDnsp.DNS_TYPE_A
    rec.dwTtlSeconds = ttl
    rec.data = value
    return rec


def tombstone():
    rec = FakeDnsp.DnssrvRpcRecord()
    rec.wType = FakeDnsp.DNS_TYPE_TOMBSTONE
    return rec


def make_io(samdb):
    record_io = samba_dns_record.SambaDnsRecordIO(samdb)
    record_io._zone_dns[ZONE] = FakeDn("DC=example.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=com")
    return record_io


def written_records(message):
    """Return ``[(wType, data)]`` of the dnsRecord element and its mod flag."""
    values, flag, dummy_name = message.elements["dnsRecord"]
    return [(rec.wType, rec.data) for rec in values], flag


def test_add_on_tombstoned_node_revives_it():
    # What samba leaves behind after the last record of a name was removed.
    samdb = FakeSamDB(node={"dnsRecord": [tombstone()], "dNSTombstoned": ["TRUE"]})
    assert make_io(samdb).add(ZONE, "www", dict(SPEC)) is True
    assert samdb.added == [] and samdb.replaced == []
    assert len(samdb.modified) == 1
    records, flag = written_records(samdb.modified[0])
    # The records are replaced (tombstone dropped, desired record in) ...
    assert flag == FakeLdb.FLAG_MOD_REPLACE
    assert records == [(FakeDnsp.DNS_TYPE_A, "192.0.2.10")]
    # ... and the flag the DNS server filters on is cleared in the same modify.
    assert samdb.modified[0].elements["dNSTombstoned"] == ("FALSE", FakeLdb.FLAG_MOD_REPLACE, "dNSTombstoned")


def test_add_on_corrupt_tombstoned_node_dedupes_and_clears_flag():
    # The state the old append-only code produced: flag still TRUE, tombstone
    # plus a live copy of the very record being added. Healing it is a real
    # change (the name becomes resolvable), so add reports True.
    samdb = FakeSamDB(node={"dnsRecord": [tombstone(), a_record("192.0.2.10")], "dNSTombstoned": ["TRUE"]})
    assert make_io(samdb).add(ZONE, "www", dict(SPEC)) is True
    records, flag = written_records(samdb.modified[0])
    assert flag == FakeLdb.FLAG_MOD_REPLACE
    assert records == [(FakeDnsp.DNS_TYPE_A, "192.0.2.10")]
    assert samdb.modified[0].elements["dNSTombstoned"][0] == "FALSE"


def test_add_on_live_node_appends_without_touching_the_flag():
    # Regression guard for the unchanged path: a live node gets one value added.
    samdb = FakeSamDB(node={"dnsRecord": [a_record("192.0.2.1")]})
    assert make_io(samdb).add(ZONE, "www", dict(SPEC)) is True
    records, flag = written_records(samdb.modified[0])
    assert flag == FakeLdb.FLAG_MOD_ADD
    assert records == [(FakeDnsp.DNS_TYPE_A, "192.0.2.10")]
    assert "dNSTombstoned" not in samdb.modified[0].elements


def test_add_on_live_node_with_matching_record_is_noop():
    samdb = FakeSamDB(node={"dnsRecord": [a_record("192.0.2.10")]})
    assert make_io(samdb).add(ZONE, "www", dict(SPEC)) is False
    assert samdb.modified == [] and samdb.added == []


def test_add_creates_absent_node():
    samdb = FakeSamDB(node=None)
    assert make_io(samdb).add(ZONE, "www", dict(SPEC)) is True
    assert len(samdb.added) == 1 and samdb.modified == []


def test_remove_on_tombstoned_node_is_noop():
    samdb = FakeSamDB(node={"dnsRecord": [tombstone()], "dNSTombstoned": ["TRUE"]})
    assert make_io(samdb).remove(ZONE, "www", dict(SPEC)) is False
    assert samdb.modified == [] and samdb.replaced == []


def test_remove_last_live_record_hands_samba_an_empty_list():
    # samba tombstones the node itself on an empty replace; remove relies on it.
    samdb = FakeSamDB(node={"dnsRecord": [a_record("192.0.2.10")]})
    assert make_io(samdb).remove(ZONE, "www", dict(SPEC)) is True
    assert len(samdb.replaced) == 1 and samdb.replaced[0][1] == []
