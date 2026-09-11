# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_dns_record LDB I/O layer (SambaDnsRecordIO) and the
zone serial helper.

Fake ``ldb``/``ndr``/``dnsp`` modules are injected, so these run without the
samba bindings while exercising the node write paths: reviving a tombstoned
node, compare-and-swap writes (delete the exact old value and add the new one
in a single modify), tombstoning on the last removal, and the SOA serial bump
every real change carries."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_record_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.modules import samba_dns_record

#: The real helper, captured before the autouse fixture stubs it for the IO tests.
REAL_BUMP = samba_dns_io.bump_soa_serial


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
    """Minimal stand-in for ldb.Message; ``add`` keeps element order."""

    def __init__(self, dn=None):
        self.dn = dn
        self.elements = {}
        self.added = []

    def __setitem__(self, key, value):
        self.elements[key] = value

    def add(self, element):
        self.added.append(element)


class FakeLdb:
    """Provides the ldb symbols SambaDnsRecordIO and the shared helpers use."""

    SCOPE_BASE = 0
    FLAG_MOD_ADD = 1
    FLAG_MOD_REPLACE = 2
    FLAG_MOD_DELETE = 3
    ERR_NO_SUCH_ATTRIBUTE = 16
    ERR_ATTRIBUTE_OR_VALUE_EXISTS = 20
    ERR_NO_SUCH_OBJECT = 32
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
    DNS_TYPE_SOA = 6
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

    class soa:
        def __init__(self):
            self.serial = None


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
    """Fake SamDB with one record node and the zone apex; records every write."""

    def __init__(self, node=None, apex=None, modify_errors=None):
        self.node = node  # None = node absent; else attr -> list of values
        self.apex = apex  # attr -> list of values of the DC=@ node (SOA)
        self.modify_errors = list(modify_errors or [])  # raised by modify() in order
        self.added = []
        self.modified = []
        self.replaced = []

    def search(self, base, scope, attrs, expression=None):
        target = self.apex if str(base).startswith("DC=@,") else self.node
        if target is None:
            raise FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "no such object")
        return [FoundMessage(target)]

    def add(self, message):
        self.added.append(message)

    def modify(self, message):
        if self.modify_errors:
            raise self.modify_errors.pop(0)
        self.modified.append(message)

    def dns_replace_by_dn(self, dn, records):
        self.replaced.append((str(dn), records))


class SerialStub:
    """Stands in for bump_soa_serial: counts calls, always returns 42."""

    def __init__(self):
        self.calls = []

    def __call__(self, samdb, zone_dn):
        self.calls.append(str(zone_dn))
        return 42


@pytest.fixture(autouse=True)
def _patch_bindings(monkeypatch):
    monkeypatch.setattr(samba_user_io, "load_ldb", FakeLdb)
    monkeypatch.setattr(samba_dns_io, "load_ndr", lambda: FakeNdr)
    monkeypatch.setattr(samba_dns_io, "load_dnsp", lambda: FakeDnsp)


@pytest.fixture(autouse=True)
def serial(monkeypatch):
    stub = SerialStub()
    monkeypatch.setattr(samba_dns_io, "bump_soa_serial", stub)
    return stub


ZONE = "example.com"
ZONE_DN = "DC=example.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=com"
SPEC = {"type": "A", "value": "192.0.2.10", "ttl": 900}


def a_record(value, ttl=900, serial=1):
    rec = FakeDnsp.DnssrvRpcRecord()
    rec.wType = FakeDnsp.DNS_TYPE_A
    rec.dwTtlSeconds = ttl
    rec.dwSerial = serial
    rec.data = value
    return rec


def tombstone():
    rec = FakeDnsp.DnssrvRpcRecord()
    rec.wType = FakeDnsp.DNS_TYPE_TOMBSTONE
    return rec


def soa_record(serial):
    rec = FakeDnsp.DnssrvRpcRecord()
    rec.wType = FakeDnsp.DNS_TYPE_SOA
    rec.dwSerial = serial
    rec.data = FakeDnsp.soa()
    rec.data.serial = serial
    return rec


def make_io(samdb):
    record_io = samba_dns_record.SambaDnsRecordIO(samdb)
    record_io._zone_dns[ZONE] = FakeDn(ZONE_DN)
    return record_io


def written_records(message):
    """Return ``[(wType, data)]`` of the dnsRecord element set via __setitem__, and its flag."""
    values, flag, dummy_name = message.elements["dnsRecord"]
    return [(rec.wType, rec.data) for rec in values], flag


# --- add ---

def test_add_on_tombstoned_node_revives_it(serial):
    # What samba leaves behind after the last record of a name was removed.
    samdb = FakeSamDB(node={"dnsRecord": [tombstone()], "dNSTombstoned": ["TRUE"]})
    assert make_io(samdb).add(ZONE, "www", dict(SPEC)) is True
    assert samdb.added == [] and samdb.replaced == []
    assert len(samdb.modified) == 1
    records, flag = written_records(samdb.modified[0])
    # The records are replaced (tombstone dropped, desired record in) ...
    assert flag == FakeLdb.FLAG_MOD_REPLACE
    assert records == [(FakeDnsp.DNS_TYPE_A, "192.0.2.10")]
    # ... the flag the DNS server filters on is cleared in the same modify ...
    assert samdb.modified[0].elements["dNSTombstoned"] == ("FALSE", FakeLdb.FLAG_MOD_REPLACE, "dNSTombstoned")
    # ... and the change carries the raised zone serial.
    assert samdb.modified[0].elements["dnsRecord"][0][0].dwSerial == 42
    assert serial.calls == [ZONE_DN]


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


def test_add_on_live_node_appends_with_the_new_serial(serial):
    # Regression guard for the append path: one value added, flag untouched.
    samdb = FakeSamDB(node={"dnsRecord": [a_record("192.0.2.1")]})
    assert make_io(samdb).add(ZONE, "www", dict(SPEC)) is True
    records, flag = written_records(samdb.modified[0])
    assert flag == FakeLdb.FLAG_MOD_ADD
    assert records == [(FakeDnsp.DNS_TYPE_A, "192.0.2.10")]
    assert samdb.modified[0].elements["dnsRecord"][0][0].dwSerial == 42
    assert "dNSTombstoned" not in samdb.modified[0].elements
    assert serial.calls == [ZONE_DN]


def test_add_of_a_present_record_is_noop_without_serial_bump(serial):
    samdb = FakeSamDB(node={"dnsRecord": [a_record("192.0.2.10")]})
    assert make_io(samdb).add(ZONE, "www", dict(SPEC)) is False
    assert samdb.modified == [] and samdb.added == []
    # An idempotent run must not touch the zone serial.
    assert serial.calls == []


def test_add_creates_absent_node_after_one_serial_bump(serial):
    samdb = FakeSamDB(node=None)
    assert make_io(samdb).add(ZONE, "www", dict(SPEC)) is True
    assert len(samdb.added) == 1 and samdb.modified == []
    assert samdb.added[0].elements["dnsRecord"][0][0].dwSerial == 42
    assert serial.calls == [ZONE_DN]


# --- remove ---

def test_remove_deletes_only_the_exact_value(serial):
    keep, target = a_record("192.0.2.1"), a_record("192.0.2.10")
    samdb = FakeSamDB(node={"dnsRecord": [keep, target]})
    assert make_io(samdb).remove(ZONE, "www", dict(SPEC)) is True
    assert samdb.replaced == []
    assert len(samdb.modified) == 1
    # Exactly the matching value is deleted; the other record is never rewritten.
    assert samdb.modified[0].added == [([target], FakeLdb.FLAG_MOD_DELETE, "dnsRecord")]
    assert "dNSTombstoned" not in samdb.modified[0].elements
    assert serial.calls == [ZONE_DN]


def test_remove_last_record_tombstones_atomically():
    target = a_record("192.0.2.10")
    samdb = FakeSamDB(node={"dnsRecord": [target]})
    assert make_io(samdb).remove(ZONE, "www", dict(SPEC)) is True
    added = samdb.modified[0].added
    assert added[0] == ([target], FakeLdb.FLAG_MOD_DELETE, "dnsRecord")
    values, flag, dummy_name = added[1]
    assert flag == FakeLdb.FLAG_MOD_ADD
    assert values[0].wType == FakeDnsp.DNS_TYPE_TOMBSTONE
    assert values[0].dwSerial == 42
    assert samdb.modified[0].elements["dNSTombstoned"] == ("TRUE", FakeLdb.FLAG_MOD_REPLACE, "dNSTombstoned")


def test_remove_drops_a_stale_tombstone_value_too():
    stale, target = tombstone(), a_record("192.0.2.10")
    samdb = FakeSamDB(node={"dnsRecord": [stale, target], "dNSTombstoned": ["FALSE"]})
    assert make_io(samdb).remove(ZONE, "www", dict(SPEC)) is True
    added = samdb.modified[0].added
    assert added[0] == ([target, stale], FakeLdb.FLAG_MOD_DELETE, "dnsRecord")
    assert added[1][0][0].wType == FakeDnsp.DNS_TYPE_TOMBSTONE


def test_remove_on_tombstoned_node_is_noop(serial):
    samdb = FakeSamDB(node={"dnsRecord": [tombstone()], "dNSTombstoned": ["TRUE"]})
    assert make_io(samdb).remove(ZONE, "www", dict(SPEC)) is False
    assert samdb.modified == [] and samdb.replaced == []
    assert serial.calls == []


def test_remove_of_an_absent_record_is_noop_without_serial_bump(serial):
    samdb = FakeSamDB(node={"dnsRecord": [a_record("192.0.2.1")]})
    assert make_io(samdb).remove(ZONE, "www", dict(SPEC)) is False
    assert samdb.modified == []
    assert serial.calls == []


class VanishingSamDB(FakeSamDB):
    """The first modify fails as if the value vanished, and the node shows that."""

    vanished = False

    def modify(self, message):
        if not self.vanished:
            self.vanished = True
            self.node = {"dnsRecord": [a_record("192.0.2.1")]}
            raise FakeLdbError(FakeLdb.ERR_NO_SUCH_ATTRIBUTE, "no such value")
        super().modify(message)


def test_remove_re_reads_when_the_value_vanished():
    samdb = VanishingSamDB(node={"dnsRecord": [a_record("192.0.2.1"), a_record("192.0.2.10")]})
    # Removed concurrently between read and write: an honest no-op, no traceback.
    assert make_io(samdb).remove(ZONE, "www", dict(SPEC)) is False
    assert samdb.modified == []


# --- update (TTL) ---

def test_update_swaps_the_value_for_the_new_ttl(serial):
    old = a_record("192.0.2.10", ttl=900)
    samdb = FakeSamDB(node={"dnsRecord": [a_record("192.0.2.1"), old]})
    assert make_io(samdb).update(ZONE, "www", dict(SPEC, ttl=600)) is True
    assert samdb.replaced == [] and len(samdb.modified) == 1
    added = samdb.modified[0].added
    # Compare-and-swap: the exact old value goes, the rebuilt record comes.
    assert added[0] == ([old], FakeLdb.FLAG_MOD_DELETE, "dnsRecord")
    values, flag, dummy_name = added[1]
    assert flag == FakeLdb.FLAG_MOD_ADD
    assert (values[0].wType, values[0].data, values[0].dwTtlSeconds, values[0].dwSerial) == (
        FakeDnsp.DNS_TYPE_A, "192.0.2.10", 600, 42)
    assert serial.calls == [ZONE_DN]


def test_update_with_matching_ttl_is_noop(serial):
    samdb = FakeSamDB(node={"dnsRecord": [a_record("192.0.2.10", ttl=600)]})
    assert make_io(samdb).update(ZONE, "www", dict(SPEC, ttl=600)) is False
    assert samdb.modified == []
    assert serial.calls == []


def test_update_of_a_vanished_record_adds_it():
    # The record went away between the plan and the write: the desired state
    # (present with this TTL) is established by adding it.
    samdb = FakeSamDB(node={"dnsRecord": [a_record("192.0.2.1")]})
    assert make_io(samdb).update(ZONE, "www", dict(SPEC, ttl=600)) is True
    records, flag = written_records(samdb.modified[0])
    assert flag == FakeLdb.FLAG_MOD_ADD
    assert records == [(FakeDnsp.DNS_TYPE_A, "192.0.2.10")]


# --- bump_soa_serial (the real helper, against a fake apex) ---

def test_bump_soa_serial_increments_by_compare_and_swap():
    soa = soa_record(5)
    samdb = FakeSamDB(apex={"dnsRecord": [a_record("192.0.2.1"), soa]})
    assert REAL_BUMP(samdb, FakeDn(ZONE_DN)) == 6
    assert len(samdb.modified) == 1
    assert str(samdb.modified[0].dn) == "DC=@," + ZONE_DN
    added = samdb.modified[0].added
    # Delete the exact old SOA value and add the new one in the same modify.
    assert added[0] == ([soa], FakeLdb.FLAG_MOD_DELETE, "dnsRecord")
    assert added[1][1] == FakeLdb.FLAG_MOD_ADD
    new_soa = added[1][0][0]
    assert new_soa.wType == FakeDnsp.DNS_TYPE_SOA
    assert new_soa.data.serial == 6 and new_soa.dwSerial == 6


def test_bump_soa_serial_retries_against_the_fresh_value():
    samdb = FakeSamDB(apex={"dnsRecord": [soa_record(5)]},
                      modify_errors=[FakeLdbError(FakeLdb.ERR_NO_SUCH_ATTRIBUTE, "rewritten")])
    # The first swap loses against a concurrent writer; the retry works on the
    # re-read SOA and ends one above whatever it found.
    assert REAL_BUMP(samdb, FakeDn(ZONE_DN)) == 7
    assert len(samdb.modified) == 1


def test_bump_soa_serial_without_soa_fails_clean():
    samdb = FakeSamDB(apex={"dnsRecord": [a_record("192.0.2.1")]})
    with pytest.raises(logic.SambaDnsRecordError):
        REAL_BUMP(samdb, FakeDn(ZONE_DN))
