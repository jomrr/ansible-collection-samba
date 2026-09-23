# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_dns_io record mapping and zone property reads.

A fake ``dnsp`` module is injected (via samba_dns_io.load_dnsp), so these run
without the samba bindings while exercising the per-type record mapping."""

from __future__ import annotations

import pytest
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_io, samba_ldb


class FakeDnsp:
    """Minimal stand-in for samba.dcerpc.dnsp."""

    DNS_TYPE_A = 1
    DNS_TYPE_NS = 2
    DNS_TYPE_CNAME = 5
    DNS_TYPE_SOA = 6
    DNS_TYPE_PTR = 12
    DNS_TYPE_MX = 15
    DNS_TYPE_TXT = 16
    DNS_TYPE_AAAA = 28
    DNS_TYPE_SRV = 33
    DNS_TYPE_TOMBSTONE = 0
    DNS_RANK_ZONE = 240
    DSPROPERTY_ZONE_TYPE = 0x01
    DSPROPERTY_ZONE_NOREFRESH_INTERVAL = 0x10
    DSPROPERTY_ZONE_REFRESH_INTERVAL = 0x20
    DSPROPERTY_ZONE_AGING_STATE = 0x40

    class DnsProperty:
        def __init__(self, prop_id, data):
            self.id = prop_id
            self.data = data

    class DnssrvRpcRecord:
        def __init__(self):
            self.wType = None
            self.rank = None
            self.dwSerial = None
            self.dwTtlSeconds = None
            self.data = None

    class mx:
        def __init__(self):
            self.nameTarget = None
            self.wPriority = None

    class srv:
        def __init__(self):
            self.nameTarget = None
            self.wPort = None
            self.wPriority = None
            self.wWeight = None

    class string_list:
        def __init__(self):
            self.count = None
            self.str = None


@pytest.fixture(autouse=True)
def _patch_dnsp(monkeypatch):
    monkeypatch.setattr(samba_dns_io, "load_dnsp", lambda: FakeDnsp)


ROUND_TRIP = [
    {"type": "A", "value": "192.0.2.10", "ttl": 900},
    {"type": "AAAA", "value": "2001:db8::10", "ttl": 900},
    {"type": "CNAME", "value": "www.example.com", "ttl": 600},
    {"type": "PTR", "value": "host.example.com", "ttl": 900},
    {"type": "NS", "value": "ns1.example.com", "ttl": 900},
    {"type": "MX", "value": "mail.example.com", "preference": 10, "ttl": 900},
    {"type": "SRV", "value": "dc1.example.com", "priority": 0, "weight": 100, "port": 389, "ttl": 900},
    {"type": "TXT", "value": "v=spf1 -all", "ttl": 900},
]


@pytest.mark.parametrize("spec", ROUND_TRIP, ids=[s["type"] for s in ROUND_TRIP])
def test_build_then_extract_round_trips(spec):
    rec = samba_dns_io.build_record(spec, 7)
    assert rec.wType == getattr(FakeDnsp, "DNS_TYPE_" + spec["type"])
    assert rec.rank == FakeDnsp.DNS_RANK_ZONE
    assert rec.dwTtlSeconds == spec["ttl"]
    assert rec.dwSerial == 7
    assert samba_dns_io.record_to_spec(rec) == spec


def test_mx_fields_mapped():
    rec = samba_dns_io.build_record({"type": "MX", "value": "mail.example.com", "preference": 20, "ttl": 900}, 1)
    assert rec.data.nameTarget == "mail.example.com"
    assert rec.data.wPriority == 20


def test_srv_fields_mapped():
    rec = samba_dns_io.build_record(
        {"type": "SRV", "value": "dc.example.com", "priority": 1, "weight": 50, "port": 88, "ttl": 900}, 1)
    assert rec.data.nameTarget == "dc.example.com"
    assert (rec.data.wPriority, rec.data.wWeight, rec.data.wPort) == (1, 50, 88)


def test_tombstone_and_soa_map_to_none():
    tombstone = FakeDnsp.DnssrvRpcRecord()
    tombstone.wType = FakeDnsp.DNS_TYPE_TOMBSTONE
    assert samba_dns_io.record_to_spec(tombstone) is None

    soa = FakeDnsp.DnssrvRpcRecord()
    soa.wType = FakeDnsp.DNS_TYPE_SOA
    assert samba_dns_io.record_to_spec(soa) is None


def test_txt_multistring_joins_with_nul_so_it_differs_from_single():
    multi = FakeDnsp.DnssrvRpcRecord()
    multi.wType = FakeDnsp.DNS_TYPE_TXT
    multi.dwTtlSeconds = 900
    strings = FakeDnsp.string_list()
    strings.count = 2
    strings.str = ["a", "b"]
    multi.data = strings
    spec = samba_dns_io.record_to_spec(multi)
    assert spec["value"] == "a\x00b"
    # A single-string "a" record must not compare equal to this.
    assert spec["value"] != "a"


class FakeLdbError(Exception):
    """Stand-in for ldb.LdbError."""


class FakeLdb:
    SCOPE_BASE = 0
    ERR_NO_SUCH_OBJECT = 32
    LdbError = FakeLdbError


class CapturingSamDB:
    """Captures the search parameters of read_node_specs; finds no node."""

    def __init__(self):
        self.captured = None

    def search(self, base, scope, expression, attrs):
        self.captured = {"base": base, "scope": scope, "expression": expression, "attrs": attrs}
        return []


def test_read_node_specs_treats_tombstoned_node_as_absent(monkeypatch):
    monkeypatch.setattr(samba_ldb, "load_ldb", FakeLdb)
    samdb = CapturingSamDB()
    assert samba_dns_io.read_node_specs(samdb, "DC=www,DC=example.com") is None
    # The base-scope read carries the DNS server's own node filter, so a
    # tombstoned node is absent for the module exactly as it is for the server.
    assert samdb.captured["scope"] == FakeLdb.SCOPE_BASE
    assert samdb.captured["expression"] == samba_dns_io.LIVE_NODE_FILTER
    assert "(!(dNSTombstoned=TRUE))" in samdb.captured["expression"]


class FakeNdr:
    """Unpacks a ``(id, data)`` pair as a DnsProperty; any other value is malformed."""

    @staticmethod
    def ndr_unpack(struct, value):
        try:
            prop_id, data = value
        except ValueError:
            raise RuntimeError(11, "Buffer Size Error") from None
        return struct(prop_id, data)


def test_decode_zone_properties_reads_the_aging_properties(monkeypatch):
    monkeypatch.setattr(samba_dns_io, "load_ndr", lambda: FakeNdr)
    stored = samba_dns_io.decode_zone_properties([
        (FakeDnsp.DSPROPERTY_ZONE_TYPE, 1),
        b"\x00",
        (FakeDnsp.DSPROPERTY_ZONE_NOREFRESH_INTERVAL, 24),
        (FakeDnsp.DSPROPERTY_ZONE_REFRESH_INTERVAL, 48),
        (FakeDnsp.DSPROPERTY_ZONE_AGING_STATE, 1),
        (FakeDnsp.DSPROPERTY_ZONE_NOREFRESH_INTERVAL, 72),
    ])
    # As the DNS server reads them: other properties are ignored, a malformed
    # value is skipped and a later value for the same property wins.
    assert stored == {"norefresh_interval": 72, "refresh_interval": 48, "aging": 1}


def test_decode_zone_properties_of_a_zone_without_the_attribute_is_empty():
    assert samba_dns_io.decode_zone_properties(None) == {}
