# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_dns_io record build/extract mapping.

A fake ``dnsp`` module is injected (via samba_dns_io.load_dnsp), so these run
without the samba bindings while exercising the per-type record mapping."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_io


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
    rec = samba_dns_io.build_record(spec)
    assert rec.wType == getattr(FakeDnsp, "DNS_TYPE_" + spec["type"])
    assert rec.rank == FakeDnsp.DNS_RANK_ZONE
    assert rec.dwTtlSeconds == spec["ttl"]
    assert samba_dns_io.record_to_spec(rec) == spec


def test_mx_fields_mapped():
    rec = samba_dns_io.build_record({"type": "MX", "value": "mail.example.com", "preference": 20, "ttl": 900})
    assert rec.data.nameTarget == "mail.example.com"
    assert rec.data.wPriority == 20


def test_srv_fields_mapped():
    rec = samba_dns_io.build_record(
        {"type": "SRV", "value": "dc.example.com", "priority": 1, "weight": 50, "port": 88, "ttl": 900})
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
