# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_dns_conn zone property write.

The lazily imported samba modules are faked, so these run without the bindings."""

from __future__ import annotations

import pytest
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_conn
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_zone_logic as logic


class FakeWERRORError(RuntimeError):
    """Stand-in for samba.WERRORError; args are (code, message)."""


class FakeNameAndParam:
    def __init__(self):
        self.pszNodeName = None
        self.dwParam = None


class FakeDnsserver:
    DNS_CLIENT_VERSION_LONGHORN = 0x70000
    DNSSRV_TYPEID_NAME_AND_PARAM = 12
    DNS_RPC_NAME_AND_PARAM = FakeNameAndParam


class FakeSamba:
    WERRORError = FakeWERRORError


class FakeConn:
    """Records DnssrvOperation2 calls; raises ``error`` when set."""

    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def DnssrvOperation2(self, version, flags, server, zone, context, operation, typeid, data):
        self.calls.append((server, zone, operation, data.pszNodeName, data.dwParam))
        if self.error is not None:
            raise self.error


@pytest.fixture(autouse=True)
def _fake_samba(monkeypatch):
    modules = {"samba.dcerpc.dnsserver": FakeDnsserver, "samba": FakeSamba}
    monkeypatch.setattr(samba_dns_conn, "_load", modules.__getitem__)


def test_set_zone_property_resets_the_named_dword():
    conn = FakeConn()
    samba_dns_conn.set_zone_property(conn, "dc1.example.com", "example.com", "RefreshInterval", 96)
    assert conn.calls == [("dc1.example.com", "example.com", "ResetDwordProperty", "RefreshInterval", 96)]


def test_set_zone_property_refusal_names_property_and_zone():
    cause = FakeWERRORError(9611, "WERR_DNS_ERROR_INVALID_PROPERTY")
    with pytest.raises(logic.SambaDnsZoneError) as raised:
        samba_dns_conn.set_zone_property(FakeConn(cause), "dc1.example.com", "example.com", "Aging", 1)
    assert str(raised.value) == "could not set Aging to 1 on zone 'example.com': WERR_DNS_ERROR_INVALID_PROPERTY"
    assert raised.value.__cause__ is cause
