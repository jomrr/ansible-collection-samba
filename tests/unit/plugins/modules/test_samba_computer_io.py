# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the computer account filter, mapping and search.

Shared by samba_computer and samba_computer_info. A fake ``ldb`` module and
SamDB are injected, so these run without the samba bindings."""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils import samba_computer_io, samba_ldb

DC_EXCLUSION = "(!(userAccountControl:1.2.840.113556.1.4.804:=67117056))"


class FakeLdb:
    SCOPE_SUBTREE = 2

    @staticmethod
    def binary_encode(value):
        return f"ESC({value})"


class FakeMessage:
    def __init__(self, dn, attrs):
        self.dn = dn
        self._attrs = attrs

    def get(self, attr):
        return self._attrs.get(attr)


class FakeSamDB:
    """Captures the search expression and returns canned messages."""

    def __init__(self, result):
        self.result = result
        self.expression = None

    def domain_dn(self):
        return "DC=example,DC=com"

    def search(self, base, scope, expression, attrs):
        self.expression = expression
        return self.result


def test_the_filter_excludes_domain_controllers_and_service_accounts():
    # objectCategory=computer leaves the managed service accounts out; the
    # bitwise-OR rule leaves out UF_SERVER_TRUST_ACCOUNT | UF_PARTIAL_SECRETS_ACCOUNT.
    assert samba_computer_io.computer_filter() == f"(&(objectCategory=computer){DC_EXCLUSION})"
    assert samba_computer_io.computer_filter("ESC(WS01$)") == f"(&(objectCategory=computer){DC_EXCLUSION}(sAMAccountName=ESC(WS01$)))"


def test_the_account_name_accepts_a_trailing_dollar():
    assert samba_computer_io.account_name("WS01") == "WS01$"
    assert samba_computer_io.account_name("WS01$") == "WS01$"


def test_search_escapes_the_account_and_maps_the_state(monkeypatch):
    monkeypatch.setattr(samba_ldb, "load_ldb", lambda: FakeLdb)
    samdb = FakeSamDB([
        FakeMessage("CN=WS01,OU=Servers,DC=example,DC=com", {"sAMAccountName": ["WS01$"], "dNSHostName": ["ws01.example.com"]}),
    ])
    assert samba_computer_io.search(samdb, "WS01") == [
        {"name": "WS01", "dn": "CN=WS01,OU=Servers,DC=example,DC=com", "dns_host_name": "ws01.example.com", "description": None},
    ]
    assert samdb.expression == samba_computer_io.computer_filter("ESC(WS01$)")


def test_search_without_a_name_lists_every_managed_account(monkeypatch):
    monkeypatch.setattr(samba_ldb, "load_ldb", lambda: FakeLdb)
    samdb = FakeSamDB([
        FakeMessage("CN=WS01,CN=Computers,DC=example,DC=com", {"sAMAccountName": ["WS01$"]}),
        FakeMessage("CN=WS02,CN=Computers,DC=example,DC=com", {"sAMAccountName": ["WS02$"]}),
    ])
    assert [state["name"] for state in samba_computer_io.search(samdb)] == ["WS01", "WS02"]
    assert samdb.expression == samba_computer_io.computer_filter()
