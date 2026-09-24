# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_computer I/O layer.

A fake ``ldb`` module is injected, so these run without the samba bindings.
Importing the modules must also not require samba."""

from __future__ import annotations

import pytest
from ansible_collections.jomrr.samba.plugins.module_utils import samba_computer_io, samba_ldb
from ansible_collections.jomrr.samba.plugins.modules import samba_computer, samba_computer_info


class FakeDn:
    def __init__(self, text):
        self.text = text

    def parent(self):
        return FakeDn(self.text.split(",", 1)[1])

    def __eq__(self, other):
        return self.text.lower() == other.text.lower()


class FakeLdb:
    @staticmethod
    def Dn(samdb, text):
        return FakeDn(text)


def test_modules_import_without_samba():
    assert hasattr(samba_computer, "main")
    assert hasattr(samba_computer, "SambaComputerIO")
    assert hasattr(samba_computer_info, "main")


def test_find_returns_the_one_account_or_none(monkeypatch):
    state = {"name": "WS01", "dn": "CN=WS01,CN=Computers,DC=example,DC=com", "dns_host_name": None, "description": None}
    monkeypatch.setattr(samba_computer_io, "search", lambda samdb, name: [state] if name == "WS01" else [])
    io = samba_computer.SambaComputerIO(samdb=None)
    assert io.find("WS01") == state
    assert io.find("GHOST") is None


def test_the_default_container_is_the_computers_container(monkeypatch):
    monkeypatch.setattr(samba_ldb, "load_ldb", lambda: FakeLdb)
    monkeypatch.setattr(samba_ldb, "default_computers_dn", lambda samdb: FakeDn("CN=Computers,DC=example,DC=com"))
    monkeypatch.setattr(samba_ldb, "default_users_dn", lambda samdb: pytest.fail("computers do not default to the Users container"))
    io = samba_computer.SambaComputerIO(samdb=None)
    assert io.needs_move("CN=WS01,CN=Computers,DC=example,DC=com", None) is False
    assert io.needs_move("CN=WS01,OU=Servers,DC=example,DC=com", None) is True
