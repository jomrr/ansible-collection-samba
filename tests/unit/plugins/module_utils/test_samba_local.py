# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the shared local-directory helper.

The samba bindings are faked via importlib, so these run without them while
exercising the local sam.ldb open and the three states it distinguishes."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_local


class FakeLoadParm:
    def load_default(self):
        pass

    def private_path(self, name):
        return "/var/lib/samba/private/" + name


class FakeParam:
    LoadParm = FakeLoadParm


class FakeAuth:
    @staticmethod
    def system_session():
        return "SYSTEM_SESSION"


def _patch_imports(monkeypatch, modules):
    monkeypatch.setattr(samba_local.importlib, "import_module", lambda name: modules[name])


def test_read_local_domain_not_a_dc(monkeypatch):
    _patch_imports(monkeypatch, {"samba.param": FakeParam})
    monkeypatch.setattr(samba_local.os.path, "exists", lambda path: False)
    assert samba_local.read_local_domain() is None


def test_read_local_domain_returns_identity(monkeypatch):
    class FakeSamDB:
        def __init__(self, url, session_info, lp):
            self.url = url

        def domain_dn(self):
            return "DC=samdom,DC=example,DC=com"

        def get_domain_sid(self):
            return "S-1-5-21-9-9-9"

    class FakeSamdbMod:
        SamDB = FakeSamDB

    _patch_imports(monkeypatch, {
        "samba.param": FakeParam, "samba.auth": FakeAuth, "samba.samdb": FakeSamdbMod,
    })
    monkeypatch.setattr(samba_local.os.path, "exists", lambda path: True)
    assert samba_local.read_local_domain() == {
        "domaindn": "DC=samdom,DC=example,DC=com",
        "domainsid": "S-1-5-21-9-9-9",
        # derived from the domain DN, lowercased, for realm matching
        "dnsdomain": "samdom.example.com",
    }


def test_read_local_domain_broken_raises(monkeypatch):
    class BoomSamDB:
        def __init__(self, url, session_info, lp):
            raise RuntimeError("unable to open tdb: corrupt")

    class FakeSamdbMod:
        SamDB = BoomSamDB

    _patch_imports(monkeypatch, {
        "samba.param": FakeParam, "samba.auth": FakeAuth, "samba.samdb": FakeSamdbMod,
    })
    monkeypatch.setattr(samba_local.os.path, "exists", lambda path: True)
    with pytest.raises(samba_local.LocalSamdbError):
        samba_local.read_local_domain()
