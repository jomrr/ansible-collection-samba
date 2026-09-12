# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the shared local-directory helper.

The samba bindings are faked via importlib, so these run without them while
exercising the local sam.ldb open and the states it distinguishes: not a DC, a
DC, not permitted to open, broken."""

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


class FakeLdbError(Exception):
    """Stand-in for ldb.LdbError; args are (code, message)."""


class FakeLdbMod:
    ERR_INSUFFICIENT_ACCESS_RIGHTS = 50
    LdbError = FakeLdbError


def _patch_imports(monkeypatch, modules):
    monkeypatch.setattr(samba_local.importlib, "import_module", lambda name: modules[name])


def _patch_dc(monkeypatch, samdb_cls):
    """A sam.ldb exists and opens through ``samdb_cls``."""

    class FakeSamdbMod:
        SamDB = samdb_cls

    _patch_imports(monkeypatch, {
        "samba.param": FakeParam, "samba.auth": FakeAuth, "samba.samdb": FakeSamdbMod, "ldb": FakeLdbMod,
    })
    monkeypatch.setattr(samba_local.os.path, "exists", lambda path: True)


def _boom(exc):
    """A SamDB whose open raises ``exc``."""

    class BoomSamDB:
        def __init__(self, url, session_info, lp):
            raise exc

    return BoomSamDB


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

        def domain_dns_name(self):
            return "SAMDOM.Example.com"

    _patch_dc(monkeypatch, FakeSamDB)
    assert samba_local.read_local_domain() == {
        "domaindn": "DC=samdom,DC=example,DC=com",
        "domainsid": "S-1-5-21-9-9-9",
        # samba's own domain_dns_name(), lowercased for realm matching
        "dnsdomain": "samdom.example.com",
    }


def test_read_local_domain_broken_raises(monkeypatch):
    _patch_dc(monkeypatch, _boom(FakeLdbError(1, "Unable to open tdb '/var/lib/samba/private/sam.ldb': Input/output error")))
    with pytest.raises(samba_local.LocalSamdbError) as raised:
        samba_local.read_local_domain()
    text = str(raised.value)
    assert "partially provisioned or corrupt" in text
    # the ldb message itself, not the (code, message) tuple
    assert "Input/output error" in text
    assert "(1, " not in text


def test_read_local_domain_permission_problem_is_not_called_corrupt(monkeypatch):
    _patch_dc(monkeypatch, _boom(FakeLdbError(50, "Unable to open tdb '/var/lib/samba/private/sam.ldb': Permission denied")))
    with pytest.raises(samba_local.LocalSamdbError) as raised:
        samba_local.read_local_domain()
    text = str(raised.value)
    assert "not allowed to open" in text
    assert "Permission denied" in text
    assert "corrupt" not in text


def test_read_local_domain_non_ldb_error_is_reported_as_broken(monkeypatch):
    _patch_dc(monkeypatch, _boom(RuntimeError("unable to open tdb: corrupt")))
    with pytest.raises(samba_local.LocalSamdbError) as raised:
        samba_local.read_local_domain()
    assert "partially provisioned or corrupt" in str(raised.value)
