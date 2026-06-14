# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_provision I/O layer.

The samba bindings are faked via importlib, so these run without them while
exercising the verified parameter mapping and the local sam.ldb probe. Importing
the module must also not require samba (the litmus test for the layer
separation)."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_local
from ansible_collections.jomrr.samba.plugins.module_utils import samba_provision_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_provision


def test_module_imports_without_samba():
    assert hasattr(samba_provision, "main")
    assert hasattr(samba_provision, "SambaProvisionIO")


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


class FakeFunctionalLevel:
    # Mirrors samba.functional_level.string_to_level (verified mapping).
    _LEVELS = {"2000": 0, "2003": 2, "2008": 3, "2008_R2": 4, "2012": 5, "2012_R2": 6, "2016": 7}

    @classmethod
    def string_to_level(cls, value):
        return cls._LEVELS[value]


class FakeResult:
    domaindn = "DC=samdom,DC=example,DC=com"
    domainsid = "S-1-5-21-1-2-3"


class FakeProvisionModule:
    def __init__(self):
        self.captured = None

    def provision(self, logger, session, **kwargs):
        self.captured = kwargs
        return FakeResult()


def _patch_imports(monkeypatch, modules):
    monkeypatch.setattr(samba_provision.importlib, "import_module", lambda name: modules[name])


def test_io_provision_maps_parameters(monkeypatch):
    fake_prov = FakeProvisionModule()
    _patch_imports(monkeypatch, {
        "samba.param": FakeParam,
        "samba.provision": fake_prov,
        "samba.auth": FakeAuth,
        "samba.functional_level": FakeFunctionalLevel,
    })
    out = samba_provision.SambaProvisionIO(module=None).provision({
        "realm": "SAMDOM.EXAMPLE.COM",
        "domain": "SAMDOM",
        "hostname": "dc1",
        "admin_password": "S3cret-Passw0rd!",
        "dns_backend": "SAMBA_INTERNAL",
        "server_role": "dc",
        "function_level": "2016",
        "use_rfc2307": True,
    })
    cap = fake_prov.captured
    # The verified option -> provision() parameter mapping.
    assert cap["realm"] == "SAMDOM.EXAMPLE.COM"
    assert cap["domain"] == "SAMDOM"
    assert cap["hostname"] == "dc1"
    assert cap["adminpass"] == "S3cret-Passw0rd!"
    assert cap["dns_backend"] == "SAMBA_INTERNAL"
    assert cap["serverrole"] == "dc"
    assert cap["dom_for_fun_level"] == 7          # "2016" -> 7 via string_to_level
    assert cap["use_rfc2307"] is True
    # Only the non-secret identity is returned; no password.
    assert out == {"domaindn": "DC=samdom,DC=example,DC=com", "domainsid": "S-1-5-21-1-2-3"}
    assert "S3cret-Passw0rd!" not in repr(out)


def test_io_provision_failure_is_clean_error(monkeypatch):
    class BoomProvision:
        def provision(self, logger, session, **kwargs):
            raise RuntimeError("password does not meet the complexity requirements")

    _patch_imports(monkeypatch, {
        "samba.param": FakeParam,
        "samba.provision": BoomProvision(),
        "samba.auth": FakeAuth,
        "samba.functional_level": FakeFunctionalLevel,
    })
    with pytest.raises(logic.SambaProvisionError):
        samba_provision.SambaProvisionIO(module=None).provision({
            "realm": "SAMDOM.EXAMPLE.COM", "domain": "SAMDOM", "hostname": None,
            "admin_password": "weak", "dns_backend": "SAMBA_INTERNAL",
            "server_role": "dc", "function_level": "2008_R2", "use_rfc2307": False,
        })


# read_state delegates to the shared samba_local helper; these confirm the
# delegation (the helper's own open logic is covered by test_samba_local).
def test_io_read_state_not_provisioned(monkeypatch):
    monkeypatch.setattr(samba_local, "read_local_domain", lambda: None)
    assert samba_provision.SambaProvisionIO(module=None).read_state() is None


def test_io_read_state_provisioned(monkeypatch):
    monkeypatch.setattr(samba_local, "read_local_domain", lambda: {
        "domaindn": "DC=samdom,DC=example,DC=com",
        "domainsid": "S-1-5-21-9-9-9",
        "dnsdomain": "samdom.example.com",
    })
    state = samba_provision.SambaProvisionIO(module=None).read_state()
    # read_state surfaces only the non-secret identity it documents (no dnsdomain).
    assert state == {"domaindn": "DC=samdom,DC=example,DC=com", "domainsid": "S-1-5-21-9-9-9"}


def test_io_read_state_broken_raises(monkeypatch):
    def boom():
        raise samba_local.LocalSamdbError("a Samba database exists but is broken")

    monkeypatch.setattr(samba_local, "read_local_domain", boom)
    with pytest.raises(logic.SambaProvisionError):
        samba_provision.SambaProvisionIO(module=None).read_state()
