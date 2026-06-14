# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_join_dc I/O layer.

The samba bindings are faked via importlib, so these run without them while
exercising the join call's parameter mapping and credential handling. Importing
the module must also not require samba."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_local
from ansible_collections.jomrr.samba.plugins.module_utils import samba_join_dc_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_join_dc


def test_module_imports_without_samba():
    assert hasattr(samba_join_dc, "main")
    assert hasattr(samba_join_dc, "SambaJoinDcIO")


def test_io_read_state_delegates_to_shared_helper(monkeypatch):
    monkeypatch.setattr(samba_local, "read_local_domain", lambda: {
        "dnsdomain": "samdom.example.com",
        "domaindn": "DC=samdom,DC=example,DC=com",
        "domainsid": "S-1-5-21-1",
    })
    state = samba_join_dc.SambaJoinDcIO(module=None).read_state()
    assert state["dnsdomain"] == "samdom.example.com"


def test_io_read_state_broken_raises(monkeypatch):
    def boom():
        raise samba_local.LocalSamdbError("a Samba database exists but is broken")

    monkeypatch.setattr(samba_local, "read_local_domain", boom)
    with pytest.raises(logic.SambaJoinDcError):
        samba_join_dc.SambaJoinDcIO(module=None).read_state()


class FakeLoadParm:
    def load_default(self):
        pass

    def set(self, *args):
        pass

    def private_path(self, name):
        return "/var/lib/samba/private/" + name


class FakeParam:
    LoadParm = FakeLoadParm


class FakeCredentials:
    def __init__(self):
        self.calls = {}

    def guess(self, lp):
        self.calls["guess"] = True

    def set_username(self, username):
        self.calls["username"] = username

    def set_password(self, password):
        self.calls["password"] = password

    def set_realm(self, realm):
        self.calls["realm"] = realm


class FakeCredentialsMod:
    def __init__(self):
        self.last = None

    def Credentials(self):
        self.last = FakeCredentials()
        return self.last


class FakeJoinMod:
    def __init__(self):
        self.captured = None

    def join_DC(self, **kwargs):
        self.captured = kwargs


def _join_params(**over):
    params = {
        "realm": "SAMDOM.EXAMPLE.COM",
        "server": "dc1.samdom.example.com",
        "bind_username": "Administrator",
        "bind_password": "S3cret-Passw0rd!",
        "domain": None,
        "netbios_name": "DC2",
        "site": "Default-First-Site-Name",
        "dns_backend": "SAMBA_INTERNAL",
    }
    params.update(over)
    return params


def test_io_join_maps_parameters_and_uses_credentials(monkeypatch):
    fake_join = FakeJoinMod()
    fake_creds = FakeCredentialsMod()
    monkeypatch.setattr(samba_join_dc.importlib, "import_module", lambda name: {
        "samba.join": fake_join,
        "samba.credentials": fake_creds,
        "samba.param": FakeParam,
    }[name])
    monkeypatch.setattr(samba_local, "read_local_domain", lambda: {
        "domaindn": "DC=samdom,DC=example,DC=com",
        "domainsid": "S-1-5-21-7",
        "dnsdomain": "samdom.example.com",
    })

    out = samba_join_dc.SambaJoinDcIO(module=None).join(_join_params())

    cap = fake_join.captured
    assert cap["server"] == "dc1.samdom.example.com"
    assert cap["netbios_name"] == "DC2"
    assert cap["site"] == "Default-First-Site-Name"
    assert cap["dns_backend"] == "SAMBA_INTERNAL"
    # The password reaches samba only through the credentials object (set_password),
    # never as a command-line argument.
    assert fake_creds.last.calls["password"] == "S3cret-Passw0rd!"
    assert fake_creds.last.calls["username"] == "Administrator"
    assert cap["creds"] is fake_creds.last
    # Only the non-secret identity is returned; no password.
    assert out == {"domaindn": "DC=samdom,DC=example,DC=com", "domainsid": "S-1-5-21-7"}
    assert "S3cret-Passw0rd!" not in repr(out)


def test_io_join_failure_is_clean_error(monkeypatch):
    class BoomJoin:
        def join_DC(self, **kwargs):
            raise RuntimeError("failed to connect to the existing DC")

    monkeypatch.setattr(samba_join_dc.importlib, "import_module", lambda name: {
        "samba.join": BoomJoin(),
        "samba.credentials": FakeCredentialsMod(),
        "samba.param": FakeParam,
    }[name])
    with pytest.raises(logic.SambaJoinDcError):
        samba_join_dc.SambaJoinDcIO(module=None).join(_join_params())
