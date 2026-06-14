# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_join_member I/O layer.

The samba bindings are faked via importlib and the net binary via a fake module,
so these run without them while exercising the testjoin discriminator and the
join call's parameter mapping and credential handling. Importing the module must
also not require samba."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_join_member_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_join_member


def test_module_imports_without_samba():
    assert hasattr(samba_join_member, "main")
    assert hasattr(samba_join_member, "SambaJoinMemberIO")


# --- read_state: the net ads testjoin rc discriminator ---

class FakeModule:
    def __init__(self, rc):
        self._rc = rc
        self.commands = []

    def get_bin_path(self, name, required=False):
        return "/usr/bin/" + name

    def run_command(self, argv):
        self.commands.append(argv)
        return (self._rc, "", "")


class FakeLoadParm:
    def __init__(self):
        self.configfile = "/etc/samba/smb.conf"

    def load_default(self):
        pass

    def guess(self, *args):
        pass

    def get(self, key):
        return {"netbios name": "DERIVEDNB", "workgroup": "SAMDOM"}.get(key)


class FakeParam:
    LoadParm = FakeLoadParm

    @staticmethod
    def default_path():
        return "/etc/samba/smb.conf"


def test_io_read_state_not_a_member(monkeypatch):
    module = FakeModule(rc=1)
    state = samba_join_member.SambaJoinMemberIO(module=module).read_state()
    assert state is None
    # testjoin was the discriminator, and it carried no credentials on argv.
    assert module.commands == [["/usr/bin/net", "ads", "testjoin"]]


def test_io_read_state_member_returns_identity(monkeypatch):
    module = FakeModule(rc=0)
    monkeypatch.setattr(samba_join_member.importlib, "import_module", lambda name: {
        "samba.param": FakeParam,
    }[name])
    state = samba_join_member.SambaJoinMemberIO(module=module).read_state()
    assert state == {"workgroup": "SAMDOM", "netbios_name": "DERIVEDNB"}


# --- join: parameter mapping, derived netbios name, safe credentials ---

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


class FakeS3LoadParm:
    def __init__(self):
        self.loaded = None

    def load(self, path):
        self.loaded = path


class FakeS3Param:
    def __init__(self):
        self.context = FakeS3LoadParm()

    def get_context(self):
        return self.context


class FakeNet:
    def __init__(self, creds, s3_lp, server):
        self.creds = creds
        self.s3_lp = s3_lp
        self.server = server
        self.captured = None

    def join_member(self, netbios_name, machinepass=None):
        self.captured = {"netbios_name": netbios_name, "machinepass": machinepass}
        return ("S-1-5-21-7", "SAMDOM")


class FakeNetS3Mod:
    def __init__(self):
        self.last = None

    def Net(self, creds, s3_lp, server):
        self.last = FakeNet(creds, s3_lp, server)
        return self.last


def _join_params(**over):
    params = {
        "realm": "SAMDOM.EXAMPLE.COM",
        "server": "dc1.samdom.example.com",
        "bind_username": "Administrator",
        "bind_password": "S3cret-Passw0rd!",
        "machinepass": "M@chine-Passw0rd!",
        "state": "present",
    }
    params.update(over)
    return params


def _patch_join_imports(monkeypatch, net_s3, creds_mod, s3param):
    monkeypatch.setattr(samba_join_member.importlib, "import_module", lambda name: {
        "samba.net_s3": net_s3,
        "samba.credentials": creds_mod,
        "samba.param": FakeParam,
        "samba.samba3.param": s3param,
    }[name])


def test_io_join_maps_parameters_and_uses_credentials(monkeypatch):
    net_s3 = FakeNetS3Mod()
    creds_mod = FakeCredentialsMod()
    s3param = FakeS3Param()
    _patch_join_imports(monkeypatch, net_s3, creds_mod, s3param)

    out = samba_join_member.SambaJoinMemberIO(module=None).join(_join_params())

    cap = net_s3.last.captured
    # netbios_name is derived from loadparm (never passed as None, the join_DC
    # lesson), and the machine password is forwarded through the kwarg.
    assert cap["netbios_name"] == "DERIVEDNB"
    assert cap["machinepass"] == "M@chine-Passw0rd!"
    assert net_s3.last.server == "dc1.samdom.example.com"
    # The s3 LoadParm was loaded from the existing smb.conf the role provides.
    assert s3param.context.loaded == "/etc/samba/smb.conf"
    # The bind password reaches samba only through the credentials object
    # (set_password), never as a command-line argument.
    assert creds_mod.last.calls["password"] == "S3cret-Passw0rd!"
    assert creds_mod.last.calls["username"] == "Administrator"
    assert net_s3.last.creds is creds_mod.last
    # Only the non-secret identity is returned; no password.
    assert out == {"workgroup": "SAMDOM", "netbios_name": "DERIVEDNB", "domainsid": "S-1-5-21-7"}
    assert "S3cret-Passw0rd!" not in repr(out)
    assert "M@chine-Passw0rd!" not in repr(out)


def test_io_join_machinepass_none_is_passed_through(monkeypatch):
    # machinepass=None is the verified-safe default samba-tool itself passes; the
    # binding generates a strong machine password, so the module forwards None
    # rather than inventing one.
    net_s3 = FakeNetS3Mod()
    _patch_join_imports(monkeypatch, net_s3, FakeCredentialsMod(), FakeS3Param())

    samba_join_member.SambaJoinMemberIO(module=None).join(_join_params(machinepass=None))

    assert net_s3.last.captured["machinepass"] is None


def test_io_join_failure_is_clean_error(monkeypatch):
    class BoomNet:
        def __init__(self, creds, s3_lp, server):
            pass

        def join_member(self, netbios_name, machinepass=None):
            raise RuntimeError("failed to connect to the existing DC")

    class BoomNetS3Mod:
        Net = BoomNet

    _patch_join_imports(monkeypatch, BoomNetS3Mod(), FakeCredentialsMod(), FakeS3Param())

    with pytest.raises(logic.SambaJoinMemberError):
        samba_join_member.SambaJoinMemberIO(module=None).join(_join_params())
