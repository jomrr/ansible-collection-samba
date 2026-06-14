# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for samba_conn.

These run in the units container WITHOUT the samba bindings - importing the
module_utils must not require samba. The GSSAPI connection logic is exercised by
faking the lazily-imported samba modules, which lets us assert the security
properties (forced sealing, required Kerberos, in-memory ccache, no credential
leak) without a DC."""

from __future__ import annotations

import importlib
import os

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_conn


def test_import_does_not_require_samba():
    assert hasattr(samba_conn, "has_samba_bindings")


def test_has_samba_bindings_returns_bool():
    assert isinstance(samba_conn.has_samba_bindings(), bool)


def test_bind_password_is_no_log_and_required():
    spec = samba_conn.connection_argument_spec()
    assert spec["bind_password"]["no_log"] is True
    assert spec["bind_password"]["required"] is True
    assert set(spec) == {"server", "bind_username", "bind_password", "realm"}


# --- Fakes for the lazily-imported samba modules ---------------------------

class FakeLoadParm:
    def __init__(self):
        self.settings = {}

    def load_default(self):
        pass

    def set(self, key, value):
        self.settings[key] = value


class FakeCredentials:
    instances = []

    def __init__(self):
        self.calls = {}
        FakeCredentials.instances.append(self)

    def set_username(self, value):
        self.calls["username"] = value

    def set_password(self, value):
        self.calls["password"] = value

    def set_realm(self, value):
        self.calls["realm"] = value

    def set_kerberos_state(self, value):
        self.calls["kerberos_state"] = value


class FakeCredentialsModule:
    MUST_USE_KERBEROS = 2
    Credentials = FakeCredentials


class FakeSamDB:
    instances = []
    fail = False

    def __init__(self, url=None, credentials=None, lp=None):
        self.url = url
        self.credentials = credentials
        self.lp = lp
        FakeSamDB.instances.append(self)
        if FakeSamDB.fail:
            raise RuntimeError("LDAP bind to the DC failed")


class FakeSamDBModule:
    SamDB = FakeSamDB


class FakeParamModule:
    LoadParm = FakeLoadParm


class AnsibleFailJson(Exception):
    """Raised by the fake module's fail_json to capture the failure result."""


class FakeModule:
    def __init__(self, params):
        self.params = params

    def fail_json(self, **kwargs):
        raise AnsibleFailJson(kwargs)


_FAKE_SAMBA = {
    "samba.param": FakeParamModule,
    "samba.credentials": FakeCredentialsModule,
    "samba.samdb": FakeSamDBModule,
}


@pytest.fixture
def conn_env(monkeypatch):
    """Pretend the bindings exist and return the fakes for samba.* imports."""
    real_import = importlib.import_module

    def fake_import(name, *args, **kwargs):
        return _FAKE_SAMBA.get(name) or real_import(name, *args, **kwargs)

    monkeypatch.setattr(samba_conn, "has_samba_bindings", lambda: True)
    monkeypatch.setattr(samba_conn.importlib, "import_module", fake_import)
    FakeCredentials.instances = []
    FakeSamDB.instances = []
    FakeSamDB.fail = False
    saved_ccname = os.environ.get("KRB5CCNAME")
    yield
    if saved_ccname is None:
        os.environ.pop("KRB5CCNAME", None)
    else:
        os.environ["KRB5CCNAME"] = saved_ccname


def _params(**over):
    params = {
        "server": "dc.example.com",
        "bind_username": "Administrator",
        "bind_password": "S3cr3t-pw!",
        "realm": "EXAMPLE.COM",
    }
    params.update(over)
    return params


def test_connect_forces_sealing(conn_env):
    samba_conn.connect_samdb(FakeModule(_params()))
    samdb = FakeSamDB.instances[-1]
    # The bind requires the SASL sealing layer (no plain/sign downgrade).
    assert samdb.lp.settings["client ldap sasl wrapping"] == "seal"
    assert samdb.url == "ldap://dc.example.com"


def test_connect_requires_kerberos(conn_env):
    samba_conn.connect_samdb(FakeModule(_params()))
    creds = FakeCredentials.instances[-1]
    # MUST_USE_KERBEROS - fail rather than downgrade to NTLM.
    assert creds.calls["kerberos_state"] == FakeCredentialsModule.MUST_USE_KERBEROS


def test_ticket_is_held_in_memory_ccache(conn_env):
    samba_conn.connect_samdb(FakeModule(_params()))
    # The ticket cache is an in-memory cache; nothing is written to disk.
    assert os.environ["KRB5CCNAME"].startswith("MEMORY:")


def test_realm_derived_from_server_when_omitted(conn_env):
    samba_conn.connect_samdb(FakeModule(_params(realm=None)))
    creds = FakeCredentials.instances[-1]
    assert creds.calls["realm"] == "EXAMPLE.COM"


def test_connect_failure_does_not_leak_credentials(conn_env):
    # An authentication/bind failure surfaces here; the error must not carry the
    # password or user name.
    FakeSamDB.fail = True
    with pytest.raises(AnsibleFailJson) as raised:
        samba_conn.connect_samdb(FakeModule(_params()))
    blob = str(raised.value.args[0])
    assert "S3cr3t-pw!" not in blob
    assert "Administrator" not in blob
