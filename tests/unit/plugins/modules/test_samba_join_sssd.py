# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_join_sssd I/O layer.

adcli is faked via a fake module (no real tool, no samba), so these exercise the
local keytab discriminator (no subprocess, no DC) and the join command's
argument building - in particular that the password is fed on stdin (data=)
and never appears in argv."""

from __future__ import annotations

import struct

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_join_sssd_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils import samba_keytab
from ansible_collections.jomrr.samba.plugins.modules import samba_join_sssd


def test_module_imports():
    assert hasattr(samba_join_sssd, "main")
    assert hasattr(samba_join_sssd, "SambaJoinSssdIO")


class FakeModule:
    """Stands in for AnsibleModule: records run_command calls and their stdin.

    Deliberately without ``params``: the I/O gets the module parameters handed
    in and must not reach for them through the module.
    """

    def __init__(self, adcli="/usr/bin/adcli", join_rc=0, join_err=""):
        self.adcli = adcli
        self.join_rc = join_rc
        self.join_err = join_err
        self.commands = []  # list of (argv, data)

    def get_bin_path(self, name, required=False):
        return self.adcli

    def run_command(self, argv, data=None):
        self.commands.append((argv, data))
        if "join" in argv:
            return (self.join_rc, "", self.join_err)
        return (0, "", "")


def _join_params(**over):
    params = {
        "realm": "SAMDOM.EXAMPLE.COM",
        "server": "dc1.samdom.example.com",
        "bind_username": "Administrator",
        "bind_password": "S3cret-Passw0rd!",
        "computer_ou": "OU=Linux,DC=samdom,DC=example,DC=com",
        "host_fqdn": "client1.samdom.example.com",
        "keytab": "/etc/krb5.keytab",
        "force": False,
        "state": "present",
    }
    params.update(over)
    return params


# --- read_state: the local keytab discriminator ---

def _octets(text):
    raw = text.encode()
    return struct.pack(">H", len(raw)) + raw


def _keytab(*principals):
    """A version 2 keytab holding the given ``(realm, components)`` principals."""
    out = b"\x05\x02"
    for realm, components in principals:
        body = struct.pack(">H", len(components)) + _octets(realm) + b"".join(_octets(c) for c in components)
        body += struct.pack(">IIB", 1, 0, 2) + struct.pack(">HH", 18, 4) + b"\x00" * 4
        out += struct.pack(">i", len(body)) + body
    return out


@pytest.fixture()
def keytab_path(tmp_path):
    return tmp_path / "krb5.keytab"


def _read_state(module, keytab_path, **over):
    """read_state with the keytab option pointing at the test file."""
    return samba_join_sssd.SambaJoinSssdIO(module=module).read_state(_join_params(keytab=str(keytab_path), **over))


def test_io_read_state_no_keytab_means_not_joined(keytab_path):
    module = FakeModule()
    assert _read_state(module, keytab_path) is None
    # The decision is local: no adcli, no DC.
    assert module.commands == []


def test_io_read_state_host_principal_means_joined(keytab_path):
    keytab_path.write_bytes(_keytab(("SAMDOM.EXAMPLE.COM", ["host", "client1.samdom.example.com"])))
    module = FakeModule()
    state = _read_state(module, keytab_path)
    assert state == {"realm": "SAMDOM.EXAMPLE.COM", "keytab": str(keytab_path)}
    assert module.commands == []


def test_io_read_state_machine_account_principal_means_joined(keytab_path):
    keytab_path.write_bytes(_keytab(("SAMDOM.EXAMPLE.COM", ["CLIENT1$"])))
    assert _read_state(FakeModule(), keytab_path) is not None


def test_io_read_state_realm_is_case_insensitive(keytab_path):
    keytab_path.write_bytes(_keytab(("SAMDOM.EXAMPLE.COM", ["host", "client1"])))
    assert _read_state(FakeModule(), keytab_path, realm="samdom.example.com") is not None


def test_io_read_state_reads_the_keytab_the_option_names(keytab_path, tmp_path):
    # The default keytab is joined, the one the option names is not: the
    # option decides, not a fixed path.
    keytab_path.write_bytes(_keytab(("SAMDOM.EXAMPLE.COM", ["host", "client1"])))
    assert _read_state(FakeModule(), tmp_path / "other.keytab") is None


def test_io_read_state_other_realm_or_service_principal_is_not_joined(keytab_path):
    keytab_path.write_bytes(_keytab(
        ("OTHER.EXAMPLE.COM", ["host", "client1.other.example.com"]),
        ("SAMDOM.EXAMPLE.COM", ["HTTP", "www.samdom.example.com"]),
    ))
    assert _read_state(FakeModule(), keytab_path) is None


def test_io_read_state_unreadable_keytab_is_clean_error(keytab_path, monkeypatch):
    def denied(path):
        raise PermissionError("denied")

    monkeypatch.setattr(samba_keytab, "read_principals", denied)
    with pytest.raises(logic.SambaJoinSssdError):
        _read_state(FakeModule(), keytab_path)


def test_io_read_state_malformed_keytab_is_clean_error(keytab_path):
    keytab_path.write_bytes(b"\x05\x01garbage")
    with pytest.raises(logic.SambaJoinSssdError):
        _read_state(FakeModule(), keytab_path)


def test_io_missing_adcli_raises_on_join():
    module = FakeModule(adcli=None)
    with pytest.raises(logic.SambaJoinSssdError):
        samba_join_sssd.SambaJoinSssdIO(module=module).join(_join_params())


# --- join: argument building and the critical stdin-password security property ---

def test_io_join_feeds_password_on_stdin_not_argv():
    module = FakeModule(join_rc=0)
    out = samba_join_sssd.SambaJoinSssdIO(module=module).join(_join_params())

    argv, data = module.commands[0]
    # THE security assertion: the password is on stdin, never in argv.
    assert data == "S3cret-Passw0rd!"
    assert all("S3cret-Passw0rd!" not in str(a) for a in argv)
    assert "--stdin-password" in argv
    # Verified flag mapping.
    assert "--domain=SAMDOM.EXAMPLE.COM" in argv
    assert "--login-user=Administrator" in argv
    assert "--domain-controller=dc1.samdom.example.com" in argv
    assert "--host-fqdn=client1.samdom.example.com" in argv
    assert "--domain-ou=OU=Linux,DC=samdom,DC=example,DC=com" in argv
    assert "--host-keytab=/etc/krb5.keytab" in argv
    # Only the non-secret identity is returned; no password.
    assert out == {"realm": "SAMDOM.EXAMPLE.COM", "keytab": "/etc/krb5.keytab"}
    assert "S3cret-Passw0rd!" not in repr(out)


def test_io_join_writes_the_keytab_the_option_names():
    module = FakeModule(join_rc=0)
    out = samba_join_sssd.SambaJoinSssdIO(module=module).join(_join_params(keytab="/var/lib/sss/keytabs/host.keytab"))
    assert "--host-keytab=/var/lib/sss/keytabs/host.keytab" in module.commands[0][0]
    assert out["keytab"] == "/var/lib/sss/keytabs/host.keytab"


def test_io_join_omits_unset_optional_flags():
    module = FakeModule(join_rc=0)
    samba_join_sssd.SambaJoinSssdIO(module=module).join(
        _join_params(server=None, host_fqdn=None, computer_ou=None)
    )
    argv = module.commands[0][0]
    assert not any(a.startswith("--domain-controller") for a in argv)
    assert not any(a.startswith("--host-fqdn") for a in argv)
    assert not any(a.startswith("--domain-ou") for a in argv)
    # The required parts remain.
    assert "--domain=SAMDOM.EXAMPLE.COM" in argv
    assert "--stdin-password" in argv


def test_io_join_failure_is_clean_error():
    module = FakeModule(join_rc=1, join_err="Couldn't authenticate as: Administrator")
    with pytest.raises(logic.SambaJoinSssdError) as excinfo:
        samba_join_sssd.SambaJoinSssdIO(module=module).join(_join_params())
    # The diagnostic is surfaced, the password is not.
    assert "S3cret-Passw0rd!" not in str(excinfo.value)
