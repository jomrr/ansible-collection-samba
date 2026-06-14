# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the pure samba_provision logic.

These run in the sanity/units container WITHOUT the samba bindings; the logic
layer must not require them."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_provision_logic as logic


class FakeIO:
    """Records calls and simulates the provision state; no samba required."""

    def __init__(self, state=None, broken=False):
        self._state = state
        self._broken = broken
        self.calls = []

    def read_state(self):
        self.calls.append("read_state")
        if self._broken:
            raise logic.SambaProvisionError("a Samba database exists but could not be opened")
        return self._state

    def provision(self, params):
        self.calls.append("provision")
        return {"domaindn": "DC=samdom,DC=example,DC=com", "domainsid": "S-1-5-21-1-2-3"}


def make_params(**over):
    params = {
        "realm": "SAMDOM.EXAMPLE.COM",
        "domain": "SAMDOM",
        "hostname": None,
        "admin_password": "S3cret-Passw0rd!",
        "dns_backend": "SAMBA_INTERNAL",
        "server_role": "dc",
        "function_level": "2008_R2",
        "use_rfc2307": False,
        "state": "present",
    }
    params.update(over)
    return params


def test_already_provisioned_is_noop():
    io = FakeIO(state={"domaindn": "DC=samdom,DC=example,DC=com", "domainsid": "S-1-5-21-1"})
    result = logic.run(make_params(), False, io)
    assert result["changed"] is False
    assert result["provisioned"] is True
    assert result["domain"]["domaindn"] == "DC=samdom,DC=example,DC=com"
    assert "provision" not in io.calls  # an existing domain is never re-provisioned


def test_not_provisioned_provisions():
    io = FakeIO(state=None)
    result = logic.run(make_params(), False, io)
    assert result["changed"] is True
    assert result["provisioned"] is True
    assert "provision" in io.calls
    assert result["domain"]["domaindn"] == "DC=samdom,DC=example,DC=com"


def test_check_mode_does_not_provision():
    io = FakeIO(state=None)
    result = logic.run(make_params(), True, io)
    assert result["changed"] is True
    assert result["provisioned"] is False
    assert result["domain"] is None
    assert "provision" not in io.calls


def test_check_mode_already_provisioned_is_noop():
    io = FakeIO(state={"domaindn": "DC=x,DC=y", "domainsid": "S-1-5-21-1"})
    result = logic.run(make_params(), True, io)
    assert result["changed"] is False
    assert "provision" not in io.calls


def test_provision_requires_admin_password():
    io = FakeIO(state=None)
    with pytest.raises(logic.SambaProvisionError):
        logic.run(make_params(admin_password=None), False, io)
    assert "provision" not in io.calls


def test_provision_requires_admin_password_even_in_check_mode():
    io = FakeIO(state=None)
    with pytest.raises(logic.SambaProvisionError):
        logic.run(make_params(admin_password=None), True, io)


def test_broken_install_raises():
    io = FakeIO(broken=True)
    with pytest.raises(logic.SambaProvisionError):
        logic.run(make_params(), False, io)


def test_password_not_leaked_in_result():
    io = FakeIO(state=None)
    result = logic.run(make_params(admin_password="S3cret-Passw0rd!"), False, io)
    assert "S3cret-Passw0rd!" not in repr(result)
