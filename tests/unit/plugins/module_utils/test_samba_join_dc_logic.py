# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the pure samba_join_dc logic (no samba bindings required)."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_join_dc_logic as logic


class FakeIO:
    """Records calls and simulates the local DC state; no samba required."""

    def __init__(self, state=None, broken=False):
        self._state = state
        self._broken = broken
        self.calls = []

    def read_state(self):
        self.calls.append("read_state")
        if self._broken:
            raise logic.SambaJoinDcError("a Samba database exists but could not be opened")
        return self._state

    def join(self, params):
        self.calls.append("join")
        return {"domaindn": "DC=samdom,DC=example,DC=com", "domainsid": "S-1-5-21-1-2-3"}


def make_params(**over):
    params = {
        "realm": "SAMDOM.EXAMPLE.COM",
        "server": "dc1.samdom.example.com",
        "bind_username": "Administrator",
        "bind_password": "S3cret-Passw0rd!",
        "domain": None,
        "netbios_name": None,
        "site": None,
        "dns_backend": "SAMBA_INTERNAL",
        "state": "present",
    }
    params.update(over)
    return params


def _target_state(**over):
    state = {
        "dnsdomain": "samdom.example.com",
        "domaindn": "DC=samdom,DC=example,DC=com",
        "domainsid": "S-1-5-21-1",
    }
    state.update(over)
    return state


def test_not_a_dc_joins():
    io = FakeIO(state=None)
    result = logic.run(make_params(), False, io)
    assert result["changed"] is True
    assert result["joined"] is True
    assert "join" in io.calls
    assert result["domain"]["domaindn"] == "DC=samdom,DC=example,DC=com"


def test_already_dc_of_target_is_noop():
    io = FakeIO(state=_target_state())
    result = logic.run(make_params(), False, io)
    assert result["changed"] is False
    assert result["joined"] is True
    assert "join" not in io.calls  # an existing matching DC is never re-joined
    assert result["domain"]["domaindn"] == "DC=samdom,DC=example,DC=com"


def test_already_dc_of_foreign_domain_fails():
    io = FakeIO(state=_target_state(dnsdomain="other.example.org",
                                    domaindn="DC=other,DC=example,DC=org"))
    with pytest.raises(logic.SambaJoinDcError):
        logic.run(make_params(), False, io)
    assert "join" not in io.calls  # never overwrite an existing different domain


def test_realm_match_is_case_insensitive():
    io = FakeIO(state=_target_state())
    result = logic.run(make_params(realm="samdom.EXAMPLE.com"), False, io)
    assert result["changed"] is False


def test_check_mode_does_not_join():
    io = FakeIO(state=None)
    result = logic.run(make_params(), True, io)
    assert result["changed"] is True
    assert result["joined"] is False
    assert result["domain"] is None
    assert "join" not in io.calls


def test_check_mode_already_joined_is_noop():
    io = FakeIO(state=_target_state())
    result = logic.run(make_params(), True, io)
    assert result["changed"] is False
    assert "join" not in io.calls


def test_join_requires_bind_password():
    io = FakeIO(state=None)
    with pytest.raises(logic.SambaJoinDcError):
        logic.run(make_params(bind_password=None), False, io)
    assert "join" not in io.calls


def test_join_requires_bind_password_even_in_check_mode():
    io = FakeIO(state=None)
    with pytest.raises(logic.SambaJoinDcError):
        logic.run(make_params(bind_password=None), True, io)


def test_broken_local_db_raises():
    io = FakeIO(broken=True)
    with pytest.raises(logic.SambaJoinDcError):
        logic.run(make_params(), False, io)


def test_password_not_leaked_in_result():
    io = FakeIO(state=None)
    result = logic.run(make_params(bind_password="S3cret-Passw0rd!"), False, io)
    assert "S3cret-Passw0rd!" not in repr(result)
