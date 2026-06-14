# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the pure samba_join_sssd logic (no adcli required)."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_join_sssd_logic as logic


class FakeIO:
    """Records calls and simulates the local join state; no adcli required."""

    def __init__(self, state=None, missing=False):
        self._state = state
        self._missing = missing
        self.calls = []

    def read_state(self):
        self.calls.append("read_state")
        if self._missing:
            raise logic.SambaJoinSssdError("adcli was not found in PATH")
        return self._state

    def join(self, params):
        self.calls.append("join")
        return {"realm": "SAMDOM.EXAMPLE.COM", "keytab": "/etc/krb5.keytab"}


def make_params(**over):
    params = {
        "realm": "SAMDOM.EXAMPLE.COM",
        "server": None,
        "bind_username": "Administrator",
        "bind_password": "S3cret-Passw0rd!",
        "computer_ou": None,
        "host_fqdn": None,
        "state": "present",
    }
    params.update(over)
    return params


def _joined_state(**over):
    state = {"realm": "SAMDOM.EXAMPLE.COM", "keytab": "/etc/krb5.keytab"}
    state.update(over)
    return state


def test_not_joined_joins():
    io = FakeIO(state=None)
    result = logic.run(make_params(), False, io)
    assert result["changed"] is True
    assert result["joined"] is True
    assert "join" in io.calls
    assert result["domain"]["realm"] == "SAMDOM.EXAMPLE.COM"


def test_already_joined_is_noop():
    io = FakeIO(state=_joined_state())
    result = logic.run(make_params(), False, io)
    assert result["changed"] is False
    assert result["joined"] is True
    assert "join" not in io.calls  # an existing valid join is never re-joined
    assert result["domain"] == _joined_state()


def test_check_mode_does_not_join():
    io = FakeIO(state=None)
    result = logic.run(make_params(), True, io)
    assert result["changed"] is True
    assert result["joined"] is False
    assert result["domain"] is None
    assert "join" not in io.calls


def test_check_mode_already_joined_is_noop():
    io = FakeIO(state=_joined_state())
    result = logic.run(make_params(), True, io)
    assert result["changed"] is False
    assert "join" not in io.calls


def test_join_requires_bind_password():
    io = FakeIO(state=None)
    with pytest.raises(logic.SambaJoinSssdError):
        logic.run(make_params(bind_password=None), False, io)
    assert "join" not in io.calls


def test_join_requires_bind_password_even_in_check_mode():
    io = FakeIO(state=None)
    with pytest.raises(logic.SambaJoinSssdError):
        logic.run(make_params(bind_password=None), True, io)


def test_missing_adcli_raises():
    io = FakeIO(missing=True)
    with pytest.raises(logic.SambaJoinSssdError):
        logic.run(make_params(), False, io)


def test_password_not_leaked_in_result():
    io = FakeIO(state=None)
    result = logic.run(make_params(bind_password="S3cret-Passw0rd!"), False, io)
    assert "S3cret-Passw0rd!" not in repr(result)
