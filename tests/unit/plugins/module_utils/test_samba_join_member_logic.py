# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the pure samba_join_member logic (no samba bindings required)."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_join_member_logic as logic


class FakeIO:
    """Records calls and simulates the local membership state; no samba required."""

    def __init__(self, state=None):
        self._state = state
        self.calls = []

    def read_state(self):
        self.calls.append("read_state")
        return self._state

    def join(self, params):
        self.calls.append("join")
        return {"workgroup": "SAMDOM", "netbios_name": "MEMBER1", "domainsid": "S-1-5-21-1-2-3"}


def make_params(**over):
    params = {
        "realm": "SAMDOM.EXAMPLE.COM",
        "server": "dc1.samdom.example.com",
        "bind_username": "Administrator",
        "bind_password": "S3cret-Passw0rd!",
        "machinepass": None,
        "state": "present",
    }
    params.update(over)
    return params


def _member_state(**over):
    state = {"workgroup": "SAMDOM", "netbios_name": "MEMBER1"}
    state.update(over)
    return state


def test_not_a_member_joins():
    io = FakeIO(state=None)
    result = logic.run(make_params(), False, io)
    assert result["changed"] is True
    assert result["joined"] is True
    assert "join" in io.calls
    assert result["domain"]["workgroup"] == "SAMDOM"


def test_already_member_is_noop():
    io = FakeIO(state=_member_state())
    result = logic.run(make_params(), False, io)
    assert result["changed"] is False
    assert result["joined"] is True
    assert "join" not in io.calls  # an existing valid member is never re-joined
    assert result["domain"] == _member_state()


def test_check_mode_does_not_join():
    io = FakeIO(state=None)
    result = logic.run(make_params(), True, io)
    assert result["changed"] is True
    assert result["joined"] is False
    assert result["domain"] is None
    assert "join" not in io.calls


def test_check_mode_already_member_is_noop():
    io = FakeIO(state=_member_state())
    result = logic.run(make_params(), True, io)
    assert result["changed"] is False
    assert "join" not in io.calls


def test_join_requires_bind_password():
    io = FakeIO(state=None)
    with pytest.raises(logic.SambaJoinMemberError):
        logic.run(make_params(bind_password=None), False, io)
    assert "join" not in io.calls


def test_join_requires_bind_password_even_in_check_mode():
    io = FakeIO(state=None)
    with pytest.raises(logic.SambaJoinMemberError):
        logic.run(make_params(bind_password=None), True, io)


def test_password_not_leaked_in_result():
    io = FakeIO(state=None)
    result = logic.run(make_params(bind_password="S3cret-Passw0rd!"), False, io)
    assert "S3cret-Passw0rd!" not in repr(result)
