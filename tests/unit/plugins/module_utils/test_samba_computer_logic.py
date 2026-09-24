# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the pure samba_computer logic (no samba bindings required)."""

from __future__ import annotations

import pytest
from ansible_collections.jomrr.samba.plugins.module_utils import samba_computer_logic as logic

DEFAULT = "CN=Computers,DC=example,DC=com"
SERVERS = "OU=Servers,DC=example,DC=com"


class FakeIO:
    """The computer account on the DC: where it is and which containers exist."""

    def __init__(self, dn, existing=(SERVERS,)):
        self.state = None if dn is None else {"name": "WS01", "dn": dn, "dns_host_name": None, "description": None}
        self.existing = existing
        self.moves = []

    def find(self, name):
        return self.state

    def needs_move(self, dn, path):
        return not dn.endswith("," + (path or DEFAULT))

    def parent_exists(self, path):
        return path in self.existing

    def move(self, dn, path):
        self.moves.append(path)
        return dn.split(",", 1)[0] + "," + (path or DEFAULT)


def make_params(**over):
    params = {"name": "WS01", "path": SERVERS}
    params.update(over)
    return params


def test_an_account_in_place_is_unchanged():
    io = FakeIO(f"CN=WS01,{SERVERS}")
    result = logic.run(make_params(), False, io)
    assert result["changed"] is False
    assert result["action"] == "unchanged"
    assert result["computer"]["dn"] == f"CN=WS01,{SERVERS}"
    assert io.moves == []


def test_an_account_elsewhere_is_moved():
    io = FakeIO(f"CN=WS01,{DEFAULT}")
    result = logic.run(make_params(), False, io)
    assert result["changed"] is True
    assert result["action"] == "modified"
    assert result["computer"]["dn"] == f"CN=WS01,{SERVERS}"


def test_check_mode_reports_the_move_without_moving():
    io = FakeIO(f"CN=WS01,{DEFAULT}")
    result = logic.run(make_params(), True, io)
    assert result["changed"] is True
    assert result["computer"]["dn"] == f"CN=WS01,{DEFAULT}"
    assert io.moves == []


def test_an_omitted_path_means_the_default_container():
    # The default container always exists, so it is not probed (SERVERS is the
    # only container this fake knows).
    io = FakeIO(f"CN=WS01,{SERVERS}")
    result = logic.run(make_params(path=None), False, io)
    assert io.moves == [None]
    assert result["computer"]["dn"] == f"CN=WS01,{DEFAULT}"


def test_a_missing_account_fails():
    with pytest.raises(logic.SambaComputerError, match="does not exist"):
        logic.run(make_params(), False, FakeIO(None))


def test_a_missing_path_fails_before_anything_is_reported():
    io = FakeIO(f"CN=WS01,{DEFAULT}", existing=())
    with pytest.raises(logic.SambaComputerError, match="create it first"):
        logic.run(make_params(), True, io)
    assert io.moves == []
