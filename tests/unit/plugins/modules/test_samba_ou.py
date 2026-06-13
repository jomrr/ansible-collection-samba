# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_ou orchestration.

The samba I/O is faked, so these run without the bindings. Importing the module
must also not require samba."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_ou_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_ou


class FakeIO:
    """Records calls and simulates an OU store; no samba required."""

    def __init__(self, current=None):
        self.current = current
        self.calls = []

    def read_current(self, name, path):
        self.calls.append(("read_current", name, path))
        return self.current

    def create_ou(self, name, path, description):
        self.calls.append(("create_ou", name, path, description))
        self.current = {"description": description, "_dn": "OU=%s,%s" % (name, path)}

    def set_description(self, dn, description):
        self.calls.append(("set_description", dn, description))
        self.current["description"] = description

    def delete_ou(self, dn):
        self.calls.append(("delete_ou", dn))
        self.current = None
        return True


def make_params(**over):
    params = {
        "name": "Staff",
        "path": "DC=example,DC=com",
        "description": None,
        "state": "present",
    }
    params.update(over)
    return params


def existing_ou(**over):
    ou = {"description": None, "_dn": "OU=Staff,DC=example,DC=com"}
    ou.update(over)
    return ou


def call_names(fake):
    return [call[0] for call in fake.calls]


def test_module_imports_without_samba():
    assert hasattr(samba_ou, "main")
    assert hasattr(samba_ou, "SambaOuIO")


def test_create():
    fake = FakeIO(current=None)
    result = logic.run(make_params(description="staff"), False, fake)
    assert result["changed"] is True
    assert result["action"] == "created"
    assert ("create_ou", "Staff", "DC=example,DC=com", "staff") in fake.calls


def test_noop_is_idempotent():
    fake = FakeIO(current=existing_ou(description="staff"))
    result = logic.run(make_params(description="staff"), False, fake)
    assert result["changed"] is False
    assert call_names(fake) == ["read_current"]


def test_modify_description():
    fake = FakeIO(current=existing_ou(description="old"))
    result = logic.run(make_params(description="new"), False, fake)
    assert result["changed"] is True
    assert ("set_description", "OU=Staff,DC=example,DC=com", "new") in fake.calls


def test_delete():
    fake = FakeIO(current=existing_ou())
    result = logic.run(make_params(state="absent"), False, fake)
    assert result["changed"] is True
    assert "delete_ou" in call_names(fake)
    assert result["ou"]["state"] == "absent"


def test_absent_on_missing_is_noop():
    fake = FakeIO(current=None)
    result = logic.run(make_params(state="absent"), False, fake)
    assert result["changed"] is False
    assert call_names(fake) == ["read_current"]


def test_delete_race_already_gone_is_noop():
    class GoneIO(FakeIO):
        def delete_ou(self, dn):
            self.calls.append(("delete_ou", dn))
            return False

    fake = GoneIO(current=existing_ou())
    result = logic.run(make_params(state="absent"), False, fake)
    assert result["changed"] is False
    assert result["action"] == "unchanged"


def test_parent_missing_fails():
    class NoParentIO(FakeIO):
        def create_ou(self, name, path, description):
            self.calls.append(("create_ou", name, path, description))
            raise logic.SambaOuError("parent path '%s' does not exist" % path)

    fake = NoParentIO(current=None)
    with pytest.raises(logic.SambaOuError):
        logic.run(make_params(path="OU=Missing,DC=example,DC=com"), False, fake)


def test_check_mode_create_does_not_write():
    fake = FakeIO(current=None)
    result = logic.run(make_params(description="staff"), True, fake)
    assert result["changed"] is True
    assert "create_ou" not in call_names(fake)
    assert result["ou"]["state"] == "present"


def test_check_mode_delete_does_not_write():
    fake = FakeIO(current=existing_ou())
    result = logic.run(make_params(state="absent"), True, fake)
    assert result["changed"] is True
    assert "delete_ou" not in call_names(fake)
