# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_group orchestration.

The samba I/O is faked, so these run without the bindings. Importing the module
must also not require samba."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_group_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_group


def member_dn(name):
    return "CN=%s,CN=Users,DC=example,DC=com" % name


class FakeIO:
    """Records calls and simulates a group store; no samba required."""

    def __init__(self, current=None):
        self.current = current
        self.calls = []

    def read_current(self, name):
        self.calls.append(("read_current", name))
        return self.current

    def resolve_member(self, name):
        self.calls.append(("resolve_member", name))
        return member_dn(name)

    def create_group(self, name, group_type_value, description):
        self.calls.append(("create_group", name, group_type_value, description))
        self.current = {
            "description": description,
            "group_type": group_type_value,
            "members": [],
            "_dn": "CN=%s,CN=Users,DC=example,DC=com" % name,
        }

    def set_description(self, dn, description):
        self.calls.append(("set_description", description))
        self.current["description"] = description

    def set_group_type(self, dn, group_type_value):
        self.calls.append(("set_group_type", group_type_value))
        self.current["group_type"] = group_type_value

    def add_member(self, group_dn, dn):
        self.calls.append(("add_member", dn))
        self.current["members"].append(dn)
        return True

    def remove_member(self, group_dn, dn):
        self.calls.append(("remove_member", dn))
        self.current["members"] = [m for m in self.current["members"] if m != dn]
        return True

    def delete_group(self, dn):
        self.calls.append(("delete_group", dn))
        self.current = None
        return True

    # Move helpers. needs_move/parent_exists are read-only checks, not recorded
    # in calls. Default: already at the desired location (no move).
    def needs_move(self, current_dn, path):
        return False

    def parent_exists(self, path):
        return True

    def move(self, current_dn, path):
        self.calls.append(("move", current_dn, path))
        return "CN=engineers,%s" % path


def make_params(**over):
    params = {
        "name": "engineers",
        "scope": "global",
        "category": "security",
        "description": None,
        "members": None,
        "members_purge": False,
        "path": None,
        "state": "present",
    }
    params.update(over)
    return params


def existing_group(**over):
    group = {
        "description": None,
        "group_type": logic.group_type("global", "security"),
        "members": [],
        "_dn": "CN=engineers,CN=Users,DC=example,DC=com",
    }
    group.update(over)
    return group


def call_names(fake):
    return [call[0] for call in fake.calls]


def test_module_imports_without_samba():
    assert hasattr(samba_group, "main")
    assert hasattr(samba_group, "SambaGroupIO")


def test_create_with_members():
    fake = FakeIO(current=None)
    result = logic.run(make_params(description="staff", members=["jdoe", "asmith"]), False, fake)
    assert result["changed"] is True
    assert result["action"] == "created"
    assert ("create_group", "engineers", logic.group_type("global", "security"), "staff") in fake.calls
    assert ("add_member", member_dn("jdoe")) in fake.calls
    assert ("add_member", member_dn("asmith")) in fake.calls


def test_noop_is_idempotent():
    fake = FakeIO(current=existing_group())
    result = logic.run(make_params(), False, fake)
    assert result["changed"] is False
    assert call_names(fake) == ["read_current"]


def test_modify_group_type():
    fake = FakeIO(current=existing_group())
    result = logic.run(make_params(scope="universal"), False, fake)
    assert result["changed"] is True
    assert result["action"] == "modified"
    assert ("set_group_type", logic.group_type("universal", "security")) in fake.calls


def test_modify_description():
    fake = FakeIO(current=existing_group(description="old"))
    result = logic.run(make_params(description="new"), False, fake)
    assert result["changed"] is True
    assert ("set_description", "new") in fake.calls


def test_members_additive_adds_only():
    fake = FakeIO(current=existing_group(members=[member_dn("jdoe")]))
    result = logic.run(make_params(members=["jdoe", "asmith"]), False, fake)
    assert result["changed"] is True
    assert ("add_member", member_dn("asmith")) in fake.calls
    assert "remove_member" not in call_names(fake)


def test_members_authoritative_removes_unlisted():
    fake = FakeIO(current=existing_group(members=[member_dn("jdoe"), member_dn("asmith")]))
    result = logic.run(make_params(members=["jdoe"], members_purge=True), False, fake)
    assert result["changed"] is True
    assert ("remove_member", member_dn("asmith")) in fake.calls
    assert "add_member" not in call_names(fake)


def test_members_no_change_is_idempotent():
    fake = FakeIO(current=existing_group(members=[member_dn("jdoe")]))
    result = logic.run(make_params(members=["jdoe"], members_purge=True), False, fake)
    assert result["changed"] is False
    assert "add_member" not in call_names(fake)
    assert "remove_member" not in call_names(fake)


def test_members_omitted_leaves_membership_untouched():
    fake = FakeIO(current=existing_group(members=[member_dn("jdoe")]))
    result = logic.run(make_params(), False, fake)
    assert result["changed"] is False
    assert "resolve_member" not in call_names(fake)


def test_check_mode_create_does_not_write():
    fake = FakeIO(current=None)
    result = logic.run(make_params(members=["jdoe"]), True, fake)
    assert result["changed"] is True
    assert "create_group" not in call_names(fake)
    assert "add_member" not in call_names(fake)


def test_check_mode_member_change_does_not_write():
    fake = FakeIO(current=existing_group())
    result = logic.run(make_params(members=["jdoe"]), True, fake)
    assert result["changed"] is True
    assert "add_member" not in call_names(fake)


def test_absent_on_missing_is_noop():
    fake = FakeIO(current=None)
    result = logic.run(make_params(state="absent"), False, fake)
    assert result["changed"] is False
    assert call_names(fake) == ["read_current"]


def test_absent_on_existing_deletes():
    fake = FakeIO(current=existing_group())
    result = logic.run(make_params(state="absent"), False, fake)
    assert result["changed"] is True
    assert "delete_group" in call_names(fake)
    assert result["group"]["state"] == "absent"


def test_delete_race_already_gone_is_noop():
    class GoneIO(FakeIO):
        def delete_group(self, dn):
            self.calls.append(("delete_group", dn))
            return False

    fake = GoneIO(current=existing_group())
    result = logic.run(make_params(state="absent"), False, fake)
    assert result["changed"] is False
    assert result["action"] == "unchanged"


def test_member_add_race_all_noop_reports_unchanged():
    # add_member reports the member was already present (concurrent add).
    class CollisionIO(FakeIO):
        def add_member(self, group_dn, dn):
            self.calls.append(("add_member", dn))
            return False

    fake = CollisionIO(current=existing_group())
    result = logic.run(make_params(members=["jdoe"]), False, fake)
    assert "add_member" in call_names(fake)
    assert result["changed"] is False
    assert result["action"] == "unchanged"


class _MovingIO(FakeIO):
    """FakeIO that reports the group is in the wrong place (a move is needed)."""

    def needs_move(self, current_dn, path):
        return True


def test_no_move_when_location_matches():
    fake = FakeIO(current=existing_group())
    result = logic.run(make_params(path="CN=Users,DC=example,DC=com"), False, fake)
    assert result["changed"] is False
    assert "move" not in call_names(fake)


def test_move_when_location_differs():
    fake = _MovingIO(current=existing_group())
    result = logic.run(make_params(path="OU=Groups,DC=example,DC=com"), False, fake)
    assert result["changed"] is True
    assert result["action"] == "modified"
    assert ("move", "CN=engineers,CN=Users,DC=example,DC=com", "OU=Groups,DC=example,DC=com") in fake.calls


def test_create_with_path_moves_after_create():
    fake = _MovingIO(current=None)
    result = logic.run(make_params(path="OU=Groups,DC=example,DC=com"), False, fake)
    assert result["changed"] is True
    names = call_names(fake)
    assert names.index("create_group") < names.index("move")


def test_move_check_mode_plans_without_writing():
    fake = _MovingIO(current=existing_group())
    result = logic.run(make_params(path="OU=Groups,DC=example,DC=com"), True, fake)
    assert result["changed"] is True
    assert "move" not in call_names(fake)


def test_move_target_path_missing_fails():
    class _MissingParentIO(_MovingIO):
        def parent_exists(self, path):
            return False

    fake = _MissingParentIO(current=existing_group())
    with pytest.raises(logic.SambaGroupError):
        logic.run(make_params(path="OU=Missing,DC=example,DC=com"), False, fake)
    assert "move" not in call_names(fake)


def test_move_before_member_changes():
    fake = _MovingIO(current=existing_group())
    result = logic.run(make_params(members=["jdoe"], path="OU=Groups,DC=example,DC=com"), False, fake)
    assert result["changed"] is True
    names = call_names(fake)
    assert names.index("move") < names.index("add_member")
