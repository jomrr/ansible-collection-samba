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
    return f"CN={name},CN=Users,DC=example,DC=com"


class FakeIO:
    """Records calls and simulates a group store; no samba required."""

    def __init__(self, current=None, provisioned=True):
        self.current = current
        self.provisioned = provisioned
        self.calls = []

    def read_current(self, name):
        self.calls.append(("read_current", name))
        return self.current

    def rfc2307_provisioned(self):
        self.calls.append(("rfc2307_provisioned",))
        return self.provisioned

    def resolve_members(self, members):
        self.calls.append(("resolve_members", list(members)))
        # Like the I/O: a DN (contains "=") is taken as is, a name is resolved.
        return [member if "=" in member else member_dn(member) for member in members]

    def create_group(self, name, group_type_value, description, path, gid_number):
        self.calls.append(("create_group", name, group_type_value, description, path, gid_number))
        # Like newgroup: placed under path, gidNumber set on the add.
        self.current = {
            "description": description,
            "group_type": group_type_value,
            "gid_number": gid_number,
            "members": [],
            "_dn": "CN={},{}".format(name, path or "CN=Users,DC=example,DC=com"),
        }

    def set_description(self, dn, description):
        self.calls.append(("set_description", description))
        self.current["description"] = description

    def set_group_type(self, dn, group_type_value):
        self.calls.append(("set_group_type", group_type_value))
        self.current["group_type"] = group_type_value

    def set_gid_number(self, dn, gid_number):
        self.calls.append(("set_gid_number", gid_number))
        self.current["gid_number"] = gid_number

    def add_member(self, group_dn, dn):
        self.calls.append(("add_member", dn))
        self.current["members"].append(dn)
        return True

    def remove_member(self, group_dn, dn):
        self.calls.append(("remove_member", dn))
        self.current["members"] = [m for m in self.current["members"] if m != dn]
        return True

    def delete(self, dn):
        self.calls.append(("delete", dn))
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
        return f"CN=engineers,{path}"


def make_params(**over):
    params = {
        "name": "engineers",
        "scope": None,
        "category": None,
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
    assert ("create_group", "engineers", logic.group_type("global", "security"), "staff", None, None) in fake.calls
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


def test_description_update_keeps_the_existing_type():
    # A built-in domain-local group gets a new description; with scope and
    # category unset its type must not be touched.
    fake = FakeIO(current=existing_group(group_type=logic.group_type("domain_local", "security"), description="old"))
    result = logic.run(make_params(description="new"), False, fake)
    assert result["changed"] is True
    assert "set_group_type" not in call_names(fake)
    assert result["group"]["scope"] == "domain_local"


def test_create_with_scope_only_uses_the_default_category():
    fake = FakeIO(current=None)
    logic.run(make_params(scope="universal"), False, fake)
    assert ("create_group", "engineers", logic.group_type("universal", "security"), None, None, None) in fake.calls


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


def test_members_given_as_dns_are_the_read_mirror():
    # samba_group_info returns DNs; feeding them back must be a no-op.
    fake = FakeIO(current=existing_group(members=[member_dn("jdoe")]))
    result = logic.run(make_params(members=[member_dn("jdoe")], members_purge=True), False, fake)
    assert result["changed"] is False
    assert "add_member" not in call_names(fake)
    assert "remove_member" not in call_names(fake)


def test_members_omitted_leaves_membership_untouched():
    fake = FakeIO(current=existing_group(members=[member_dn("jdoe")]))
    result = logic.run(make_params(), False, fake)
    assert result["changed"] is False
    assert "resolve_members" not in call_names(fake)


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
    assert "delete" in call_names(fake)
    assert result["group"]["state"] == "absent"


def test_delete_race_already_gone_is_noop():
    class GoneIO(FakeIO):
        def delete(self, dn):
            self.calls.append(("delete", dn))
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


# --- RFC2307/POSIX gid_number ---

def test_gid_number_create_sets_it_on_the_add():
    fake = FakeIO(current=None)
    result = logic.run(make_params(gid_number=10000), False, fake)
    assert result["changed"] is True
    assert ("create_group", "engineers", logic.group_type("global", "security"), None, None, 10000) in fake.calls
    assert "set_gid_number" not in call_names(fake)
    assert result["group"]["gid_number"] == 10000


def test_gid_number_modify_sets_it():
    fake = FakeIO(current=existing_group(gid_number=500))
    result = logic.run(make_params(gid_number=10000), False, fake)
    assert result["changed"] is True
    assert ("set_gid_number", 10000) in fake.calls


def test_gid_number_idempotent_integer():
    fake = FakeIO(current=existing_group(gid_number=10000))
    result = logic.run(make_params(gid_number=10000), False, fake)
    assert result["changed"] is False
    assert "set_gid_number" not in call_names(fake)


def test_gid_refused_without_rfc2307_before_any_write():
    fake = FakeIO(current=existing_group(), provisioned=False)
    with pytest.raises(logic.SambaGroupError):
        logic.run(make_params(gid_number=10000), False, fake)
    assert "set_gid_number" not in call_names(fake)


def test_gid_negative_integer_fails():
    fake = FakeIO(current=existing_group(), provisioned=True)
    with pytest.raises(logic.SambaGroupError):
        logic.run(make_params(gid_number=-1), False, fake)
    assert "set_gid_number" not in call_names(fake)


def test_non_posix_run_on_non_rfc2307_domain_is_unaffected():
    # The non-negotiable negative test: with no gid_number set, the provisioning
    # state is never probed and a normal change goes through unchanged.
    fake = FakeIO(current=existing_group(description="old"), provisioned=False)
    result = logic.run(make_params(description="new"), False, fake)
    assert result["changed"] is True
    assert ("set_description", "new") in fake.calls
    assert "rfc2307_provisioned" not in call_names(fake)


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


def test_create_with_path_places_the_group_directly():
    fake = FakeIO(current=None)
    result = logic.run(make_params(path="OU=Groups,DC=example,DC=com"), False, fake)
    assert result["changed"] is True
    assert (
        "create_group", "engineers", logic.group_type("global", "security"), None, "OU=Groups,DC=example,DC=com", None,
    ) in fake.calls
    assert "move" not in call_names(fake)
    assert result["group"]["dn"] == "CN=engineers,OU=Groups,DC=example,DC=com"


def test_create_moves_afterwards_only_when_the_add_could_not_place_it():
    # The domain root cannot be expressed as newgroup's relative container.
    fake = _MovingIO(current=None)
    logic.run(make_params(path="DC=example,DC=com"), False, fake)
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


def test_check_mode_create_with_missing_parent_fails_like_a_real_run():
    class _NoParentIO(FakeIO):
        def parent_exists(self, path):
            return False

    fake = _NoParentIO(current=None)
    with pytest.raises(logic.SambaGroupError):
        logic.run(make_params(path="OU=Missing,DC=example,DC=com"), True, fake)
    assert "create_group" not in call_names(fake)


def test_check_mode_move_to_missing_parent_fails_like_a_real_run():
    class _MissingParentMovingIO(_MovingIO):
        def parent_exists(self, path):
            return False

    fake = _MissingParentMovingIO(current=existing_group())
    with pytest.raises(logic.SambaGroupError):
        logic.run(make_params(path="OU=Missing,DC=example,DC=com"), True, fake)
    assert "move" not in call_names(fake)


def test_move_before_member_changes():
    fake = _MovingIO(current=existing_group())
    result = logic.run(make_params(members=["jdoe"], path="OU=Groups,DC=example,DC=com"), False, fake)
    assert result["changed"] is True
    names = call_names(fake)
    assert names.index("move") < names.index("add_member")


# --- removing the description (empty string) ---

def test_empty_description_removes_it_and_reads_back_none():
    fake = FakeIO(current=existing_group(description="old"))
    result = logic.run(make_params(description=""), False, fake)
    assert result["changed"] is True
    assert "set_description" in call_names(fake)
    assert fake.current["description"] is None
    assert result["group"]["description"] is None


def test_empty_description_on_absent_is_idempotent():
    fake = FakeIO(current=existing_group(description=None))
    result = logic.run(make_params(description=""), False, fake)
    assert result["changed"] is False
    assert "set_description" not in call_names(fake)


def test_create_with_empty_description_passes_none():
    fake = FakeIO(current=None)
    result = logic.run(make_params(description=""), False, fake)
    assert result["changed"] is True
    assert fake.current["description"] is None
    assert result["group"]["description"] is None


# --- all-or-nothing create (compensation, since LDAP has no transactions) ---

class _MemberFailIO(FakeIO):
    """add_member fails after the group was created."""

    def add_member(self, group_dn, dn):
        self.calls.append(("add_member", dn))
        raise RuntimeError("00000035: Unwilling to perform")


def test_create_failure_on_member_add_removes_the_new_group():
    fake = _MemberFailIO(current=None)
    with pytest.raises(logic.SambaGroupError) as excinfo:
        logic.run(make_params(members=["jdoe"]), False, fake)
    names = call_names(fake)
    assert names.index("create_group") < names.index("delete")
    assert fake.current is None
    assert "partially created object was removed" in str(excinfo.value)
    assert "Unwilling to perform" in str(excinfo.value)


def test_create_failure_after_the_add_removes_the_new_group():
    # newgroup raised after its add went through; the leftover is removed.
    class _AddThenFailIO(FakeIO):
        def create_group(self, name, group_type_value, description, path, gid_number):
            FakeIO.create_group(self, name, group_type_value, description, path, gid_number)
            raise RuntimeError("0000202F: Constraint violation")

    fake = _AddThenFailIO(current=None)
    with pytest.raises(logic.SambaGroupError):
        logic.run(make_params(gid_number=10000), False, fake)
    assert "delete" in call_names(fake)
    assert fake.current is None


def test_create_collision_is_not_undone():
    class _CollisionIO(FakeIO):
        def create_group(self, name, group_type_value, description, path, gid_number):
            self.calls.append(("create_group", name, group_type_value, description, path, gid_number))
            raise logic.SambaGroupError("group 'engineers' already exists (created concurrently?)")

    fake = _CollisionIO(current=None)
    with pytest.raises(logic.SambaGroupError):
        logic.run(make_params(), False, fake)
    assert "delete" not in call_names(fake)


def test_modify_failure_leaves_the_existing_group_alone():
    fake = _MemberFailIO(current=existing_group())
    with pytest.raises(RuntimeError):
        logic.run(make_params(members=["jdoe"]), False, fake)
    assert "delete" not in call_names(fake)
    assert fake.current is not None
