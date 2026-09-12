# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_user module orchestration.

The samba I/O layer is faked, so these run in the sanity/units container
WITHOUT the samba bindings. Importing the module itself must also not require
samba - that is the litmus test for the layer separation."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_user


class FakeIO:
    """Records calls and simulates a user store; no samba required."""

    def __init__(self, current=None, provisioned=True):
        self.current = current
        self.provisioned = provisioned
        self.calls = []

    def read_current(self, username):
        self.calls.append(("read_current", username))
        return self.current

    def rfc2307_provisioned(self):
        self.calls.append(("rfc2307_provisioned",))
        return self.provisioned

    def create_user(self, username, password):
        self.calls.append(("create_user", username, password))
        self.current = {
            "given_name": None,
            "surname": None,
            "display_name": None,
            "email": None,
            "description": None,
            "enabled": True,
            "_dn": "CN=%s,CN=Users,DC=example,DC=com" % username,
            "_uac": 512,
        }

    def apply_attrs(self, dn, attr_changes):
        self.calls.append(("apply_attrs", dn, dict(attr_changes)))
        self.current.update(attr_changes)

    def set_enabled(self, dn, current_uac, enabled):
        self.calls.append(("set_enabled", dn, enabled))
        self.current["enabled"] = enabled

    def delete_user(self, dn):
        self.calls.append(("delete_user", dn))
        self.current = None
        return True

    def set_password(self, username, password):
        self.calls.append(("set_password", username, password))

    # Move helpers. needs_move/parent_exists are read-only checks and are not
    # recorded in calls (so existing call-sequence assertions stay valid).
    # Default: object already at the desired location (no move). Tests that
    # exercise moves override needs_move.
    def needs_move(self, current_dn, path):
        return False

    def parent_exists(self, path):
        return True

    def move(self, current_dn, path):
        self.calls.append(("move", current_dn, path))
        return "CN=jdoe,%s" % path


def make_params(**over):
    params = {
        "username": "jdoe",
        "given_name": None,
        "surname": None,
        "display_name": None,
        "email": None,
        "description": None,
        "enabled": None,
        "password": None,
        "update_password": "on_create",
        "path": None,
        "state": "present",
    }
    params.update(over)
    return params


def existing_user(**over):
    user = {
        "given_name": None,
        "surname": None,
        "display_name": None,
        "email": None,
        "description": None,
        "enabled": True,
        "_dn": "CN=jdoe,CN=Users,DC=example,DC=com",
        "_uac": 512,
    }
    user.update(over)
    return user


def call_names(fake):
    return [call[0] for call in fake.calls]


def test_module_imports_without_samba():
    assert hasattr(samba_user, "main")
    assert hasattr(samba_user, "SambaUserIO")


def test_create_present_writes():
    fake = FakeIO(current=None)
    result = logic.run(make_params(given_name="Jane", password="S3cret!"), False, fake)
    assert result["changed"] is True
    assert result["action"] == "created"
    assert "create_user" in call_names(fake)
    assert "apply_attrs" in call_names(fake)
    assert result["user"]["given_name"] == "Jane"


def test_create_requires_password():
    fake = FakeIO(current=None)
    with pytest.raises(logic.SambaUserError):
        logic.run(make_params(given_name="Jane"), False, fake)
    assert "create_user" not in call_names(fake)


def test_check_mode_create_does_not_write():
    fake = FakeIO(current=None)
    result = logic.run(make_params(password="S3cret!"), True, fake)
    assert result["changed"] is True
    assert "create_user" not in call_names(fake)
    assert result["user"]["state"] == "present"


def test_present_idempotent_no_write():
    fake = FakeIO(current=existing_user(given_name="Jane"))
    result = logic.run(make_params(given_name="Jane"), False, fake)
    assert result["changed"] is False
    assert call_names(fake) == ["read_current"]


def test_modify_attribute_writes():
    fake = FakeIO(current=existing_user(given_name="Old"))
    result = logic.run(make_params(given_name="New"), False, fake)
    assert result["changed"] is True
    assert ("apply_attrs", "CN=jdoe,CN=Users,DC=example,DC=com", {"given_name": "New"}) in fake.calls


def test_check_mode_modify_does_not_write():
    fake = FakeIO(current=existing_user(given_name="Old"))
    result = logic.run(make_params(given_name="New"), True, fake)
    assert result["changed"] is True
    assert "apply_attrs" not in call_names(fake)


def test_disable_existing_user():
    fake = FakeIO(current=existing_user(enabled=True))
    result = logic.run(make_params(enabled=False), False, fake)
    assert result["changed"] is True
    assert ("set_enabled", "CN=jdoe,CN=Users,DC=example,DC=com", False) in fake.calls


def test_attribute_update_keeps_disabled_account_disabled():
    # Offboarding guarantee: enabled is unset, so the state is not reconciled.
    fake = FakeIO(current=existing_user(given_name="Old", enabled=False, _uac=514))
    result = logic.run(make_params(given_name="New"), False, fake)
    assert result["changed"] is True
    assert "set_enabled" not in call_names(fake)
    assert result["user"]["enabled"] is False


def test_explicit_enabled_true_re_enables():
    fake = FakeIO(current=existing_user(enabled=False, _uac=514))
    result = logic.run(make_params(enabled=True), False, fake)
    assert result["changed"] is True
    assert ("set_enabled", "CN=jdoe,CN=Users,DC=example,DC=com", True) in fake.calls


def test_create_without_enabled_is_enabled_and_toggles_nothing():
    fake = FakeIO(current=None)
    result = logic.run(make_params(password="S3cret!"), False, fake)
    assert "set_enabled" not in call_names(fake)
    assert result["user"]["enabled"] is True


def test_create_disabled_toggles_after_create():
    fake = FakeIO(current=None)
    result = logic.run(make_params(password="S3cret!", enabled=False), False, fake)
    assert ("set_enabled", "CN=jdoe,CN=Users,DC=example,DC=com", False) in fake.calls
    assert result["user"]["enabled"] is False


def test_absent_on_missing_is_noop():
    fake = FakeIO(current=None)
    result = logic.run(make_params(state="absent"), False, fake)
    assert result["changed"] is False
    assert call_names(fake) == ["read_current"]


def test_absent_on_existing_deletes():
    fake = FakeIO(current=existing_user())
    result = logic.run(make_params(state="absent"), False, fake)
    assert result["changed"] is True
    assert "delete_user" in call_names(fake)
    assert result["user"]["state"] == "absent"


def test_check_mode_absent_does_not_delete():
    fake = FakeIO(current=existing_user())
    result = logic.run(make_params(state="absent"), True, fake)
    assert result["changed"] is True
    assert "delete_user" not in call_names(fake)


def test_delete_race_already_gone_is_noop():
    # The object was deleted concurrently between read and write: delete_user
    # reports it was already gone, so the run is an honest no-op.
    class GoneIO(FakeIO):
        def delete_user(self, dn):
            self.calls.append(("delete_user", dn))
            return False

    fake = GoneIO(current=existing_user())
    result = logic.run(make_params(state="absent"), False, fake)
    assert result["changed"] is False
    assert result["action"] == "unchanged"
    assert result["diff"] == {"before": {}, "after": {}}
    assert "delete_user" in call_names(fake)


def test_password_not_leaked_in_result_or_diff():
    fake = FakeIO(current=None)
    result = logic.run(make_params(given_name="Jane", password="S3cret!"), False, fake)
    assert "S3cret!" not in repr(result)
    assert "S3cret!" not in repr(result["diff"])
    assert "S3cret!" not in repr(result["user"])


def test_password_not_leaked_in_check_mode():
    fake = FakeIO(current=None)
    result = logic.run(make_params(password="S3cret!"), True, fake)
    assert "S3cret!" not in repr(result)


def test_on_create_existing_user_does_not_set_password():
    # update_password=on_create (default): existing user, identical attrs ->
    # password is left untouched and the run stays idempotent.
    fake = FakeIO(current=existing_user(given_name="Jane"))
    result = logic.run(
        make_params(given_name="Jane", password="S3cret!", update_password="on_create"),
        False, fake,
    )
    assert result["changed"] is False
    assert "set_password" not in call_names(fake)


def test_always_existing_user_sets_password_and_changes():
    # update_password=always: password is written even though attrs are
    # unchanged, and that write is honestly reported as changed:true.
    fake = FakeIO(current=existing_user(given_name="Jane"))
    result = logic.run(
        make_params(given_name="Jane", password="S3cret!", update_password="always"),
        False, fake,
    )
    assert result["changed"] is True
    assert result["action"] == "modified"
    # The password is set by DN (the object that was read), never by a name lookup.
    assert ("set_password", "CN=jdoe,CN=Users,DC=example,DC=com", "S3cret!") in fake.calls


def test_empty_string_removes_attribute_and_reads_back_none():
    fake = FakeIO(current=existing_user(description="old"))
    result = logic.run(make_params(description=""), False, fake)
    assert result["changed"] is True
    assert ("apply_attrs", "CN=jdoe,CN=Users,DC=example,DC=com", {"description": None}) in fake.calls
    assert result["user"]["description"] is None


def test_empty_string_on_absent_attribute_is_idempotent():
    fake = FakeIO(current=existing_user(description=None))
    result = logic.run(make_params(description=""), False, fake)
    assert result["changed"] is False
    assert call_names(fake) == ["read_current"]


def test_always_existing_user_check_mode_no_write_but_changed():
    fake = FakeIO(current=existing_user(given_name="Jane"))
    result = logic.run(
        make_params(given_name="Jane", password="S3cret!", update_password="always"),
        True, fake,
    )
    assert result["changed"] is True
    assert "set_password" not in call_names(fake)


def test_always_password_not_leaked():
    fake = FakeIO(current=existing_user(given_name="Jane"))
    result = logic.run(
        make_params(given_name="Jane", password="S3cret!", update_password="always"),
        False, fake,
    )
    assert "S3cret!" not in repr(result)
    assert "S3cret!" not in repr(result["diff"])
    assert "S3cret!" not in repr(result["user"])


def test_always_without_password_does_not_write():
    # update_password=always but no password supplied -> nothing to set, and an
    # unchanged existing user stays changed:false.
    fake = FakeIO(current=existing_user(given_name="Jane"))
    result = logic.run(
        make_params(given_name="Jane", update_password="always"), False, fake,
    )
    assert result["changed"] is False
    assert "set_password" not in call_names(fake)


# --- RFC2307/POSIX attributes ---

def test_posix_attrs_create_writes():
    fake = FakeIO(current=None)
    result = logic.run(
        make_params(uid_number=10001, gid_number=10000, login_shell="/bin/bash", password="S3cret!"),
        False, fake,
    )
    assert result["changed"] is True
    applied = [call[2] for call in fake.calls if call[0] == "apply_attrs"][0]
    assert applied["uid_number"] == 10001
    assert applied["login_shell"] == "/bin/bash"
    assert result["user"]["uid_number"] == 10001


def test_posix_modify_writes():
    fake = FakeIO(current=existing_user(uid_number=500))
    result = logic.run(make_params(uid_number=10001), False, fake)
    assert result["changed"] is True
    assert ("apply_attrs", "CN=jdoe,CN=Users,DC=example,DC=com", {"uid_number": 10001}) in fake.calls


def test_posix_idempotent_integer_no_write():
    fake = FakeIO(current=existing_user(uid_number=10001, gid_number=10000))
    result = logic.run(make_params(uid_number=10001, gid_number=10000), False, fake)
    assert result["changed"] is False
    assert "apply_attrs" not in call_names(fake)


def test_posix_refused_without_rfc2307_before_any_write():
    fake = FakeIO(current=existing_user(), provisioned=False)
    with pytest.raises(logic.SambaUserError):
        logic.run(make_params(uid_number=10001), False, fake)
    assert "apply_attrs" not in call_names(fake)


def test_posix_negative_integer_fails():
    fake = FakeIO(current=existing_user(), provisioned=True)
    with pytest.raises(logic.SambaUserError):
        logic.run(make_params(uid_number=-1), False, fake)
    assert "apply_attrs" not in call_names(fake)


def test_non_posix_run_on_non_rfc2307_domain_is_unaffected():
    # The non-negotiable negative test: no POSIX attribute set -> the
    # provisioning state is never probed and a normal change goes through on a
    # non-rfc2307 domain, exactly as before this feature.
    fake = FakeIO(current=existing_user(given_name="Old"), provisioned=False)
    result = logic.run(make_params(given_name="New"), False, fake)
    assert result["changed"] is True
    assert "apply_attrs" in call_names(fake)
    assert "rfc2307_provisioned" not in call_names(fake)


class _MovingIO(FakeIO):
    """FakeIO that reports the object is in the wrong place (a move is needed)."""

    def needs_move(self, current_dn, path):
        return True


def test_no_move_when_location_matches():
    # needs_move False (default) -> existing user, path set, nothing else -> no
    # move and no change (the idempotence guarantee).
    fake = FakeIO(current=existing_user())
    result = logic.run(make_params(path="CN=Users,DC=example,DC=com"), False, fake)
    assert result["changed"] is False
    assert "move" not in call_names(fake)


def test_move_when_location_differs():
    fake = _MovingIO(current=existing_user())
    result = logic.run(make_params(path="OU=Eng,DC=example,DC=com"), False, fake)
    assert result["changed"] is True
    assert result["action"] == "modified"
    assert ("move", "CN=jdoe,CN=Users,DC=example,DC=com", "OU=Eng,DC=example,DC=com") in fake.calls


def test_create_with_path_moves_after_create():
    fake = _MovingIO(current=None)
    result = logic.run(make_params(password="S3cret!", path="OU=Eng,DC=example,DC=com"), False, fake)
    assert result["changed"] is True
    names = call_names(fake)
    assert "create_user" in names
    assert "move" in names
    assert names.index("create_user") < names.index("move")


def test_move_check_mode_plans_without_writing():
    fake = _MovingIO(current=existing_user())
    result = logic.run(make_params(path="OU=Eng,DC=example,DC=com"), True, fake)
    assert result["changed"] is True
    assert "move" not in call_names(fake)


def test_move_target_path_missing_fails():
    class _MissingParentIO(_MovingIO):
        def parent_exists(self, path):
            return False

    fake = _MissingParentIO(current=existing_user())
    with pytest.raises(logic.SambaUserError):
        logic.run(make_params(path="OU=Missing,DC=example,DC=com"), False, fake)
    assert "move" not in call_names(fake)


def test_move_then_attribute_change_in_order():
    fake = _MovingIO(current=existing_user(display_name="Old"))
    result = logic.run(make_params(display_name="New", path="OU=Eng,DC=example,DC=com"), False, fake)
    assert result["changed"] is True
    names = call_names(fake)
    assert names.index("move") < names.index("apply_attrs")


# --- all-or-nothing create (compensation, since LDAP has no transactions) ---

class _AttrsFailIO(FakeIO):
    """apply_attrs fails after the object was created."""

    def apply_attrs(self, dn, attr_changes):
        self.calls.append(("apply_attrs", dn, dict(attr_changes)))
        raise RuntimeError("0000202F: Constraint violation")


def test_create_failure_after_add_removes_the_new_object():
    fake = _AttrsFailIO(current=None)
    with pytest.raises(logic.SambaUserError) as excinfo:
        logic.run(make_params(given_name="Jane", password="S3cret!"), False, fake)
    names = call_names(fake)
    assert names.index("create_user") < names.index("delete_user")
    assert fake.current is None
    assert "partially created object was removed" in str(excinfo.value)
    assert "Constraint violation" in str(excinfo.value)


def test_create_with_rejected_password_removes_half_created_account():
    # samba's newuser adds the object first and sets the password second, so a
    # policy rejection raises after the add and leaves a disabled account.
    class _WeakPasswordIO(FakeIO):
        def create_user(self, username, password):
            FakeIO.create_user(self, username, password)
            raise RuntimeError("0000052D: Constraint violation - the password is too short")

    fake = _WeakPasswordIO(current=None)
    with pytest.raises(logic.SambaUserError) as excinfo:
        logic.run(make_params(password="Weak-Pass-1"), False, fake)
    assert "delete_user" in call_names(fake)
    assert fake.current is None
    assert "removed" in str(excinfo.value)
    # The cause is reported, the password never is.
    assert "Weak-Pass-1" not in str(excinfo.value)


def test_create_undo_failure_reports_both_errors():
    class _StuckIO(_AttrsFailIO):
        def delete_user(self, dn):
            self.calls.append(("delete_user", dn))
            raise RuntimeError("busy")

    fake = _StuckIO(current=None)
    with pytest.raises(logic.SambaUserError) as excinfo:
        logic.run(make_params(given_name="Jane", password="S3cret!"), False, fake)
    assert "Constraint violation" in str(excinfo.value)
    assert "busy" in str(excinfo.value)


def test_create_collision_is_not_undone():
    class _CollisionIO(FakeIO):
        def create_user(self, username, password):
            self.calls.append(("create_user", username, password))
            raise logic.SambaUserError("user 'jdoe' already exists (created concurrently?)")

    fake = _CollisionIO(current=None)
    with pytest.raises(logic.SambaUserError):
        logic.run(make_params(password="S3cret!"), False, fake)
    # The object is somebody else's: never deleted.
    assert "delete_user" not in call_names(fake)


def test_modify_failure_leaves_the_existing_object_alone():
    fake = _AttrsFailIO(current=existing_user(given_name="Old"))
    with pytest.raises(RuntimeError):
        logic.run(make_params(given_name="New"), False, fake)
    assert "delete_user" not in call_names(fake)
    assert fake.current is not None
