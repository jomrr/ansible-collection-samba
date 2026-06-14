# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the pure samba_user logic.

These run in the sanity/units container WITHOUT the samba bindings; the logic
layer must not require them."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_logic as logic


def make_params(**over):
    params = {
        "username": "jdoe",
        "given_name": None,
        "surname": None,
        "display_name": None,
        "email": None,
        "description": None,
        "enabled": True,
        "password": None,
        "state": "present",
    }
    params.update(over)
    return params


def make_current(**over):
    current = {
        "given_name": None,
        "surname": None,
        "display_name": None,
        "email": None,
        "description": None,
        "enabled": True,
        "_dn": "CN=jdoe,CN=Users,DC=example,DC=com",
        "_uac": 512,
    }
    current.update(over)
    return current


def test_build_desired_skips_unset_and_keeps_enabled():
    desired = logic.build_desired(make_params(given_name="Jane"))
    assert desired == {"given_name": "Jane", "enabled": True}


def test_plan_absent_on_missing_is_noop():
    planned = logic.plan("absent", None, logic.build_desired(make_params(state="absent")))
    assert planned["action"] == "none"
    assert planned["changed"] is False


def test_plan_absent_on_existing_deletes():
    planned = logic.plan("absent", make_current(), logic.build_desired(make_params(state="absent")))
    assert planned["action"] == "delete"
    assert planned["changed"] is True


def test_plan_present_create_collects_attrs():
    desired = logic.build_desired(make_params(given_name="Jane", surname="Doe"))
    planned = logic.plan("present", None, desired)
    assert planned["action"] == "create"
    assert planned["changed"] is True
    assert planned["attr_changes"] == {"given_name": "Jane", "surname": "Doe"}
    assert planned["enable_change"] is None


def test_plan_present_create_disabled_requests_disable():
    planned = logic.plan("present", None, logic.build_desired(make_params(enabled=False)))
    assert planned["enable_change"] is False


def test_plan_present_no_change_is_idempotent():
    planned = logic.plan(
        "present",
        make_current(given_name="Jane"),
        logic.build_desired(make_params(given_name="Jane")),
    )
    assert planned["action"] == "none"
    assert planned["changed"] is False


def test_plan_present_attribute_diff():
    planned = logic.plan(
        "present",
        make_current(given_name="Old"),
        logic.build_desired(make_params(given_name="New")),
    )
    assert planned["action"] == "modify"
    assert planned["attr_changes"] == {"given_name": "New"}
    assert planned["changed"] is True


def test_plan_present_enable_toggle():
    planned = logic.plan(
        "present",
        make_current(enabled=True),
        logic.build_desired(make_params(enabled=False)),
    )
    assert planned["action"] == "modify"
    assert planned["enable_change"] is False
    assert planned["changed"] is True


def test_build_diff_present_modify():
    current = make_current(given_name="Old")
    desired = logic.build_desired(make_params(given_name="New"))
    planned = logic.plan("present", current, desired)
    diff = logic.build_diff("present", current, desired, planned)
    assert diff["before"]["given_name"] == "Old"
    assert diff["after"]["given_name"] == "New"


# --- RFC2307/POSIX attributes ---

def test_build_desired_includes_posix():
    desired = logic.build_desired(make_params(uid_number=10001, unix_home_directory="/home/jdoe"))
    assert desired["uid_number"] == 10001
    assert desired["unix_home_directory"] == "/home/jdoe"


def test_plan_posix_string_and_int_create_collects():
    desired = logic.build_desired(make_params(uid_number=10001, login_shell="/bin/bash"))
    planned = logic.plan("present", None, desired)
    assert planned["attr_changes"]["uid_number"] == 10001
    assert planned["attr_changes"]["login_shell"] == "/bin/bash"


def test_plan_posix_integer_idempotent_no_artifact():
    # Same integer uid/gid must not look like a change (no str-vs-int artifact).
    desired = logic.build_desired(make_params(uid_number=10001, gid_number=10000))
    planned = logic.plan("present", make_current(uid_number=10001, gid_number=10000), desired)
    assert planned["action"] == "none"
    assert planned["changed"] is False


def test_plan_posix_integer_diff():
    desired = logic.build_desired(make_params(uid_number=10002))
    planned = logic.plan("present", make_current(uid_number=10001), desired)
    assert planned["attr_changes"] == {"uid_number": 10002}
    assert planned["changed"] is True


class _ProbeIO:
    """Minimal io exposing only the provisioning probe the precheck needs."""

    def __init__(self, provisioned):
        self._provisioned = provisioned
        self.probed = False

    def rfc2307_provisioned(self):
        self.probed = True
        return self._provisioned


def test_precheck_no_posix_skips_probe():
    # The critical negative: no POSIX attribute set -> provisioning is never
    # probed, so a non-rfc2307 domain is completely unaffected.
    io = _ProbeIO(provisioned=False)
    logic.check_posix_preconditions(logic.build_desired(make_params(given_name="Jane")), io)
    assert io.probed is False


def test_precheck_refuses_without_rfc2307():
    io = _ProbeIO(provisioned=False)
    with pytest.raises(logic.SambaUserError):
        logic.check_posix_preconditions(logic.build_desired(make_params(uid_number=10001)), io)
    assert io.probed is True


def test_precheck_passes_with_rfc2307():
    io = _ProbeIO(provisioned=True)
    logic.check_posix_preconditions(logic.build_desired(make_params(uid_number=10001)), io)
    assert io.probed is True


def test_precheck_negative_integer_fails_before_probe():
    io = _ProbeIO(provisioned=True)
    with pytest.raises(logic.SambaUserError):
        logic.check_posix_preconditions(logic.build_desired(make_params(gid_number=-1)), io)
    assert io.probed is False
