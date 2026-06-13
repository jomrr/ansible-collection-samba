# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the pure samba_user logic.

These run in the sanity/units container WITHOUT the samba bindings; the logic
layer must not require them."""

from __future__ import annotations

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
