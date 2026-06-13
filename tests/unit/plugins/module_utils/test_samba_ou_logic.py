# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the pure samba_ou logic (no samba bindings required)."""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils import samba_ou_logic as logic


def make_params(**over):
    params = {
        "name": "Staff",
        "path": "DC=example,DC=com",
        "description": None,
        "state": "present",
    }
    params.update(over)
    return params


def make_current(**over):
    current = {"description": None, "_dn": "OU=Staff,DC=example,DC=com"}
    current.update(over)
    return current


def test_build_desired_skips_unset():
    assert logic.build_desired(make_params()) == {}
    assert logic.build_desired(make_params(description="d")) == {"description": "d"}


def test_plan_absent_on_missing_is_noop():
    planned = logic.plan("absent", None, {})
    assert planned["action"] == "none"
    assert planned["changed"] is False


def test_plan_absent_on_existing_deletes():
    planned = logic.plan("absent", make_current(), {})
    assert planned["action"] == "delete"
    assert planned["changed"] is True


def test_plan_create_collects_description():
    planned = logic.plan("present", None, logic.build_desired(make_params(description="d")))
    assert planned["action"] == "create"
    assert planned["attr_changes"] == {"description": "d"}


def test_plan_noop_is_idempotent():
    planned = logic.plan("present", make_current(description="d"),
                         logic.build_desired(make_params(description="d")))
    assert planned["action"] == "none"
    assert planned["changed"] is False


def test_plan_description_change():
    planned = logic.plan("present", make_current(description="old"),
                         logic.build_desired(make_params(description="new")))
    assert planned["attr_changes"] == {"description": "new"}
    assert planned["changed"] is True


def test_build_diff_present_modify():
    current = make_current(description="old")
    desired = logic.build_desired(make_params(description="new"))
    planned = logic.plan("present", current, desired)
    diff = logic.build_diff("present", current, desired, planned)
    assert diff["before"]["description"] == "old"
    assert diff["after"]["description"] == "new"
