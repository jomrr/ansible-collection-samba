# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the pure samba_group logic (no samba bindings required)."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_group_logic as logic


def make_params(**over):
    params = {
        "name": "engineers",
        "scope": "global",
        "category": "security",
        "description": None,
        "members": None,
        "members_purge": False,
        "state": "present",
    }
    params.update(over)
    return params


def make_current(**over):
    current = {
        "description": None,
        "group_type": logic.group_type("global", "security"),
        "members": [],
        "_dn": "CN=engineers,CN=Users,DC=example,DC=com",
    }
    current.update(over)
    return current


# --- groupType: verified against samba.dsdb 4.23.8 GTYPE_* values ---

def test_group_type_security_combinations():
    assert logic.group_type("global", "security") == 0x80000002
    assert logic.group_type("domain_local", "security") == 0x80000004
    assert logic.group_type("universal", "security") == 0x80000008


def test_group_type_distribution_combinations():
    assert logic.group_type("global", "distribution") == 0x00000002
    assert logic.group_type("domain_local", "distribution") == 0x00000004
    assert logic.group_type("universal", "distribution") == 0x00000008


def test_decode_group_type_roundtrip():
    for scope in ("global", "domain_local", "universal"):
        for category in ("security", "distribution"):
            assert logic.decode_group_type(logic.group_type(scope, category)) == (scope, category)


def test_decode_group_type_accepts_signed_form():
    # 0x80000002 stored signed is -2147483646; it must decode the same.
    assert logic.decode_group_type(-2147483646) == ("global", "security")


def test_normalise_int32_security_is_signed():
    assert logic.normalise_int32(0x80000002) == "-2147483646"


def test_normalise_int32_distribution_is_positive():
    assert logic.normalise_int32(0x00000002) == "2"


# --- plan ---

def test_plan_absent_on_missing_is_noop():
    planned = logic.plan("absent", None, {})
    assert planned["action"] == "none"
    assert planned["changed"] is False


def test_plan_absent_on_existing_deletes():
    planned = logic.plan("absent", make_current(), {})
    assert planned["action"] == "delete"
    assert planned["changed"] is True


def test_plan_create_collects_description():
    desired = logic.build_desired(make_params(description="staff"))
    planned = logic.plan("present", None, desired)
    assert planned["action"] == "create"
    assert planned["attr_changes"] == {"description": "staff"}


def test_plan_noop_is_idempotent():
    planned = logic.plan("present", make_current(), logic.build_desired(make_params()))
    assert planned["action"] == "none"
    assert planned["changed"] is False


def test_plan_group_type_change():
    desired = logic.build_desired(make_params(scope="universal"))
    planned = logic.plan("present", make_current(), desired)
    assert "group_type" in planned["attr_changes"]
    assert planned["changed"] is True


def test_plan_description_change():
    desired = logic.build_desired(make_params(description="new"))
    planned = logic.plan("present", make_current(description="old"), desired)
    assert planned["attr_changes"] == {"description": "new"}


def test_plan_group_type_signed_current_is_idempotent():
    # Current groupType stored in signed form must not look like a change.
    desired = logic.build_desired(make_params(scope="global", category="security"))
    planned = logic.plan("present", make_current(group_type=-2147483646), desired)
    assert planned["changed"] is False


# --- RFC2307/POSIX gid_number ---

def test_build_desired_includes_gid_number():
    assert logic.build_desired(make_params(gid_number=10000))["gid_number"] == 10000


def test_plan_gid_number_change():
    desired = logic.build_desired(make_params(gid_number=10000))
    planned = logic.plan("present", make_current(gid_number=500), desired)
    assert planned["attr_changes"] == {"gid_number": 10000}
    assert planned["changed"] is True


def test_plan_gid_number_idempotent_integer():
    # Same integer gid must not look like a change (no str-vs-int artifact).
    desired = logic.build_desired(make_params(gid_number=10000))
    planned = logic.plan("present", make_current(gid_number=10000), desired)
    assert planned["action"] == "none"
    assert planned["changed"] is False


class _ProbeIO:
    """Minimal io exposing only the provisioning probe the precheck needs."""

    def __init__(self, provisioned):
        self._provisioned = provisioned
        self.probed = False

    def rfc2307_provisioned(self):
        self.probed = True
        return self._provisioned


def test_precheck_no_gid_skips_probe():
    io = _ProbeIO(provisioned=False)
    logic.check_posix_preconditions(logic.build_desired(make_params(description="x")), io)
    assert io.probed is False


def test_precheck_refuses_without_rfc2307():
    io = _ProbeIO(provisioned=False)
    with pytest.raises(logic.SambaGroupError):
        logic.check_posix_preconditions(logic.build_desired(make_params(gid_number=10000)), io)


def test_precheck_passes_with_rfc2307():
    io = _ProbeIO(provisioned=True)
    logic.check_posix_preconditions(logic.build_desired(make_params(gid_number=10000)), io)
    assert io.probed is True


def test_precheck_negative_gid_fails_before_probe():
    io = _ProbeIO(provisioned=True)
    with pytest.raises(logic.SambaGroupError):
        logic.check_posix_preconditions(logic.build_desired(make_params(gid_number=-1)), io)
    assert io.probed is False


# --- member set-diff ---

def test_diff_members_additive_adds_only():
    diff = logic.diff_members(["CN=a", "CN=b"], ["CN=b", "CN=c"], purge=False)
    assert diff["adds"] == ["CN=c"]
    assert diff["removes"] == []


def test_diff_members_authoritative_removes_unlisted():
    diff = logic.diff_members(["CN=a", "CN=b"], ["CN=b", "CN=c"], purge=True)
    assert diff["adds"] == ["CN=c"]
    assert diff["removes"] == ["CN=a"]


def test_diff_members_no_change():
    diff = logic.diff_members(["CN=a", "CN=b"], ["CN=a", "CN=b"], purge=True)
    assert diff["adds"] == []
    assert diff["removes"] == []


def test_diff_members_order_and_case_independent():
    diff = logic.diff_members(
        ["CN=Foo,DC=x", "CN=Bar,DC=x"], ["cn=bar,dc=x", "cn=foo,dc=x"], purge=True,
    )
    assert diff["adds"] == []
    assert diff["removes"] == []
