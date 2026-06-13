# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for the ``samba_user`` module.

This module deliberately imports nothing from ``samba``. It works on plain
Python dictionaries describing the current and desired user state, computes the
required changes, decides the check-mode behaviour, and orchestrates the actual
work through an injected ``io`` object whose methods perform the LDB
reads/writes. Keeping this layer binding-free is exactly what lets the unit
tests exercise it inside the sanity/units container without ``samba`` present.
"""

from __future__ import annotations


class SambaUserError(Exception):
    """User-facing error the module turns into ``fail_json``."""


#: Module parameter names of the simple string attributes we manage, mapped to
#: their LDAP attribute names.
ATTR_TO_LDAP = {
    "given_name": "givenName",
    "surname": "sn",
    "display_name": "displayName",
    "email": "mail",
    "description": "description",
}

#: ACCOUNTDISABLE bit inside the ``userAccountControl`` attribute.
UAC_ACCOUNTDISABLE = 0x0002

_ACTION_LABEL = {
    "create": "created",
    "modify": "modified",
    "delete": "deleted",
    "none": "unchanged",
}


def build_desired(params):
    """Build the desired-state dict from the module parameters.

    Only simple attributes the caller actually set (non-``None``) are included,
    so attributes the user did not mention are never diffed and therefore never
    touched. ``enabled`` always carries a value (it has a default) and is always
    present.
    """
    desired = {}
    for name in ATTR_TO_LDAP:
        value = params.get(name)
        if value is not None:
            desired[name] = value
    desired["enabled"] = params["enabled"]
    return desired


def plan(state, current, desired):
    """Decide what must change, without performing any I/O.

    :param state: ``present`` or ``absent``.
    :param current: normalized current-state dict, or ``None`` if the user does
        not exist.
    :param desired: the result of :func:`build_desired`.
    :returns: dict with ``action`` (``create``/``modify``/``delete``/``none``),
        ``attr_changes`` (param name -> value), ``enable_change`` (the desired
        ``enabled`` bool when it must change, else ``None``) and ``changed``.
    """
    if state == "absent":
        if current is None:
            return {"action": "none", "attr_changes": {}, "enable_change": None, "changed": False}
        return {"action": "delete", "attr_changes": {}, "enable_change": None, "changed": True}

    if current is None:
        attr_changes = {name: value for name, value in desired.items() if name != "enabled"}
        enable_change = None if desired["enabled"] else False
        return {"action": "create", "attr_changes": attr_changes, "enable_change": enable_change, "changed": True}

    attr_changes = {}
    for name, value in desired.items():
        if name == "enabled":
            continue
        if current.get(name) != value:
            attr_changes[name] = value
    enable_change = desired["enabled"] if current.get("enabled") != desired["enabled"] else None
    changed = bool(attr_changes) or enable_change is not None
    return {
        "action": "modify" if changed else "none",
        "attr_changes": attr_changes,
        "enable_change": enable_change,
        "changed": changed,
    }


def _managed_fields(current):
    """Return only the managed fields of a current-state dict (no internals)."""
    fields = {name: current.get(name) for name in ATTR_TO_LDAP}
    fields["enabled"] = current.get("enabled")
    return fields


def _effective_fields(current, desired, planned):
    """Return the managed fields as they will look after the planned changes."""
    if current is not None:
        fields = _managed_fields(current)
    else:
        fields = {name: None for name in ATTR_TO_LDAP}
        fields["enabled"] = desired["enabled"]
    fields.update(planned["attr_changes"])
    if planned["enable_change"] is not None:
        fields["enabled"] = planned["enable_change"]
    return fields


def public_state(current, username):
    """Return the externally reported state for an existing/observed user."""
    if current is None:
        return {"username": username, "state": "absent"}
    state = {"username": username, "state": "present", "enabled": current.get("enabled")}
    if current.get("_dn") is not None:
        state["dn"] = current["_dn"]
    for name in ATTR_TO_LDAP:
        state[name] = current.get(name)
    return state


def build_diff(state, current, desired, planned):
    """Build an Ansible before/after diff for the managed fields."""
    before = _managed_fields(current) if current is not None else {}
    if state == "absent":
        return {"before": before, "after": {} if current is not None else before}
    return {"before": before, "after": _effective_fields(current, desired, planned)}


def run(params, check_mode, io):
    """Orchestrate read -> plan -> (check-mode?) -> write -> report.

    ``io`` provides ``read_current``, ``create_user``, ``apply_attrs``,
    ``set_enabled`` and ``delete_user``. Injecting it keeps this function
    testable without the samba bindings.
    """
    username = params["username"]
    state = params["state"]
    desired = build_desired(params)

    current = io.read_current(username)
    planned = plan(state, current, desired)

    if planned["action"] == "create" and not params.get("password"):
        raise SambaUserError("password is required to create user '%s'" % username)

    result = {
        "changed": planned["changed"],
        "action": _ACTION_LABEL[planned["action"]],
        "diff": build_diff(state, current, desired, planned),
    }

    if not planned["changed"]:
        result["user"] = public_state(current, username)
        return result

    if check_mode:
        if state == "absent":
            result["user"] = {"username": username, "state": "absent"}
        else:
            user = {"username": username, "state": "present"}
            user.update(_effective_fields(current, desired, planned))
            if current is not None and current.get("_dn") is not None:
                user["dn"] = current["_dn"]
            result["user"] = user
        return result

    if planned["action"] == "delete":
        deleted = io.delete_user(current["_dn"])
        if not deleted:
            # The object was removed concurrently between read and write; the
            # desired state (absent) already holds, so this is a no-op.
            result["changed"] = False
            result["action"] = _ACTION_LABEL["none"]
            result["diff"] = {"before": {}, "after": {}}
        result["user"] = {"username": username, "state": "absent"}
        return result

    if planned["action"] == "create":
        io.create_user(username, params["password"])
        current = io.read_current(username)

    if current is None:
        raise SambaUserError("user '%s' could not be read back after creation" % username)

    if planned["attr_changes"]:
        io.apply_attrs(current["_dn"], planned["attr_changes"])
    if planned["enable_change"] is not None:
        io.set_enabled(current["_dn"], current["_uac"], planned["enable_change"])

    result["user"] = public_state(io.read_current(username), username)
    return result
