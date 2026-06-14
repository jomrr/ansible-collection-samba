# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
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


#: Module parameter names of the scalar attributes we manage, mapped to their
#: LDAP attribute names. The first group are simple strings; the RFC2307/POSIX
#: attributes follow and are handled the same way, except that the two integer
#: ones (see :data:`POSIX_INT_ATTRS`) are normalised to ``int`` on read and
#: written as a decimal string (LDB stores integers as decimal text).
ATTR_TO_LDAP = {
    "given_name": "givenName",
    "surname": "sn",
    "display_name": "displayName",
    "email": "mail",
    "description": "description",
    "uid_number": "uidNumber",
    "gid_number": "gidNumber",
    "unix_home_directory": "unixHomeDirectory",
    "login_shell": "loginShell",
    "gecos": "gecos",
}

#: The RFC2307/POSIX attributes. They require a domain provisioned with
#: ``--use-rfc2307``; setting any of them on a non-provisioned domain is refused
#: up front (see :func:`run`).
POSIX_ATTRS = ("uid_number", "gid_number", "unix_home_directory", "login_shell", "gecos")

#: The POSIX attributes whose value is an integer (LDAP INTEGER syntax).
POSIX_INT_ATTRS = ("uid_number", "gid_number")

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


def check_posix_preconditions(desired, io):
    """Validate POSIX attributes and refuse them on a non-RFC2307 domain.

    Fires only when the caller actually set at least one POSIX attribute, so
    playbooks that never touch them are unaffected and the provisioning probe is
    skipped entirely. Validates the integer fields and, before any write, refuses
    with a clear error when the domain was not provisioned with --use-rfc2307.
    """
    posix_requested = [name for name in POSIX_ATTRS if name in desired]
    if not posix_requested:
        return
    for name in POSIX_INT_ATTRS:
        value = desired.get(name)
        if value is not None and value < 0:
            raise SambaUserError("%s must be a non-negative integer" % name)
    if not io.rfc2307_provisioned():
        raise SambaUserError(
            "domain is not provisioned with RFC2307/--use-rfc2307; "
            "cannot set POSIX attributes (%s)" % ", ".join(posix_requested)
        )


def run(params, check_mode, io):
    """Orchestrate read -> plan -> (check-mode?) -> write -> report.

    ``io`` provides ``read_current``, ``rfc2307_provisioned``, ``create_user``,
    ``apply_attrs``, ``set_enabled``, ``set_password``, ``delete_user`` and the
    move helpers ``needs_move``, ``parent_exists`` and ``move``. Injecting it
    keeps this function testable without the samba bindings.
    """
    username = params["username"]
    state = params["state"]
    password = params.get("password")
    update_password = params["update_password"]
    path = params.get("path")
    desired = build_desired(params)

    if state == "present":
        check_posix_preconditions(desired, io)

    current = io.read_current(username)
    planned = plan(state, current, desired)

    if planned["action"] == "create" and not password:
        raise SambaUserError("password is required to create user '%s'" % username)

    # update_password=always sets the password on an existing user on every run.
    # The password cannot be read back to diff, so the write itself is the
    # change we make -> reporting changed:true here is honest, not an idempotency
    # break. (On create the password is already set via create_user.)
    set_pw_on_existing = (
        state == "present"
        and current is not None
        and password is not None
        and update_password == "always"
    )

    # A move is needed when an existing object's parent differs from the desired
    # location (path, or the default container when path is omitted). The DN
    # comparison is done by io via normalized ldb.Dn equality, never strings.
    move_needed = (
        state == "present"
        and current is not None
        and io.needs_move(current["_dn"], path)
    )

    action = planned["action"]
    if action == "none" and (set_pw_on_existing or move_needed):
        action = "modify"
    changed = planned["changed"] or set_pw_on_existing or move_needed

    result = {
        "changed": changed,
        "action": _ACTION_LABEL[action],
        "diff": build_diff(state, current, desired, planned),
    }

    if not changed:
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

    # Fail before any write if the target parent is missing (no partial create
    # or move). The narrow race where it vanishes afterwards is caught by move().
    if (planned["action"] == "create" or move_needed) and path is not None \
            and not io.parent_exists(path):
        raise SambaUserError("path '%s' does not exist; create it first" % path)

    if planned["action"] == "create":
        io.create_user(username, password)
        current = io.read_current(username)

    if current is None:
        raise SambaUserError("user '%s' could not be read back after creation" % username)

    # Order: move first (so the later attribute writes target the final DN),
    # then attributes, enable state and password.
    if io.needs_move(current["_dn"], path):
        io.move(current["_dn"], path)
        current = io.read_current(username)

    if planned["attr_changes"]:
        io.apply_attrs(current["_dn"], planned["attr_changes"])
    if planned["enable_change"] is not None:
        io.set_enabled(current["_dn"], current["_uac"], planned["enable_change"])
    if set_pw_on_existing:
        io.set_password(username, password)

    result["user"] = public_state(io.read_current(username), username)
    return result
