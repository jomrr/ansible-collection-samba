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

#: The attributes samba's ``newuser`` sets on the add itself (the I/O maps them
#: to its keyword arguments), so a create needs no modify for them.
#: ``display_name`` is not among them: newuser derives displayName from the
#: names; an explicit value is a follow-up write.
CREATE_ATTRS = (
    "given_name", "surname", "email", "description",
    "uid_number", "gid_number", "unix_home_directory", "login_shell", "gecos",
)

#: ACCOUNTDISABLE bit inside the ``userAccountControl`` attribute.
UAC_ACCOUNTDISABLE = 0x0002

_ACTION_LABEL = {
    "create": "created",
    "modify": "modified",
    "delete": "deleted",
    "none": "unchanged",
}


def same_value(current_value, desired_value):
    """Attribute equality where an empty desired string means "absent".

    An empty string is the caller's way to remove an attribute; a removed
    attribute reads back as ``None``, so the two must compare equal or a run
    that clears an attribute would never become idempotent.
    """
    if desired_value == "":
        return current_value is None
    return current_value == desired_value


def build_desired(params):
    """Build the desired-state dict from the module parameters.

    Only attributes the caller actually set (non-``None``) are included, so
    attributes the user did not mention are never diffed and therefore never
    touched. That holds for ``enabled`` too: left unset, an existing account
    keeps its state and a new one is created enabled (samba's default). An
    empty string is kept as the request to remove the attribute.
    """
    desired = {}
    for name in ATTR_TO_LDAP:
        value = params.get(name)
        if value is not None:
            desired[name] = value
    if params.get("enabled") is not None:
        desired["enabled"] = params["enabled"]
    return desired


def derived_display_name(desired):
    """The displayName samba's ``newuser`` derives on create: the names joined.

    Mirrors ``SamDB.fullname_from_names`` for the parts this module manages
    (given name and surname), so the diff and check mode predict what a real
    create leaves behind. ``None`` when neither name is given.
    """
    parts = (desired.get("given_name"), desired.get("surname"))
    return " ".join(part for part in parts if part) or None


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
        # Removing an attribute (empty string) is a no-op on a new account.
        attr_changes = {name: value for name, value in desired.items() if name != "enabled" and value != ""}
        # A new account comes up enabled; only an explicit enabled=false needs a toggle.
        enable_change = False if desired.get("enabled") is False else None
        return {"action": "create", "attr_changes": attr_changes, "enable_change": enable_change, "changed": True}

    attr_changes = {}
    for name, value in desired.items():
        if name == "enabled":
            continue
        if not same_value(current.get(name), value):
            # ``None`` in attr_changes means "remove the attribute".
            attr_changes[name] = None if value == "" else value
    enable_change = None
    if "enabled" in desired and current.get("enabled") != desired["enabled"]:
        enable_change = desired["enabled"]
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
        fields["enabled"] = desired.get("enabled", True)
        # newuser derives displayName from the names; an explicit display_name
        # in attr_changes overrides it below.
        fields["display_name"] = derived_display_name(desired)
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


def _undo_create(io, username, exc):
    """Remove the object a failed create left behind and report the cause.

    LDAP offers no transactions (ldb's LDAP backend implements
    transaction_start/commit/cancel as no-ops), so a create is made
    all-or-nothing by compensation: whichever step failed after the initial
    add (an explicit display name, the enabled state, the move a domain-root
    path needs), the object this run created is
    deleted again. Only an object that did not exist when the run started
    reaches this point, so nothing foreign is ever removed; if the failed step
    was the add itself, there is nothing to remove and only the cause is
    reported.
    """
    current = io.read_current(username)
    if current is None:
        raise SambaUserError("creating user '%s' failed: %s" % (username, exc))
    try:
        io.delete(current["_dn"])
    except Exception as undo_exc:
        raise SambaUserError(
            "creating user '%s' failed: %s; removing the partially created object failed too: %s"
            % (username, exc, undo_exc)
        )
    raise SambaUserError(
        "creating user '%s' failed: %s; the partially created object was removed" % (username, exc)
    )


def run(params, check_mode, io):
    """Orchestrate read -> plan -> (check-mode?) -> write -> report.

    ``io`` provides ``read_current``, ``rfc2307_provisioned``, ``create_user``,
    ``apply_attrs``, ``set_enabled``, ``set_password``, ``delete`` and the
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

    # Validate the target location (path parses, parent exists) before anything
    # is reported or written, so check mode fails exactly where a real run would
    # and no partial create or move happens. Read-only; skipped when nothing is
    # created or moved. The narrow race where the parent vanishes afterwards is
    # caught by move().
    if state == "present" and path is not None and (current is None or move_needed) \
            and not io.parent_exists(path):
        raise SambaUserError("path '%s' does not exist; create it first" % path)

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
        deleted = io.delete(current["_dn"])
        if not deleted:
            # The object was removed concurrently between read and write; the
            # desired state (absent) already holds, so this is a no-op.
            result["changed"] = False
            result["action"] = _ACTION_LABEL["none"]
            result["diff"] = {"before": {}, "after": {}}
        result["user"] = {"username": username, "state": "absent"}
        return result

    created = planned["action"] == "create"
    attr_changes = planned["attr_changes"]
    if created:
        # One add: newuser places the account under path and sets the names,
        # mail, description and POSIX attributes itself; only what it cannot
        # take (an explicit display name) is written afterwards.
        create_attrs = {name: value for name, value in attr_changes.items() if name in CREATE_ATTRS}
        attr_changes = {name: value for name, value in attr_changes.items() if name not in CREATE_ATTRS}
        try:
            io.create_user(username, password, path, create_attrs)
        except SambaUserError:
            # A concurrent create: the object is not ours, nothing to undo.
            raise
        except Exception as exc:
            # samba's newuser cleans up its own password step (it deletes the
            # account again when setting the password fails), so usually there
            # is nothing left to undo here; the guard covers whatever remains.
            _undo_create(io, username, exc)
        current = io.read_current(username)
        if current is None:
            raise SambaUserError("user '%s' could not be read back after creation" % username)

    # Order: move first (so the later attribute writes target the final DN; a
    # fresh account is already in place unless path is the domain root, which
    # newuser cannot express), then attributes, enable state and password.
    # Each is its own LDAP operation; on a fresh object a failure rolls the
    # create back, on an existing object the earlier steps stay applied and a
    # re-run completes the rest.
    try:
        if io.needs_move(current["_dn"], path):
            io.move(current["_dn"], path)
            current = io.read_current(username)

        if attr_changes:
            io.apply_attrs(current["_dn"], attr_changes)
        if planned["enable_change"] is not None:
            io.set_enabled(current["_dn"], current["_uac"], planned["enable_change"])
        if set_pw_on_existing:
            io.set_password(current["_dn"], password)
    except Exception as exc:
        if created:
            _undo_create(io, username, exc)
        raise

    result["user"] = public_state(io.read_current(username), username)
    return result
