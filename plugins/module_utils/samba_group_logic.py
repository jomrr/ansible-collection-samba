# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for the ``samba_group`` module.

Imports nothing from ``samba``. It works on plain Python data describing the
current and desired group state, computes the groupType bitfield, the member
set-diff, the required changes and the check-mode behaviour, and orchestrates
the work through an injected ``io`` object. Keeping this layer binding-free lets
the unit tests run without the samba bindings.
"""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils.samba_user_logic import same_value


class SambaGroupError(Exception):
    """User-facing error the module turns into ``fail_json``."""


# groupType bitfield. Values verified against samba.dsdb 4.23.8:
#   GTYPE_SECURITY_GLOBAL_GROUP        = 0x80000002
#   GTYPE_SECURITY_DOMAIN_LOCAL_GROUP  = 0x80000004
#   GTYPE_SECURITY_UNIVERSAL_GROUP     = 0x80000008
#   GTYPE_DISTRIBUTION_GLOBAL_GROUP    = 0x00000002
#   GTYPE_DISTRIBUTION_DOMAIN_LOCAL_GROUP = 0x00000004
#   GTYPE_DISTRIBUTION_UNIVERSAL_GROUP = 0x00000008
# i.e. SECURITY_ENABLED bit OR'd with the scope bit. The I/O layer cross-checks
# these against samba.dsdb at runtime.
GROUP_TYPE_SECURITY_ENABLED = 0x80000000
SCOPE_BITS = {
    "global": 0x00000002,
    "domain_local": 0x00000004,
    "universal": 0x00000008,
}

_ACTION_LABEL = {
    "create": "created",
    "modify": "modified",
    "delete": "deleted",
    "none": "unchanged",
}


def group_type(scope, category):
    """Return the groupType bitfield for the given scope and category."""
    value = SCOPE_BITS[scope]
    if category == "security":
        value |= GROUP_TYPE_SECURITY_ENABLED
    return value


def normalise_int32(value):
    """Return value as a signed 32-bit decimal string.

    Mirrors ``samba.common.normalise_int32``; groupType is stored signed, so a
    high-bit (security) value must be written in its negative form to satisfy
    the 32-bit signed schema range.
    """
    number = int(value)
    if number & 0x80000000 and number > 0:
        number -= 0x100000000
    return str(number)


def decode_group_type(value):
    """Return the (scope, category) tuple for a groupType value (or None scope)."""
    normalized = int(value) & 0xFFFFFFFF
    category = "security" if normalized & GROUP_TYPE_SECURITY_ENABLED else "distribution"
    scope_bit = normalized & sum(SCOPE_BITS.values())
    scope = None
    for name, bit in SCOPE_BITS.items():
        if scope_bit == bit:
            scope = name
    return scope, category


def _same_group_type(left, right):
    """Compare two groupType values as unsigned 32-bit (sign-representation safe)."""
    return (int(left) & 0xFFFFFFFF) == (int(right) & 0xFFFFFFFF)


#: The type samba-tool gives a new group when none is asked for.
DEFAULT_SCOPE = "global"
DEFAULT_CATEGORY = "security"


def build_desired(params):
    """Build the desired-state dict from the module parameters.

    Only options the caller actually set are included. ``scope`` and
    ``category`` are no exception: left unset, an existing group keeps its
    type and a new one is created as a global security group.
    """
    desired = {}
    for name in ("scope", "category", "description", "gid_number"):
        if params.get(name) is not None:
            desired[name] = params[name]
    return desired


def create_group_type(desired):
    """Return the groupType a new group gets; unset parts take samba-tool's default."""
    return group_type(desired.get("scope") or DEFAULT_SCOPE, desired.get("category") or DEFAULT_CATEGORY)


def target_group_type(current_group_type, desired):
    """Return the groupType an existing group should have, or None to leave it.

    Only the parts given (scope, category) are reconciled; the other part is
    kept from the stored type, so updating a built-in group's description never
    tries to convert it. Fails clearly when the stored scope cannot be decoded
    and would have to be kept.
    """
    if "scope" not in desired and "category" not in desired:
        return None
    current_scope, current_category = decode_group_type(current_group_type)
    scope = desired.get("scope") or current_scope
    if scope is None:
        raise SambaGroupError(
            "the stored groupType has no recognised scope; set scope explicitly to change the category"
        )
    return group_type(scope, desired.get("category") or current_category)


def check_posix_preconditions(desired, io):
    """Validate C(gid_number) and refuse it on a non-RFC2307 domain.

    Fires only when the caller actually set C(gid_number), so groups that never
    touch POSIX attributes are unaffected and the provisioning probe is skipped.
    Validates the integer and, before any write, refuses with a clear error when
    the domain was not provisioned with C(--use-rfc2307).
    """
    if "gid_number" not in desired:
        return
    if desired["gid_number"] < 0:
        raise SambaGroupError("gid_number must be a non-negative integer")
    if not io.rfc2307_provisioned():
        raise SambaGroupError(
            "domain is not provisioned with RFC2307/--use-rfc2307; "
            "cannot set POSIX attributes (gid_number)"
        )


def plan(state, current, desired):
    """Decide the create/modify/delete action and the scalar attribute changes."""
    if state == "absent":
        if current is None:
            return {"action": "none", "attr_changes": {}, "changed": False}
        return {"action": "delete", "attr_changes": {}, "changed": True}

    if current is None:
        attr_changes = {}
        # Removing the description (empty string) is a no-op on a new group.
        if desired.get("description"):
            attr_changes["description"] = desired["description"]
        if "gid_number" in desired:
            attr_changes["gid_number"] = desired["gid_number"]
        return {"action": "create", "attr_changes": attr_changes, "changed": True}

    attr_changes = {}
    if "description" in desired and not same_value(current.get("description"), desired["description"]):
        # ``None`` means "remove the attribute" (the caller's empty string).
        attr_changes["description"] = desired["description"] or None
    if "gid_number" in desired and current.get("gid_number") != desired["gid_number"]:
        attr_changes["gid_number"] = desired["gid_number"]
    target = target_group_type(current["group_type"], desired)
    if target is not None and not _same_group_type(current["group_type"], target):
        attr_changes["group_type"] = target
    changed = bool(attr_changes)
    return {"action": "modify" if changed else "none", "attr_changes": attr_changes, "changed": changed}


def diff_members(current_dns, desired_dns, purge):
    """Compute member adds/removes as a set-diff (order-independent, case-insensitive).

    ``purge=False`` is additive (only adds); ``purge=True`` is authoritative
    (also removes members not in ``desired_dns``).
    """
    current = {dn.lower(): dn for dn in current_dns}
    desired = {dn.lower(): dn for dn in desired_dns}
    adds = [desired[key] for key in desired if key not in current]
    removes = [current[key] for key in current if key not in desired] if purge else []
    return {"adds": adds, "removes": removes}


def _decoded_fields(group_type_value, description, gid_number, members):
    """Return the managed fields decoded for human-readable diff/return."""
    scope, category = decode_group_type(group_type_value)
    return {
        "description": description,
        "gid_number": gid_number,
        "scope": scope,
        "category": category,
        "members": sorted(members),
    }


def _effective_members(current, member_diff):
    """Return the member DN list after applying the planned adds/removes."""
    members = {dn.lower(): dn for dn in (current.get("members", []) if current else [])}
    for dn in member_diff["adds"]:
        members[dn.lower()] = dn
    for dn in member_diff["removes"]:
        members.pop(dn.lower(), None)
    return list(members.values())


def _effective_state(current, desired, planned, member_diff):
    """Return the managed fields as they will look after the planned changes."""
    if current is not None:
        group_type_value = current["group_type"]
        description = current.get("description")
        gid_number = current.get("gid_number")
    else:
        group_type_value = create_group_type(desired)
        description = desired.get("description") or None
        gid_number = desired.get("gid_number")
    if "group_type" in planned["attr_changes"]:
        group_type_value = planned["attr_changes"]["group_type"]
    if "description" in planned["attr_changes"]:
        description = planned["attr_changes"]["description"]
    if "gid_number" in planned["attr_changes"]:
        gid_number = planned["attr_changes"]["gid_number"]
    return _decoded_fields(group_type_value, description, gid_number, _effective_members(current, member_diff))


def public_state(current, name):
    """Return the externally reported state for an existing/observed group."""
    if current is None:
        return {"name": name, "state": "absent"}
    state = {"name": name, "state": "present"}
    if current.get("_dn") is not None:
        state["dn"] = current["_dn"]
    state.update(_decoded_fields(
        current["group_type"], current.get("description"), current.get("gid_number"), current.get("members", []),
    ))
    return state


def build_diff(state, current, desired, planned, member_diff):
    """Build an Ansible before/after diff for the managed group fields."""
    before = (
        _decoded_fields(
            current["group_type"], current.get("description"), current.get("gid_number"), current.get("members", []),
        )
        if current is not None else {}
    )
    if state == "absent":
        return {"before": before, "after": {} if current is not None else before}
    return {"before": before, "after": _effective_state(current, desired, planned, member_diff)}


def _undo_create(io, name, exc):
    """Remove the group a failed create left behind and report the cause.

    LDAP offers no transactions (ldb's LDAP backend implements
    transaction_start/commit/cancel as no-ops), so a create is made
    all-or-nothing by compensation: whichever step failed after the initial
    add (membership, or the move a domain-root path needs), the group this run
    created is deleted again. Only a group that did not exist when the run
    started reaches this
    point, so nothing foreign is ever removed.
    """
    current = io.read_current(name)
    if current is None:
        raise SambaGroupError("creating group '%s' failed: %s" % (name, exc))
    try:
        io.delete(current["_dn"])
    except Exception as undo_exc:
        raise SambaGroupError(
            "creating group '%s' failed: %s; removing the partially created object failed too: %s"
            % (name, exc, undo_exc)
        )
    raise SambaGroupError(
        "creating group '%s' failed: %s; the partially created object was removed" % (name, exc)
    )


def run(params, check_mode, io):
    """Orchestrate read -> plan -> (check-mode?) -> write -> report.

    ``io`` provides ``read_current``, ``rfc2307_provisioned``,
    ``resolve_member``, ``create_group``, ``set_description``,
    ``set_group_type``, ``set_gid_number``, ``add_member``, ``remove_member``,
    ``delete`` and the move helpers ``needs_move``, ``parent_exists`` and
    ``move``. Injecting it keeps this function testable without the bindings.
    """
    name = params["name"]
    state = params["state"]
    members = params.get("members")
    purge = params["members_purge"]
    path = params.get("path")
    desired = build_desired(params)

    if state == "present":
        check_posix_preconditions(desired, io)

    current = io.read_current(name)
    planned = plan(state, current, desired)

    member_diff = {"adds": [], "removes": []}
    if state == "present" and members is not None:
        current_members = current["members"] if current is not None else []
        desired_dns = [io.resolve_member(member) for member in members]
        member_diff = diff_members(current_members, desired_dns, purge)

    member_planned = bool(member_diff["adds"] or member_diff["removes"])
    # A move is needed when an existing group's parent differs from the desired
    # location (path, or the default container when omitted). io compares DNs
    # with normalized ldb.Dn equality, never strings.
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
        raise SambaGroupError("path '%s' does not exist; create it first" % path)

    action = planned["action"]
    if action == "none" and (member_planned or move_needed):
        action = "modify"
    changed = planned["changed"] or member_planned or move_needed

    result = {
        "changed": changed,
        "action": _ACTION_LABEL[action],
        "diff": build_diff(state, current, desired, planned, member_diff),
    }

    if not changed:
        result["group"] = public_state(current, name)
        return result

    if check_mode:
        if state == "absent":
            result["group"] = {"name": name, "state": "absent"}
        else:
            group = {"name": name, "state": "present"}
            group.update(_effective_state(current, desired, planned, member_diff))
            if current is not None and current.get("_dn") is not None:
                group["dn"] = current["_dn"]
            result["group"] = group
        return result

    if planned["action"] == "delete":
        deleted = io.delete(current["_dn"])
        if not deleted:
            # Removed concurrently between read and write; absent already holds.
            result["changed"] = False
            result["action"] = _ACTION_LABEL["none"]
            result["diff"] = {"before": {}, "after": {}}
        result["group"] = {"name": name, "state": "absent"}
        return result

    created = planned["action"] == "create"
    if created:
        # One add: newgroup places the group under path and sets its type,
        # description and gidNumber itself; members are added afterwards.
        try:
            io.create_group(
                name, create_group_type(desired), desired.get("description") or None,
                path, desired.get("gid_number"),
            )
        except SambaGroupError:
            # A concurrent create: the object is not ours, nothing to undo.
            raise
        except Exception as exc:
            _undo_create(io, name, exc)
        current = io.read_current(name)
        if current is None:
            raise SambaGroupError("group '%s' could not be read back after creation" % name)

    # Order: move first (so later writes target the final DN; a fresh group is
    # already in place unless path is the domain root, which newgroup cannot
    # express), then attributes and membership. Each is its own LDAP operation;
    # on a fresh group a failure rolls the create back, on an existing group
    # the earlier steps stay applied and a re-run completes the rest.
    moved = False
    member_changed = False
    try:
        if io.needs_move(current["_dn"], path):
            io.move(current["_dn"], path)
            current = io.read_current(name)
            moved = True

        if planned["action"] == "modify":
            if "description" in planned["attr_changes"]:
                io.set_description(current["_dn"], planned["attr_changes"]["description"])
            if "group_type" in planned["attr_changes"]:
                io.set_group_type(current["_dn"], planned["attr_changes"]["group_type"])
            if "gid_number" in planned["attr_changes"]:
                io.set_gid_number(current["_dn"], planned["attr_changes"]["gid_number"])

        for dn in member_diff["adds"]:
            if io.add_member(current["_dn"], dn):
                member_changed = True
        for dn in member_diff["removes"]:
            if io.remove_member(current["_dn"], dn):
                member_changed = True
    except Exception as exc:
        if created:
            _undo_create(io, name, exc)
        raise

    # Honest changed: scalar/move changes are real; member ops may have been
    # no-ops due to a concurrent change (handled as idempotent no-ops in the I/O).
    result["changed"] = planned["changed"] or member_changed or moved
    if not result["changed"]:
        result["action"] = _ACTION_LABEL["none"]
        result["diff"] = {"before": {}, "after": {}}
    result["group"] = public_state(io.read_current(name), name)
    return result
