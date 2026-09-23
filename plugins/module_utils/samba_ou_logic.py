# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for the ``samba_ou`` module.

Imports nothing from ``samba``. It works on plain Python data describing the
current and desired OU state, decides the required change and the check-mode
behaviour, and orchestrates the work through an injected ``io`` object whose
methods perform the LDB reads/writes (and the DN construction, which needs
ldb). Keeping this layer binding-free lets the unit tests run without the
bindings.
"""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils.samba_user_logic import same_value


class SambaOuError(Exception):
    """User-facing error the module turns into ``fail_json``."""


_ACTION_LABEL = {
    "create": "created",
    "modify": "modified",
    "delete": "deleted",
    "none": "unchanged",
}


def build_desired(params):
    """Build the desired-state dict from the module parameters."""
    desired = {}
    if params.get("description") is not None:
        desired["description"] = params["description"]
    return desired


def plan(state, current, desired):
    """Decide the create/modify/delete action and the attribute changes."""
    if state == "absent":
        if current is None:
            return {"action": "none", "attr_changes": {}, "changed": False}
        return {"action": "delete", "attr_changes": {}, "changed": True}

    if current is None:
        attr_changes = {}
        # Removing the description (empty string) is a no-op on a new OU.
        if desired.get("description"):
            attr_changes["description"] = desired["description"]
        return {"action": "create", "attr_changes": attr_changes, "changed": True}

    attr_changes = {}
    if "description" in desired and not same_value(current.get("description"), desired["description"]):
        # ``None`` means "remove the attribute" (the caller's empty string).
        attr_changes["description"] = desired["description"] or None
    changed = bool(attr_changes)
    return {"action": "modify" if changed else "none", "attr_changes": attr_changes, "changed": changed}


def _effective_description(current, desired, planned):
    """Return the description as it will look after the planned change."""
    description = current.get("description") if current is not None else (desired.get("description") or None)
    if "description" in planned["attr_changes"]:
        description = planned["attr_changes"]["description"]
    return description


def public_state(current, name, path):
    """Return the externally reported state for an existing/observed OU."""
    if current is None:
        return {"name": name, "path": path, "state": "absent"}
    return {
        "name": name,
        "path": path,
        "state": "present",
        "dn": current.get("_dn"),
        "description": current.get("description"),
    }


def build_diff(state, current, desired, planned):
    """Build an Ansible before/after diff for the managed OU fields."""
    before = {"description": current.get("description")} if current is not None else {}
    if state == "absent":
        return {"before": before, "after": {} if current is not None else before}
    return {"before": before, "after": {"description": _effective_description(current, desired, planned)}}


def run(params, check_mode, io):
    """Orchestrate read -> plan -> (check-mode?) -> write -> report.

    ``io`` provides ``read_current``, ``parent_exists``, ``create_ou``,
    ``set_description`` and ``delete_ou`` and is responsible for the safe DN
    construction. Injecting it keeps this function testable without the samba
    bindings.
    """
    name = params["name"]
    path = params["path"]
    state = params["state"]
    desired = build_desired(params)

    current = io.read_current(name, path)
    planned = plan(state, current, desired)

    # Validate the parent before anything is reported or written, so check mode
    # fails exactly where a real run would. Read-only; only a create needs it.
    # The narrow race where the parent vanishes afterwards is caught by create_ou().
    if planned["action"] == "create" and not io.parent_exists(path):
        raise SambaOuError(f"path '{path}' does not exist; create it first")

    result = {
        "changed": planned["changed"],
        "action": _ACTION_LABEL[planned["action"]],
        "diff": build_diff(state, current, desired, planned),
    }

    if not planned["changed"]:
        result["ou"] = public_state(current, name, path)
        return result

    if check_mode:
        if state == "absent":
            result["ou"] = {"name": name, "path": path, "state": "absent"}
        else:
            ou = {"name": name, "path": path, "state": "present",
                  "description": _effective_description(current, desired, planned)}
            if current is not None and current.get("_dn") is not None:
                ou["dn"] = current["_dn"]
            result["ou"] = ou
        return result

    if planned["action"] == "delete":
        deleted = io.delete_ou(current["_dn"])
        if not deleted:
            # Removed concurrently between read and write; absent already holds.
            result["changed"] = False
            result["action"] = _ACTION_LABEL["none"]
            result["diff"] = {"before": {}, "after": {}}
        result["ou"] = {"name": name, "path": path, "state": "absent"}
        return result

    if planned["action"] == "create":
        io.create_ou(name, path, desired.get("description") or None)
        current = io.read_current(name, path)

    if current is None:
        raise SambaOuError(f"OU '{name}' could not be read back after creation")

    # On create the description was already set via create_ou; only an existing
    # OU needs a separate modify.
    if planned["action"] == "modify" and "description" in planned["attr_changes"]:
        io.set_description(current["_dn"], planned["attr_changes"]["description"])

    result["ou"] = public_state(io.read_current(name, path), name, path)
    return result
