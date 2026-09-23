# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free planner for samba_schema_extension.

Turns a catalog entry into the add and modify operations the directory needs,
grouped in phases that respect the schema's dependencies: attributes and
extended rights first, then classes (which may contain the new attributes),
then the links into existing classes (which may name the new classes). The
current schema comes from an injected reader whose records are plain dicts
(attribute -> list of text values, GUIDs as canonical strings, ``_dn``); the
operations are plain dicts the I/O turns into ldb messages. Schema is only
ever extended: an existing entry is completed, list properties only gain
values, nothing is removed.
"""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils import samba_schema_catalog as catalog


class SambaSchemaError(Exception):
    """User-facing error the module turns into ``fail_json``."""


#: List properties compared as sets and only ever extended.
_ADD_ONLY = ("mayContain", "auxiliaryClass")

#: Properties that identify the entry (its RDN) or are set on the add only.
_SKIP = ("cn", "objectClass")


def _values(definition, **extra):
    """The definition's properties as lists of text values, plus ``extra``."""
    values = {}
    for name, value in list(definition.items()) + list(extra.items()):
        values[name] = [value] if isinstance(value, str) else list(value)
    return values


def _lower(values):
    return sorted(value.lower() for value in values)


def _reconcile(current, dn, desired, label):
    """An add when the entry is missing, a modify of what differs, or None."""
    if current is None:
        return {"action": "add", "dn": dn, "values": desired, "label": f"add {label}"}
    replace = {}
    add = {}
    for name, values in desired.items():
        if name in _SKIP:
            continue
        have = current.get(name, [])
        if name in _ADD_ONLY:
            missing = [value for value in values if value.lower() not in _lower(have)]
            if missing:
                add[name] = missing
        elif _lower(have) != _lower(values):
            replace[name] = values
    if not replace and not add:
        return None
    changed = ", ".join(sorted(list(replace) + list(add)))
    return {"action": "modify", "dn": dn, "replace": replace, "add": add, "label": f"modify {label} ({changed})"}


def plan(extension, reader):
    """The operations an extension needs, as ``[(phase name, [operation, ...]), ...]``.

    ``reader`` provides ``schema_dn()``, ``config_dn()``, ``find_schema(ldap
    display name, attrs)`` and ``find_right(rights guid, attrs)``, each returning
    a record or None.
    """
    spec = catalog.EXTENSIONS[extension]
    schema_dn = reader.schema_dn()
    first = []
    for attribute in spec["attributes"]:
        desired = _values(attribute, objectClass="attributeSchema")
        current = reader.find_schema(attribute["lDAPDisplayName"], list(desired))
        dn = "CN={},{}".format(attribute["cn"], schema_dn)
        operation = _reconcile(current, dn, desired, "attributeSchema {}".format(attribute["lDAPDisplayName"]))
        if operation:
            first.append(operation)
    rights_dn = f"CN=Extended-Rights,{reader.config_dn()}"
    for right in spec["rights"]:
        desired = _values(right, objectClass="controlAccessRight")
        current = reader.find_right(right["rightsGuid"], list(desired))
        dn = "CN={},{}".format(right["cn"], rights_dn)
        operation = _reconcile(current, dn, desired, "controlAccessRight {}".format(right["cn"]))
        if operation:
            first.append(operation)
    classes = []
    for definition in spec["classes"]:
        dn = "CN={},{}".format(definition["cn"], schema_dn)
        desired = _values(definition, objectClass="classSchema", defaultObjectCategory=dn)
        current = reader.find_schema(definition["lDAPDisplayName"], list(desired))
        operation = _reconcile(current, dn, desired, "classSchema {}".format(definition["lDAPDisplayName"]))
        if operation:
            classes.append(operation)
    links = []
    for class_name, prop, values in spec["links"]:
        current = reader.find_schema(class_name, [prop])
        if current is None:
            raise SambaSchemaError(f"class '{class_name}' is not in the schema")
        operation = _reconcile(current, current["_dn"], {prop: list(values)}, f"classSchema {class_name}")
        if operation:
            links.append(operation)
    return [("attributes and rights", first), ("classes", classes), ("class links", links)]


def run(params, check_mode, io):
    """Plan and, unless in check mode, apply an extension phase by phase.

    ``io`` is the reader above plus ``require_schema_master()``, ``apply(ops)``
    (one transaction) and ``schema_update_now()``, called after each applied
    phase so the next one sees the new schema objects.
    """
    extension = params["extension"]
    io.require_schema_master()
    phases = plan(extension, io)
    changes = [operation["label"] for dummy_name, operations in phases for operation in operations]
    if changes and not check_mode:
        for dummy_name, operations in phases:
            if operations:
                io.apply(operations)
                io.schema_update_now()
    return {"changed": bool(changes), "extension": extension, "changes": changes}
