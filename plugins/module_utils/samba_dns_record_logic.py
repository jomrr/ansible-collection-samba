# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for the ``samba_dns_record`` module.

Imports nothing from ``samba``. It validates the record parameters, normalizes
them into a plain "spec" dict, decides record equality (mirroring the semantics
of ``samba.dsdb_dns.records_match`` - verified against the bindings: serial/ttl
are ignored, AAAA is compared canonically, names case- and trailing-dot
insensitively, MX/SRV by their full structure, TXT exactly), and orchestrates
the work through an injected ``io`` object. Keeping this layer binding-free lets
the unit tests run without the samba bindings.

``socket`` is from the standard library (not samba), so IPv4/IPv6 validation and
canonicalization live here.
"""

from __future__ import annotations

import socket

#: The record types this module manages.
TYPE_CHOICES = ["A", "AAAA", "CNAME", "PTR", "MX", "NS", "SRV", "TXT"]

#: Types whose value is a single DNS name (compared case/trailing-dot insensitive).
_NAME_TYPES = {"CNAME", "PTR", "NS"}

_UINT16_MAX = 0xFFFF


class SambaDnsRecordError(Exception):
    """User-facing error the module turns into ``fail_json``."""


def _name_equal(left, right):
    """Compare two DNS names case- and trailing-dot-insensitively."""
    return left.rstrip(".").lower() == right.rstrip(".").lower()


def _ipv6_normalise(addr):
    """Return the canonical form of an IPv6 address (raises ValueError if bad)."""
    return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, addr))


def _require_port_range(value, field):
    """Validate that an unsigned 16-bit field is in range."""
    if value < 0 or value > _UINT16_MAX:
        raise SambaDnsRecordError("%s must be between 0 and %d" % (field, _UINT16_MAX))


def validate(params):
    """Validate the parameters and return the normalized desired record spec.

    Raises :class:`SambaDnsRecordError` on data that does not fit the type, so
    invalid input never reaches the directory.
    """
    rtype = params["type"]
    value = params["value"]
    ttl = params["ttl"]

    if value is None or value == "":
        raise SambaDnsRecordError("value is required for a %s record" % rtype)
    if ttl < 0 or ttl > 0xFFFFFFFF:
        raise SambaDnsRecordError("ttl must be between 0 and %d" % 0xFFFFFFFF)

    spec = {"type": rtype, "value": value, "ttl": ttl}

    if rtype == "A":
        try:
            socket.inet_pton(socket.AF_INET, value)
        except OSError:
            raise SambaDnsRecordError("value '%s' is not a valid IPv4 address" % value)
    elif rtype == "AAAA":
        try:
            spec["value"] = _ipv6_normalise(value)
        except (OSError, ValueError):
            raise SambaDnsRecordError("value '%s' is not a valid IPv6 address" % value)
    elif rtype == "MX":
        _require_port_range(params["preference"], "preference")
        spec["preference"] = params["preference"]
    elif rtype == "SRV":
        for field in ("priority", "weight", "port"):
            _require_port_range(params[field], field)
            spec[field] = params[field]

    return spec


def records_equal(left, right):
    """True if two record specs denote the same record (same identity)."""
    if left["type"] != right["type"]:
        return False
    rtype = left["type"]
    if rtype == "A":
        return left["value"] == right["value"]
    if rtype == "AAAA":
        # Canonicalize both sides; the stored form may differ from the input.
        return _ipv6_normalise(left["value"]) == _ipv6_normalise(right["value"])
    if rtype == "TXT":
        return left["value"] == right["value"]
    if rtype in _NAME_TYPES:
        return _name_equal(left["value"], right["value"])
    if rtype == "MX":
        return left["preference"] == right["preference"] and _name_equal(left["value"], right["value"])
    if rtype == "SRV":
        return (
            left["priority"] == right["priority"]
            and left["weight"] == right["weight"]
            and left["port"] == right["port"]
            and _name_equal(left["value"], right["value"])
        )
    raise SambaDnsRecordError("unsupported record type '%s'" % rtype)


def public_state(spec, zone, name, present):
    """Return the externally reported record state."""
    state = {
        "zone": zone,
        "name": name,
        "type": spec["type"],
        "value": spec["value"],
        "state": "present" if present else "absent",
    }
    for field in ("preference", "priority", "weight", "port"):
        if field in spec:
            state[field] = spec[field]
    return state


def build_diff(zone, name, spec, before_present, after_present):
    """Build a before/after diff of the record's presence."""
    entry = {"zone": zone, "name": name, "type": spec["type"], "value": spec["value"]}
    before = dict(entry) if before_present else {}
    after = dict(entry) if after_present else {}
    return {"before": before, "after": after}


def run(params, check_mode, io):
    """Orchestrate validate -> read -> match -> (check-mode?) -> write -> report.

    ``io`` provides ``zone_exists``, ``read``, ``add`` and ``remove``. The match
    is computed here (samba-free) so the decision is unit-testable; ``io`` re-reads
    at write time and returns whether it actually changed anything, so a record
    created or removed concurrently is reconciled as an honest no-op.
    """
    zone = params["zone"]
    name = params["name"]
    state = params["state"]
    desired = validate(params)

    if not io.zone_exists(zone):
        raise SambaDnsRecordError("zone '%s' does not exist" % zone)

    existing = io.read(zone, name)
    present_now = existing is not None and any(records_equal(desired, rec) for rec in existing)

    if state == "present":
        changed = not present_now
        if changed and not check_mode:
            changed = io.add(zone, name, desired)
    else:
        changed = present_now
        if changed and not check_mode:
            changed = io.remove(zone, name, desired)

    # After a successful run the desired state holds, so the reported record and
    # the diff "after" reflect the requested state, independent of whether a
    # concurrent change made the write itself a no-op.
    after_present = (state == "present")
    return {
        "changed": changed,
        "record": public_state(desired, zone, name, after_present),
        "diff": build_diff(zone, name, desired, present_now, after_present),
    }
