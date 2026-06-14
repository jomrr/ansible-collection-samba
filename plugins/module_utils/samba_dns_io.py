# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Samba DNS record build/extract helpers for the samba_dns_record module.

All ``samba`` imports (``samba.dcerpc.dnsp``, ``samba.ndr``) are lazy, via
importlib inside the functions - importing this module never requires the
bindings, so the static sanity phase stays green. The on-disk record structure
is ``dnsp.DnssrvRpcRecord`` (verified against samba 4.23.8), not the wire
``dnsserver.DNS_RPC_RECORD``.

These helpers translate between the plain "spec" dicts used by the samba-free
logic layer and the ``dnsp`` records stored in the directory.
"""

from __future__ import annotations

import importlib

#: Record types this module builds/extracts (the eight managed types).
_MANAGED_TYPES = ["A", "AAAA", "CNAME", "PTR", "NS", "MX", "SRV", "TXT"]
_NAME_DATA_TYPES = {"A", "AAAA", "CNAME", "PTR", "NS"}
#: TXT strings are joined with NUL for matching, so a multi-string record can
#: never accidentally compare equal to a single-string one.
_TXT_SEP = "\x00"


def load_dnsp():
    """Import and return ``samba.dcerpc.dnsp`` lazily."""
    return importlib.import_module("samba.dcerpc.dnsp")


def load_ndr():
    """Import and return ``samba.ndr`` lazily."""
    return importlib.import_module("samba.ndr")


def _type_const(dnsp, name):
    """Return the ``dnsp.DNS_TYPE_*`` constant for a type name."""
    return getattr(dnsp, "DNS_TYPE_" + name)


def _type_name(dnsp, wtype):
    """Return the managed type name for a wType, or ``None`` if unmanaged."""
    for name in _MANAGED_TYPES:
        if _type_const(dnsp, name) == wtype:
            return name
    return None


def build_record(spec):
    """Build an on-disk ``dnsp.DnssrvRpcRecord`` from a record spec.

    Serial/ttl do not affect identity (the matcher ignores them); a fixed serial
    and the requested ttl are used, with the standard zone rank for a static
    record.
    """
    dnsp = load_dnsp()
    rec = dnsp.DnssrvRpcRecord()
    rec.wType = _type_const(dnsp, spec["type"])
    rec.rank = dnsp.DNS_RANK_ZONE
    rec.dwSerial = 1
    rec.dwTtlSeconds = spec["ttl"]
    rtype = spec["type"]
    if rtype in _NAME_DATA_TYPES:
        rec.data = spec["value"]
    elif rtype == "MX":
        mx = dnsp.mx()
        mx.nameTarget = spec["value"]
        mx.wPriority = spec["preference"]
        rec.data = mx
    elif rtype == "SRV":
        srv = dnsp.srv()
        srv.nameTarget = spec["value"]
        srv.wPort = spec["port"]
        srv.wPriority = spec["priority"]
        srv.wWeight = spec["weight"]
        rec.data = srv
    elif rtype == "TXT":
        strings = dnsp.string_list()
        strings.count = 1
        strings.str = [spec["value"]]
        rec.data = strings
    return rec


def record_to_spec(rec):
    """Return the spec dict for a stored record, or ``None`` if it is unmanaged.

    Tombstone, SOA and any non-managed record types map to ``None`` so they are
    ignored by matching and preserved untouched by writes.
    """
    dnsp = load_dnsp()
    name = _type_name(dnsp, rec.wType)
    if name is None:
        return None
    spec = {"type": name, "ttl": rec.dwTtlSeconds}
    if name in _NAME_DATA_TYPES:
        spec["value"] = str(rec.data)
    elif name == "MX":
        spec["value"] = str(rec.data.nameTarget)
        spec["preference"] = rec.data.wPriority
    elif name == "SRV":
        spec["value"] = str(rec.data.nameTarget)
        spec["priority"] = rec.data.wPriority
        spec["weight"] = rec.data.wWeight
        spec["port"] = rec.data.wPort
    elif name == "TXT":
        spec["value"] = _TXT_SEP.join(str(s) for s in rec.data.str)
    return spec
