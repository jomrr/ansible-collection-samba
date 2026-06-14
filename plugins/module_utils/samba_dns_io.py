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

from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io

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


def find_zone_dn(samdb, zone):
    """Return the DNS zone's DN, searched across the DNS partitions, or None.

    The zone name is escaped via ``ldb.binary_encode`` before it enters the
    search filter. The phantom-root control reaches the separate DNS application
    partitions (DomainDnsZones/ForestDnsZones).
    """
    ldb = samba_user_io.load_ldb()
    res = samdb.search(
        base="",
        scope=ldb.SCOPE_SUBTREE,
        expression="(&(objectClass=dnsZone)(name=%s))" % ldb.binary_encode(zone),
        attrs=["name"],
        controls=["search_options:0:2"],
    )
    return res[0].dn if len(res) > 0 else None


def read_node_specs(samdb, node_dn):
    """Return the managed record specs at ``node_dn``, or None if it is absent."""
    ldb = samba_user_io.load_ldb()
    try:
        res = samdb.search(base=node_dn, scope=ldb.SCOPE_BASE, attrs=["dnsRecord"])
    except ldb.LdbError as err:
        if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return None
        raise
    if len(res) == 0:
        return None
    return _specs_from_element(res[0].get("dnsRecord"))


def read_name_specs(samdb, zone_dn, name):
    """Return the managed record specs for ``name`` in a zone, or None if absent.

    The ``name`` is placed via ``ldb.Dn.set_component`` (in build_child_dn), so DN
    metacharacters cannot inject extra components.
    """
    node_dn = samba_user_io.build_child_dn(samdb, "DC", name, zone_dn)
    return read_node_specs(samdb, node_dn)


def enumerate_zone_specs(samdb, zone_dn):
    """Return ``(name, spec)`` for every managed record in the zone.

    ``name`` is the record's name relative to the zone (``@`` for the apex,
    dotted for nested nodes like ``_ldap._tcp``).
    """
    ldb = samba_user_io.load_ldb()
    res = samdb.search(
        base=zone_dn,
        scope=ldb.SCOPE_SUBTREE,
        expression="(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))",
        attrs=["dnsRecord"],
    )
    pairs = []
    for message in res:
        name = _relative_name(samdb, message.dn, zone_dn)
        for spec in _specs_from_element(message.get("dnsRecord")):
            pairs.append((name, spec))
    return pairs


def _specs_from_element(element):
    """Decode a dnsRecord message element into a list of managed record specs."""
    if element is None:
        return []
    ndr = load_ndr()
    dnsp = load_dnsp()
    specs = []
    for value in element:
        spec = record_to_spec(ndr.ndr_unpack(dnsp.DnssrvRpcRecord, value))
        if spec is not None:
            specs.append(spec)
    return specs


def _relative_name(samdb, node_dn, zone_dn):
    """Return a dnsNode's DNS name relative to its zone (deepest label first)."""
    ldb = samba_user_io.load_ldb()
    relative = ldb.Dn(samdb, str(node_dn))
    relative.remove_base_components(len(zone_dn))
    labels = []
    for index in range(len(relative)):
        value = relative.get_component_value(index)
        labels.append(value.decode() if isinstance(value, bytes) else value)
    return ".".join(labels)
