# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for the ``samba_dns_zone`` module.

Imports nothing from ``samba``. It validates the zone name, decides the
create/delete action, and orchestrates the work through an injected ``io`` object
(existence via the local LDB, create/delete via the dnsserver RPC). Keeping this
layer binding-free lets the unit tests run without the samba bindings.
"""

from __future__ import annotations

import re

#: The replication scope (directory partition) the zone is created in.
REPLICATION_CHOICES = ["domain", "forest"]

#: A DNS zone name: dot-separated labels (forward like ``example.com`` or reverse
#: like ``2.0.192.in-addr.arpa``), total length within the DNS limit.
_ZONE_NAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]+\.)*[A-Za-z0-9_-]+$")


class SambaDnsZoneError(Exception):
    """User-facing error the module turns into ``fail_json``."""


def validate(params):
    """Validate the zone name and return it normalized (lowercased, as samba stores it)."""
    name = params["name"]
    if not name or not _ZONE_NAME_RE.match(name):
        raise SambaDnsZoneError("'%s' is not a valid DNS zone name" % name)
    return name.lower()


def public_state(name, replication, present):
    """Return the externally reported zone state."""
    if not present:
        return {"name": name, "state": "absent"}
    return {"name": name, "state": "present", "replication": replication}


#: Reverse-lookup zone suffixes (a zone under these is a reverse zone).
_REVERSE_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")


def is_reverse(name):
    """True if ``name`` is a reverse-lookup zone (under in-addr.arpa/ip6.arpa)."""
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in _REVERSE_SUFFIXES)


def decode_replication(zone_dn):
    """Derive the replication scope from the zone's directory partition.

    Read mirror of ``create_zone``'s partition selection: a zone held in the
    ForestDnsZones application partition is forest-replicated; every other
    location (the DomainDnsZones partition, or the legacy domain location) is
    domain-replicated.
    """
    return "forest" if "forestdnszones" in zone_dn.lower() else "domain"


def zone_info(name, zone_dn):
    """Return the read-only public state for one observed zone.

    ``replication`` (from the partition) and ``reverse`` (from the name) are
    derived so the fields line up with what ``samba_dns_zone`` accepts as input -
    the read mirror of that module's write parameters.
    """
    return {
        "name": name,
        "replication": decode_replication(str(zone_dn)),
        "reverse": is_reverse(name),
        "dn": str(zone_dn),
    }


def build_diff(name, before_present, after_present):
    """Build a before/after diff of the zone's existence."""
    return {
        "before": {"name": name} if before_present else {},
        "after": {"name": name} if after_present else {},
    }


def run(params, check_mode, io):
    """Orchestrate validate -> exists? -> (check-mode?) -> create/delete -> report.

    ``io`` provides ``zone_exists`` (local LDB), ``create`` and ``delete`` (RPC).
    ``create``/``delete`` return whether they actually changed anything, so a zone
    created or removed concurrently is reconciled as an honest no-op.

    ``present`` only ensures the zone exists; a zone's replication scope is fixed
    at creation and is not reconciled for an already-existing zone.
    """
    name = validate(params)
    state = params["state"]
    replication = params["replication"]

    exists = io.zone_exists(name)

    if state == "present":
        changed = not exists
        if changed and not check_mode:
            changed = io.create(name, replication)
    else:
        changed = exists
        if changed and not check_mode:
            changed = io.delete(name)

    after_present = (state == "present")
    return {
        "changed": changed,
        "zone": public_state(name, replication, after_present),
        "diff": build_diff(name, exists, after_present),
    }
