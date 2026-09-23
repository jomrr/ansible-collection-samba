# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for the ``samba_dns_zone`` module.

Imports nothing from ``samba``. It validates the zone name and aging options,
decides the create/delete/option action, and orchestrates the work through an
injected ``io`` object (zone state via the local LDB, writes via the dnsserver
RPC). Keeping this layer binding-free lets the unit tests run without the samba
bindings.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, NamedTuple, Protocol

#: The replication scope (directory partition) the zone is created in.
REPLICATION_CHOICES = ["domain", "forest"]

#: A DNS zone name: dot-separated labels (forward like ``example.com`` or reverse
#: like ``2.0.192.in-addr.arpa``), total length within the DNS limit.
_ZONE_NAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]+\.)*[A-Za-z0-9_-]+$")


class ZoneOption(NamedTuple):
    """One zone aging option under its three names."""

    #: The module parameter and returned field.
    param: str
    #: The property ``ResetDwordProperty`` sets (``samba-tool dns zoneoptions``).
    rpc_property: str
    #: The ``samba.dcerpc.dnsp`` id the zone's ``dNSProperty`` stores it under.
    dnsp_property: str


#: The aging options, in write order: the intervals come before ``Aging``, so
#: aging never starts with the intervals the zone had before.
ZONE_OPTIONS = (
    ZoneOption("norefresh_interval", "NoRefreshInterval", "DSPROPERTY_ZONE_NOREFRESH_INTERVAL"),
    ZoneOption("refresh_interval", "RefreshInterval", "DSPROPERTY_ZONE_REFRESH_INTERVAL"),
    ZoneOption("aging", "Aging", "DSPROPERTY_ZONE_AGING_STATE"),
)

#: The interval bound ``samba-tool dns zoneoptions`` enforces: ten years, in
#: hours. 0 selects the DC's default interval.
MAX_INTERVAL_HOURS = 10 * 365 * 24


class SambaDnsZoneError(Exception):
    """User-facing error the module turns into ``fail_json``."""


class ZoneIO(Protocol):
    """The zone I/O ``run`` works through: LDB reads, dnsserver RPC writes."""

    def read_options(self, name: str) -> dict[str, int] | None:
        """Return the stored aging properties by parameter, or None if the zone is absent."""

    def create(self, name: str, replication: str) -> bool:
        """Create the zone; return False if it already existed."""

    def delete(self, name: str) -> bool:
        """Delete the zone; return False if it was already gone."""

    def set_properties(self, name: str, writes: list[tuple[str, int]]) -> None:
        """Write the ``(rpc_property, value)`` pairs to the zone, in order."""


def validate(params: Mapping[str, Any]) -> str:
    """Validate the zone name and return it normalized (lowercased, as samba stores it)."""
    name = params["name"]
    if not name or not _ZONE_NAME_RE.match(name):
        raise SambaDnsZoneError(f"'{name}' is not a valid DNS zone name")
    return name.lower()


def requested_options(params: Mapping[str, Any]) -> dict[str, bool | int]:
    """Return the aging options the task sets; an option left unset is not managed.

    The intervals accept the range ``samba-tool dns zoneoptions`` accepts. The
    options describe an existing zone, so they require ``state=present``.
    """
    requested = {option.param: params[option.param] for option in ZONE_OPTIONS if params[option.param] is not None}
    for param, value in requested.items():
        if not isinstance(value, bool) and not 0 <= value <= MAX_INTERVAL_HOURS:
            raise SambaDnsZoneError(f"{param} must be between 0 and {MAX_INTERVAL_HOURS} hours")
    if requested and params["state"] == "absent":
        raise SambaDnsZoneError(f"{', '.join(requested)} can only be set with state=present")
    return requested


def zone_options(stored: Mapping[str, int]) -> dict[str, bool | int]:
    """Return the public aging options of a zone from its stored properties.

    A property the zone does not store counts as 0, as the DNS server reads it:
    aging off, intervals at the DC's default.
    """
    options: dict[str, bool | int] = {option.param: stored.get(option.param, 0) for option in ZONE_OPTIONS}
    options["aging"] = bool(options["aging"])
    return options


def option_changes(current: Mapping[str, bool | int] | None, requested: Mapping[str, bool | int]) -> dict[str, bool | int]:
    """Return the requested options that differ from ``current``; all of them for a zone yet to be created."""
    if current is None:
        return dict(requested)
    return {param: value for param, value in requested.items() if current[param] != value}


def property_writes(changes: Mapping[str, bool | int]) -> list[tuple[str, int]]:
    """Return the ``(rpc_property, value)`` writes for ``changes``, in write order."""
    return [(option.rpc_property, int(changes[option.param])) for option in ZONE_OPTIONS if option.param in changes]


def public_state(name: str, replication: str, options: Mapping[str, bool | int | None] | None) -> dict[str, Any]:
    """Return the externally reported zone state; ``options`` is None for an absent zone."""
    if options is None:
        return {"name": name, "state": "absent"}
    return {"name": name, "state": "present", "replication": replication, **options}


#: Reverse-lookup zone suffixes (a zone under these is a reverse zone).
_REVERSE_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")


def is_reverse(name: str) -> bool:
    """True if ``name`` is a reverse-lookup zone (under in-addr.arpa/ip6.arpa)."""
    lowered = name.lower()
    return any(lowered.endswith(suffix) for suffix in _REVERSE_SUFFIXES)


def decode_replication(zone_dn: str) -> str:
    """Derive the replication scope from the zone's directory partition.

    Read mirror of ``create_zone``'s partition selection: a zone held in the
    ForestDnsZones application partition is forest-replicated; every other
    location (the DomainDnsZones partition, or the legacy domain location) is
    domain-replicated.
    """
    return "forest" if "forestdnszones" in zone_dn.lower() else "domain"


def zone_info(name: str, zone_dn: object, stored: Mapping[str, int]) -> dict[str, Any]:
    """Return the read-only public state for one observed zone.

    ``replication`` (from the partition), the aging options (from the stored
    properties) and ``reverse`` (from the name) are derived so the fields line up
    with what ``samba_dns_zone`` accepts as input - the read mirror of that
    module's write parameters.
    """
    return {
        "name": name,
        "replication": decode_replication(str(zone_dn)),
        **zone_options(stored),
        "reverse": is_reverse(name),
        "dn": str(zone_dn),
    }


def build_diff(name: str, before: Mapping[str, Any] | None, after: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Build a before/after diff of the zone's existence and aging options."""
    return {
        "before": {} if before is None else {"name": name, **before},
        "after": {} if after is None else {"name": name, **after},
    }


def _read(io: ZoneIO, name: str) -> dict[str, bool | int] | None:
    """Return the zone's public aging options, or None if the zone is absent."""
    stored = io.read_options(name)
    return None if stored is None else zone_options(stored)


def run(params: Mapping[str, Any], check_mode: bool, io: ZoneIO) -> dict[str, Any]:
    """Orchestrate validate -> read -> (check-mode?) -> create/delete/options -> report.

    ``io.read_options`` reads the zone from the local LDB; ``create``, ``delete``
    and ``set_properties`` go through the RPC. ``create``/``delete`` return
    whether they actually changed anything, so a zone created or removed
    concurrently is reconciled as an honest no-op.

    ``present`` ensures the zone exists with the requested aging options; an
    option left unset is not managed. A zone's replication scope is fixed at
    creation and is not reconciled for an already-existing zone. In check mode
    the options of a zone that would be created are unknown unless requested.
    """
    name = validate(params)
    requested = requested_options(params)
    replication = params["replication"]
    before = _read(io, name)

    if params["state"] == "absent":
        changed = before is not None
        if changed and not check_mode:
            changed = io.delete(name)
        return {
            "changed": changed,
            "zone": public_state(name, replication, None),
            "diff": build_diff(name, before, None),
        }

    current = before
    created = before is None
    if created and not check_mode:
        created = io.create(name, replication)
        current = _read(io, name)
        if current is None:
            raise SambaDnsZoneError(f"zone '{name}' could not be read back after creation")

    changes = option_changes(current, requested)
    if changes and not check_mode:
        io.set_properties(name, property_writes(changes))

    unknown: dict[str, bool | int | None] = dict.fromkeys(option.param for option in ZONE_OPTIONS)
    after = {**(unknown if current is None else current), **requested}
    return {
        "changed": created or bool(changes),
        "zone": public_state(name, replication, after),
        "diff": build_diff(name, before, after),
    }
