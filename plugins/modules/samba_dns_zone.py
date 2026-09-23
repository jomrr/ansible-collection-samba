# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to manage DNS zones in a Samba AD DC."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_dns_zone
short_description: Manage DNS zones in a Samba AD DC
version_added: 0.1.0
extends_documentation_fragment:
  - jomrr.samba.connection
description:
  - Create and remove AD-integrated DNS zones (forward and reverse) in a Samba
    Active Directory Domain Controller's internal DNS.
  - Mirrors C(samba-tool dns zonecreate); zones are primary, directory-integrated
    zones with secure dynamic updates enabled. Whether a zone is forward or
    reverse is determined by its O(name) (a reverse zone is named under
    C(in-addr.arpa) or C(ip6.arpa)).
  - Sets the zone's record aging like C(samba-tool dns zoneoptions).
  - Zone existence and aging options (C(dNSProperty)) are read through
    C(samba.samdb.SamDB) over LDAP; create, delete and option writes go through
    the C(dnsserver) RPC, authenticated and sealed with the same caller
    credentials.
  - The module is idempotent and supports check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - The C(samba) Python bindings (C(python3-samba)) on the host that runs the
    module, with the DC's C(dnsserver) RPC reachable from it.
options:
  aging:
    description:
      - Enable record aging (C(samba-tool dns zoneoptions --aging)).
      - A dynamic record not refreshed within O(norefresh_interval) plus
        O(refresh_interval) becomes eligible for scavenging.
      - Not managed if omitted. Requires O(state=present).
    type: bool
    version_added: 2.1.0
  name:
    description:
      - The zone name, for example C(example.com) for a forward zone or
        C(2.0.192.in-addr.arpa) for a reverse zone.
    type: str
    required: true
  norefresh_interval:
    description:
      - No-refresh interval in hours (C(--norefreshinterval)); within it an
        update does not refresh a record's time stamp.
      - C(0) to C(87600); C(0) selects the DC's default.
      - Not managed if omitted. Requires O(state=present).
    type: int
    version_added: 2.1.0
  refresh_interval:
    description:
      - Refresh interval in hours (C(--refreshinterval)), following the
        no-refresh interval.
      - C(0) to C(87600); C(0) selects the DC's default.
      - Not managed if omitted. Requires O(state=present).
    type: int
    version_added: 2.1.0
  replication:
    description:
      - The replication scope of the zone, selected by the directory partition it
        is created in C(domain) for domain-wide or C(forest) for forest-wide
        replication.
      - This is applied only when the zone is created. It is fixed at creation;
        for an existing zone the module ensures existence only and does not change
        the replication scope.
    type: str
    default: domain
    choices:
      - domain
      - forest
  state:
    description:
      - Whether the zone should exist (C(present)) or not (C(absent)).
      - C(absent) deletes the zone B(and every record it contains); there is no
        emptiness check. If the zone does not exist it is a no-op.
    type: str
    default: present
    choices:
      - present
      - absent
seealso:
  - module: jomrr.samba.samba_dns_zone_info
    description: Query DNS zones from a Samba AD DC.
  - module: jomrr.samba.samba_dns_record
    description: Manage the records inside a DNS zone.
notes:
  - The DC is reached over the network (LDAP and the C(dnsserver) RPC), so the
    module does not have to run on a domain controller. Any host with the
    C(samba) bindings that can reach O(server) and obtain a Kerberos ticket for
    its realm will do; running on the DC itself, with O(server) pointing at it,
    is the simplest topology.
  - Only primary, AD-integrated zones are managed (the set C(samba-tool dns
    zonecreate) supports).
  - The DC removes aged records only with C(dns zone scavenging = yes) in its
    C(smb.conf); this module does not manage C(smb.conf).
  - Do not enable scavenging on a domain created before Samba 4.9; its static
    records may be marked dynamic and would be removed.
  - The intervals are written before O(aging). A property the zone does not
    store counts as C(0).
  - Records created by C(jomrr.samba.samba_dns_record) are static and never
    scavenged.
"""

EXAMPLES = r"""
- name: Ensure a forward zone exists
  jomrr.samba.samba_dns_zone:
    name: example.com
    state: present

- name: Ensure a reverse zone for 192.0.2.0/24 exists
  jomrr.samba.samba_dns_zone:
    name: 2.0.192.in-addr.arpa
    state: present

- name: Ensure a forest-wide replicated zone exists
  jomrr.samba.samba_dns_zone:
    name: forest.example.com
    replication: forest
    state: present

- name: Enable record aging with one-week intervals
  jomrr.samba.samba_dns_zone:
    name: example.com
    aging: true
    norefresh_interval: 168
    refresh_interval: 168
    state: present

- name: Remove a zone (and all its records)
  jomrr.samba.samba_dns_zone:
    name: old.example.com
    state: absent
"""

RETURN = r"""
zone:
  description: The resulting zone state.
  returned: success
  type: dict
  contains:
    name:
      description: The zone name.
      returned: always
      type: str
      sample: example.com
    state:
      description: Whether the zone exists after the run.
      returned: always
      type: str
      sample: present
    replication:
      description: The requested replication scope.
      returned: when the zone is present
      type: str
      sample: domain
    aging:
      description:
        - Whether record aging is enabled.
        - C(null) in check mode if the zone would be created and O(aging) is
          not set.
      returned: when the zone is present
      type: bool
      sample: true
      version_added: 2.1.0
    norefresh_interval:
      description:
        - The no-refresh interval in hours; C(0) is the DC's default.
        - C(null) in check mode if the zone would be created and
          O(norefresh_interval) is not set.
      returned: when the zone is present
      type: int
      sample: 168
      version_added: 2.1.0
    refresh_interval:
      description:
        - The refresh interval in hours; C(0) is the DC's default.
        - C(null) in check mode if the zone would be created and
          O(refresh_interval) is not set.
      returned: when the zone is present
      type: int
      sample: 168
      version_added: 2.1.0
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_conn, samba_dns_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_zone_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb, connection_argument_spec, run_or_fail


class SambaDnsZoneIO:
    """Zone I/O: state via local LDB; create, delete and options via the dnsserver RPC.

    The RPC connection (caller credentials) is opened lazily, only when a write
    is actually performed - check-mode and idempotent runs touch the LDB only.
    All samba access goes through the shared lazy-import helpers.
    """

    def __init__(self, module, samdb):
        self.module = module
        self.samdb = samdb
        self._conn = None
        self._server = None

    def _rpc(self):
        if self._conn is None:
            self._conn, self._server = samba_dns_conn.connect_dnsserver(self.module)
        return self._conn

    def read_options(self, name: str) -> dict[str, int] | None:
        """Return the zone's stored aging properties, or None if it does not exist."""
        entries = samba_dns_io.list_zone_entries(self.samdb, name)
        return entries[0][2] if entries else None

    def create(self, name, replication):
        """Create the zone; return False if it already existed (race)."""
        return samba_dns_conn.create_zone(self._rpc(), self._server, name, replication)

    def delete(self, name):
        """Delete the zone; return False if it was already gone (race)."""
        return samba_dns_conn.delete_zone(self._rpc(), self._server, name)

    def set_properties(self, name: str, writes: list[tuple[str, int]]) -> None:
        """Write the zone properties in the given order."""
        conn = self._rpc()
        for property_name, value in writes:
            samba_dns_conn.set_zone_property(conn, self._server, name, property_name, value)


def main():
    """Module entry point."""
    argument_spec = {
        "name": {"type": "str", "required": True},
        "aging": {"type": "bool"},
        "norefresh_interval": {"type": "int"},
        "refresh_interval": {"type": "int"},
        "replication": {"type": "str", "default": "domain", "choices": logic.REPLICATION_CHOICES},
        "state": {"type": "str", "default": "present", "choices": ["present", "absent"]},
    }
    argument_spec.update(connection_argument_spec())
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)
    zone_io = SambaDnsZoneIO(module, samdb)

    result = run_or_fail(module, "samba_dns_zone", (logic.SambaDnsZoneError,), lambda: logic.run(module.params, module.check_mode, zone_io))

    module.exit_json(**result)


if __name__ == "__main__":
    main()
