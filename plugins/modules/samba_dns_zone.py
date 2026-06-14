#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to manage DNS zones in a Samba AD DC."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_dns_zone
short_description: Manage DNS zones in a Samba AD DC
version_added: 0.1.0
description:
  - Create and remove AD-integrated DNS zones (forward and reverse) in a Samba
    Active Directory Domain Controller's internal DNS.
  - Mirrors C(samba-tool dns zonecreate); zones are primary, directory-integrated
    zones with secure dynamic updates enabled. Whether a zone is forward or
    reverse is determined by its O(name) (a reverse zone is named under
    C(in-addr.arpa) or C(ip6.arpa)).
  - Zone existence is read through the local C(samba.samdb.SamDB); create and
    delete go through the C(dnsserver) RPC, authenticated with the host's machine
    account (no credentials are taken as parameters).
  - The module is idempotent and supports check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run on a Samba AD DC host with the C(samba) Python bindings installed
    and the DNS RPC server reachable.
options:
  name:
    description:
      - The zone name, for example C(example.com) for a forward zone or
        C(2.0.192.in-addr.arpa) for a reverse zone.
    type: str
    required: true
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
notes:
  - This module must be executed on a Samba AD DC where the C(samba) Python
    bindings, the directory and the DNS RPC server are available.
  - Only primary, AD-integrated zones are managed (the set C(samba-tool dns
    zonecreate) supports).
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
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_conn
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_zone_logic as logic


class SambaDnsZoneIO:
    """Zone I/O: existence via local LDB, create/delete via the dnsserver RPC.

    The RPC connection (machine account) is opened lazily, only when a write is
    actually performed - check-mode and idempotent runs touch the LDB only. All
    samba access goes through the shared lazy-import helpers.
    """

    def __init__(self, module, samdb):
        self.module = module
        self.samdb = samdb
        self._conn = None
        self._server = None

    def _rpc(self):
        if self._conn is None:
            self._conn, self._server = samba_dns_conn.connect_dnsserver(self.module, self.samdb)
        return self._conn

    def zone_exists(self, name):
        """True if the zone exists (read from the local directory)."""
        return samba_dns_io.find_zone_dn(self.samdb, name) is not None

    def create(self, name, replication):
        """Create the zone; return False if it already existed (race)."""
        return samba_dns_conn.create_zone(self._rpc(), self._server, name, replication)

    def delete(self, name):
        """Delete the zone; return False if it was already gone (race)."""
        return samba_dns_conn.delete_zone(self._rpc(), self._server, name)


def main():
    """Module entry point."""
    argument_spec = dict(
        name=dict(type="str", required=True),
        replication=dict(type="str", default="domain", choices=logic.REPLICATION_CHOICES),
        state=dict(type="str", default="present", choices=["present", "absent"]),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)
    zone_io = SambaDnsZoneIO(module, samdb)

    try:
        result = logic.run(module.params, module.check_mode, zone_io)
    except logic.SambaDnsZoneError as exc:
        module.fail_json(msg=to_native(exc))
    except Exception as exc:
        module.fail_json(
            msg="samba_dns_zone failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
