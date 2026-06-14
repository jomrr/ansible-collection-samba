#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to query DNS zones from a Samba AD DC."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_dns_zone_info
short_description: Query DNS zones from a Samba AD DC
version_added: 0.1.0
extends_documentation_fragment:
  - jomrr.samba.connection
description:
  - Read AD-integrated DNS zones (forward and reverse) from a Samba Active
    Directory Domain Controller's internal DNS.
  - Talks to the directory through the native C(samba) Python bindings
    (C(samba.samdb.SamDB)) over LDAP, not through C(samba-tool) subprocesses and
    not through the C(dnsserver) RPC (that is only the write path of
    M(jomrr.samba.samba_dns_zone)).
  - This module is read-only; it never changes the directory and always reports
    C(changed=false).
  - The returned zone fields mirror the parameters of
    M(jomrr.samba.samba_dns_zone) (C(name), C(replication)), so a returned entry
    can be fed back as that module's input.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run on a Samba AD DC host with the C(samba) Python bindings installed.
options:
  name:
    description:
      - Restrict the query to the zone with this name, for example
        C(example.com) or C(2.0.192.in-addr.arpa).
      - If omitted, all DNS zones are returned.
    type: str
notes:
  - This module must be executed on a Samba AD DC where the C(samba) Python
    bindings and the directory are available.
  - The replication scope is derived from the directory partition the zone lives
    in (ForestDnsZones means C(forest), otherwise C(domain)).
"""

EXAMPLES = r"""
- name: Look up a single forward zone
  jomrr.samba.samba_dns_zone_info:
    name: example.com
  register: example_zone

- name: Look up a reverse zone
  jomrr.samba.samba_dns_zone_info:
    name: 2.0.192.in-addr.arpa
  register: reverse_zone

- name: Fetch all DNS zones
  jomrr.samba.samba_dns_zone_info:
  register: all_zones

- name: Show the names and replication scope of every zone
  ansible.builtin.debug:
    msg: "{{ all_zones.zones | map('dict2items') | list }}"
"""

RETURN = r"""
zones:
  description:
    - The matching DNS zones. Empty when none matched.
  returned: success
  type: list
  elements: dict
  contains:
    name:
      description: The zone name.
      returned: always
      type: str
      sample: example.com
    replication:
      description:
        - The replication scope, derived from the directory partition the zone
          lives in (C(forest) for ForestDnsZones, otherwise C(domain)).
      returned: always
      type: str
      sample: domain
    reverse:
      description:
        - Whether the zone is a reverse-lookup zone (named under C(in-addr.arpa)
          or C(ip6.arpa)), derived from the name.
      returned: always
      type: bool
      sample: false
    dn:
      description: The distinguished name of the zone object.
      returned: always
      type: str
      sample: DC=example.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=com
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb, connection_argument_spec
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_zone_logic as logic


def query(samdb, name):
    """Return the public zone states; all zones when ``name`` is None.

    Reuses the shared local-SamDB zone enumeration (the same partition search the
    write module's existence check uses) and the shared scope decode, so the
    output is the read mirror of the write semantics. A name that matches no zone
    yields an empty list - non-existence is not an error when querying. The name
    is escaped before it enters the search filter by the shared helper.
    """
    entries = samba_dns_io.list_zone_entries(samdb, name)
    return [logic.zone_info(zone_name, zone_dn) for zone_name, zone_dn in entries]


def main():
    """Module entry point."""
    argument_spec = dict(
        name=dict(type="str"),
    )
    argument_spec.update(connection_argument_spec())
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)

    try:
        zones = query(samdb, module.params["name"])
    except Exception as exc:
        module.fail_json(
            msg="samba_dns_zone_info failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(changed=False, zones=zones)


if __name__ == "__main__":
    main()
