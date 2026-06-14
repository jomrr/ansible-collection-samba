#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to query DNS records from a Samba AD DC."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_dns_record_info
short_description: Query DNS records from a Samba AD DC
version_added: 0.1.0
description:
  - Read DNS records (A, AAAA, CNAME, PTR, MX, TXT, SRV, NS) from a Samba Active
    Directory Domain Controller's internal DNS.
  - Talks to the directory through the native C(samba) Python bindings (the local
    C(samba.samdb.SamDB)), not through C(samba-tool) subprocesses.
  - This module is read-only; it never changes the directory and always reports
    C(changed=false).
  - The returned record fields mirror the parameters of M(jomrr.samba.samba_dns_record),
    so a returned entry can be fed back as that module's input.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run on a Samba AD DC host with the C(samba) Python bindings installed.
options:
  zone:
    description:
      - The DNS zone to read from, for example C(example.com).
      - The zone must exist.
    type: str
    required: true
  name:
    description:
      - Restrict the query to the records at this name (relative to the zone),
        for example C(www) or C(@) for the apex.
      - If omitted, all records in the zone are returned.
    type: str
  type:
    description:
      - Restrict the query to records of this type.
      - If omitted, records of all managed types are returned.
    type: str
    choices: [A, AAAA, CNAME, PTR, MX, NS, SRV, TXT]
notes:
  - This module must be executed on a Samba AD DC where the C(samba) Python
    bindings and the directory are available.
  - Values are returned in the DC's stored form (AAAA addresses are fully
    expanded, for instance).
"""

EXAMPLES = r"""
- name: Look up a single record
  jomrr.samba.samba_dns_record_info:
    zone: example.com
    name: www
    type: A
  register: www_a

- name: Fetch every record in a zone
  jomrr.samba.samba_dns_record_info:
    zone: example.com
  register: all_records

- name: Fetch all MX records in a zone
  jomrr.samba.samba_dns_record_info:
    zone: example.com
    type: MX
  register: mx_records

- name: Show the names and types of all records
  ansible.builtin.debug:
    msg: "{{ all_records.records | map('dict2items') | list }}"
"""

RETURN = r"""
records:
  description:
    - The matching DNS records. Empty when none matched.
  returned: success
  type: list
  elements: dict
  contains:
    zone:
      description: The DNS zone the record lives in.
      returned: always
      type: str
      sample: example.com
    name:
      description: The record name relative to the zone (C(@) for the apex).
      returned: always
      type: str
      sample: www
    type:
      description: The record type.
      returned: always
      type: str
      sample: A
    value:
      description:
        - The record value in the DC's stored form (IP for A/AAAA, target name
          for CNAME/PTR/NS and the MX/SRV target, text for TXT).
      returned: always
      type: str
      sample: 192.0.2.10
    ttl:
      description: The time-to-live of the record, in seconds.
      returned: always
      type: int
      sample: 900
    preference:
      description: The MX preference.
      returned: for MX records
      type: int
      sample: 10
    priority:
      description: The SRV priority.
      returned: for SRV records
      type: int
      sample: 0
    weight:
      description: The SRV weight.
      returned: for SRV records
      type: int
      sample: 100
    port:
      description: The SRV port.
      returned: for SRV records
      type: int
      sample: 389
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_record_logic as logic

#: The per-type structured fields a record spec may carry, mirroring the
#: samba_dns_record parameters.
_EXTRA_FIELDS = ("preference", "priority", "weight", "port")


def public_record(zone, name, spec):
    """Build the externally reported record from a decoded spec.

    Field names match M(jomrr.samba.samba_dns_record)'s parameters, so the result
    is the read mirror of that module's write input.
    """
    record = {
        "zone": zone,
        "name": name,
        "type": spec["type"],
        "value": spec["value"],
        "ttl": spec["ttl"],
    }
    for field in _EXTRA_FIELDS:
        if field in spec:
            record[field] = spec[field]
    return record


def query(samdb, zone, name, rtype):
    """Return the public records for a name (or the whole zone when name is None).

    Reuses the shared local-SamDB read helpers (the same decode the write module
    uses). The zone name and the record name are escaped by those helpers before
    they enter the search filter / the node DN.
    """
    zone_dn = samba_dns_io.find_zone_dn(samdb, zone)
    if zone_dn is None:
        raise logic.SambaDnsRecordError("zone '%s' does not exist" % zone)

    if name is not None:
        specs = samba_dns_io.read_name_specs(samdb, zone_dn, name) or []
        pairs = [(name, spec) for spec in specs]
    else:
        pairs = samba_dns_io.enumerate_zone_specs(samdb, zone_dn)

    records = [public_record(zone, entry_name, spec) for entry_name, spec in pairs]
    if rtype is not None:
        records = [record for record in records if record["type"] == rtype]
    return records


def main():
    """Module entry point."""
    argument_spec = dict(
        zone=dict(type="str", required=True),
        name=dict(type="str"),
        type=dict(type="str", choices=logic.TYPE_CHOICES),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)

    try:
        records = query(samdb, module.params["zone"], module.params["name"], module.params["type"])
    except logic.SambaDnsRecordError as exc:
        module.fail_json(msg=to_native(exc))
    except Exception as exc:
        module.fail_json(
            msg="samba_dns_record_info failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(changed=False, records=records)


if __name__ == "__main__":
    main()
