#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to manage DNS records in a Samba AD DC."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_dns_record
short_description: Manage DNS records in a Samba AD DC
version_added: 0.1.0
description:
  - Create and remove DNS records (A, AAAA, CNAME, PTR, MX, TXT, SRV, NS) in a
    Samba Active Directory Domain Controller's internal DNS.
  - Talks to the directory through the native C(samba) Python bindings (the
    local C(samba.samdb.SamDB) DNS API), not through C(samba-tool) subprocesses.
  - A record is identified by its zone, name, type and value (including the
    full structure for MX and SRV). Only that single record is managed; other
    records of the same name and type but a different value are left untouched.
  - The module is idempotent and supports check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run on a Samba AD DC host with the C(samba) Python bindings installed.
options:
  zone:
    description:
      - The DNS zone the record lives in, for example C(example.com).
      - The zone must already exist; this module does not create zones.
    type: str
    required: true
  name:
    description:
      - The record name relative to the zone, for example C(www).
      - Use C(@) for the zone apex.
    type: str
    required: true
  type:
    description:
      - The DNS record type.
    type: str
    required: true
    choices: [A, AAAA, CNAME, PTR, MX, NS, SRV, TXT]
  value:
    description:
      - The record value; its meaning depends on O(type).
      - For V(A) an IPv4 address, for V(AAAA) an IPv6 address.
      - For V(CNAME), V(PTR) and V(NS) the target name.
      - For V(MX) and V(SRV) the target host (combined with the structure
        options below).
      - For V(TXT) the text string (a single string is managed).
    type: str
    required: true
  preference:
    description:
      - The preference (priority) of an V(MX) record. Required for V(MX).
    type: int
  priority:
    description:
      - The priority of an V(SRV) record. Required for V(SRV).
    type: int
  weight:
    description:
      - The weight of an V(SRV) record. Required for V(SRV).
    type: int
  port:
    description:
      - The port of an V(SRV) record. Required for V(SRV).
    type: int
  ttl:
    description:
      - The time-to-live of the record, in seconds.
    type: int
    default: 900
  state:
    description:
      - Whether the record should exist (C(present)) or not (C(absent)).
    type: str
    default: present
    choices: [present, absent]
notes:
  - This module must be executed on a Samba AD DC where the C(samba) Python
    bindings and the directory are available.
  - The zone must already exist; managing zones is out of scope for this module.
"""

EXAMPLES = r"""
- name: Ensure an A record exists
  jomrr.samba.samba_dns_record:
    zone: example.com
    name: www
    type: A
    value: 192.0.2.10
    state: present

- name: Ensure an AAAA record exists
  jomrr.samba.samba_dns_record:
    zone: example.com
    name: www
    type: AAAA
    value: 2001:db8::10
    state: present

- name: Ensure a CNAME record exists
  jomrr.samba.samba_dns_record:
    zone: example.com
    name: ftp
    type: CNAME
    value: www.example.com

- name: Ensure an MX record exists
  jomrr.samba.samba_dns_record:
    zone: example.com
    name: "@"
    type: MX
    value: mail.example.com
    preference: 10

- name: Ensure an SRV record exists
  jomrr.samba.samba_dns_record:
    zone: example.com
    name: _ldap._tcp
    type: SRV
    value: dc1.example.com
    priority: 0
    weight: 100
    port: 389

- name: Ensure a TXT record exists
  jomrr.samba.samba_dns_record:
    zone: example.com
    name: "@"
    type: TXT
    value: "v=spf1 -all"

- name: Remove an A record
  jomrr.samba.samba_dns_record:
    zone: example.com
    name: old
    type: A
    value: 192.0.2.99
    state: absent
"""

RETURN = r"""
record:
  description: The managed record's resulting state.
  returned: success
  type: dict
  contains:
    zone:
      description: The DNS zone.
      returned: always
      type: str
      sample: example.com
    name:
      description: The record name relative to the zone.
      returned: always
      type: str
      sample: www
    type:
      description: The record type.
      returned: always
      type: str
      sample: A
    value:
      description: The record value.
      returned: always
      type: str
      sample: 192.0.2.10
    state:
      description: Whether the record exists after the run.
      returned: always
      type: str
      sample: present
    preference:
      description: The MX preference (MX records only).
      returned: for MX records
      type: int
      sample: 10
    priority:
      description: The SRV priority (SRV records only).
      returned: for SRV records
      type: int
      sample: 0
    weight:
      description: The SRV weight (SRV records only).
      returned: for SRV records
      type: int
      sample: 100
    port:
      description: The SRV port (SRV records only).
      returned: for SRV records
      type: int
      sample: 389
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_record_logic as logic


class SambaDnsRecordIO:
    """Local-SamDB DNS record I/O.

    DNS records are the multi-valued ``dnsRecord`` attribute (NDR-packed
    ``dnsp.DnssrvRpcRecord``) on ``dnsNode`` objects under the zone. All reads and
    writes go through the local ``SamDB`` (system session) - no RPC, no
    credentials, no network - the same connection base as the other modules. The
    ``samba``/``ldb`` bindings are imported lazily via the shared module_utils
    helpers, so importing this module never requires them.
    """

    def __init__(self, samdb):
        self.samdb = samdb
        self._zone_dns = {}

    def _zone_dn(self, zone):
        """Return the zone's DN (cached), or None if the zone does not exist."""
        if zone not in self._zone_dns:
            self._zone_dns[zone] = samba_dns_io.find_zone_dn(self.samdb, zone)
        return self._zone_dns[zone]

    def _node_dn(self, zone, name):
        """Build the dnsNode DN ``DC=<name>,<zone_dn>`` with the name escaped."""
        return samba_user_io.build_child_dn(self.samdb, "DC", name, self._zone_dn(zone))

    def _read_raw(self, node_dn):
        """Return the raw dnsRecord values of a node, or None if it is absent."""
        ldb = samba_user_io.load_ldb()
        try:
            res = self.samdb.search(base=node_dn, scope=ldb.SCOPE_BASE, attrs=["dnsRecord"])
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                return None
            raise
        if len(res) == 0:
            return None
        element = res[0].get("dnsRecord")
        return list(element) if element is not None else []

    def zone_exists(self, zone):
        """True if the DNS zone exists."""
        return self._zone_dn(zone) is not None

    def read(self, zone, name):
        """Return the managed record specs at ``name``, or None if name is absent."""
        return samba_dns_io.read_node_specs(self.samdb, self._node_dn(zone, name))

    def _live_records(self, raw):
        """Unpack raw values into records, dropping tombstones."""
        ndr = samba_dns_io.load_ndr()
        dnsp = samba_dns_io.load_dnsp()
        records = []
        for value in raw:
            rec = ndr.ndr_unpack(dnsp.DnssrvRpcRecord, value)
            if rec.wType != dnsp.DNS_TYPE_TOMBSTONE:
                records.append(rec)
        return records

    def _create_node(self, node_dn, spec):
        """Create a new dnsNode holding the single desired record."""
        ldb = samba_user_io.load_ldb()
        ndr = samba_dns_io.load_ndr()
        message = ldb.Message(node_dn)
        message["objectClass"] = ldb.MessageElement(["top", "dnsNode"], ldb.FLAG_MOD_ADD, "objectClass")
        message["dnsRecord"] = ldb.MessageElement(
            [ndr.ndr_pack(samba_dns_io.build_record(spec))], ldb.FLAG_MOD_ADD, "dnsRecord"
        )
        self.samdb.add(message)

    def add(self, zone, name, spec):
        """Add the record, creating the node if needed. Returns False if present.

        An existing node is extended with a single ``dnsRecord`` value
        (FLAG_MOD_ADD), so other records on the name - including the SOA at the
        apex - are left untouched rather than rewritten.
        """
        ldb = samba_user_io.load_ldb()
        ndr = samba_dns_io.load_ndr()
        node_dn = self._node_dn(zone, name)
        raw = self._read_raw(node_dn)
        if raw is None:
            try:
                self._create_node(node_dn, spec)
                return True
            except ldb.LdbError as err:
                if err.args[0] != ldb.ERR_ENTRY_ALREADY_EXISTS:
                    raise
                # Created concurrently between the read and the add; fall through
                # to the modify path against the now-existing node.
                raw = self._read_raw(node_dn)
                if raw is None:
                    raise
        if any(self._matches(rec, spec) for rec in self._live_records(raw)):
            return False
        message = ldb.Message(node_dn)
        message["dnsRecord"] = ldb.MessageElement(
            [ndr.ndr_pack(samba_dns_io.build_record(spec))], ldb.FLAG_MOD_ADD, "dnsRecord"
        )
        try:
            self.samdb.modify(message)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_ATTRIBUTE_OR_VALUE_EXISTS:
                # Added concurrently with identical bytes; the desired state holds.
                return False
            raise
        return True

    def remove(self, zone, name, spec):
        """Remove the record. Returns False if it was already absent."""
        node_dn = self._node_dn(zone, name)
        raw = self._read_raw(node_dn)
        if raw is None:
            return False
        kept = []
        removed = False
        for rec in self._live_records(raw):
            if self._matches(rec, spec):
                removed = True
                continue
            kept.append(rec)
        if not removed:
            return False
        self.samdb.dns_replace_by_dn(node_dn, kept)
        return True

    @staticmethod
    def _matches(rec, spec):
        """True if a stored record matches the desired spec (same identity)."""
        rec_spec = samba_dns_io.record_to_spec(rec)
        return rec_spec is not None and logic.records_equal(rec_spec, spec)


def main():
    """Module entry point."""
    argument_spec = dict(
        zone=dict(type="str", required=True),
        name=dict(type="str", required=True),
        type=dict(type="str", required=True, choices=logic.TYPE_CHOICES),
        value=dict(type="str", required=True),
        preference=dict(type="int"),
        priority=dict(type="int"),
        weight=dict(type="int"),
        port=dict(type="int"),
        ttl=dict(type="int", default=900),
        state=dict(type="str", default="present", choices=["present", "absent"]),
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("type", "MX", ["preference"]),
            ("type", "SRV", ["priority", "weight", "port"]),
        ],
    )

    samdb = connect_samdb(module)
    record_io = SambaDnsRecordIO(samdb)

    try:
        result = logic.run(module.params, module.check_mode, record_io)
    except logic.SambaDnsRecordError as exc:
        module.fail_json(msg=to_native(exc))
    except Exception as exc:
        module.fail_json(
            msg="samba_dns_record failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
