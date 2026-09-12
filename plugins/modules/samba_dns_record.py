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
extends_documentation_fragment:
  - jomrr.samba.connection
description:
  - Create and remove DNS records (A, AAAA, CNAME, PTR, MX, TXT, SRV, NS) in a
    Samba Active Directory Domain Controller's internal DNS.
  - Talks to the directory through the native C(samba) Python bindings
    (C(samba.samdb.SamDB) over LDAP), not through C(samba-tool) subprocesses.
  - A record is identified by its zone, name, type and value (including the
    full structure for MX and SRV). Only that single record is managed; other
    records of the same name and type but a different value are left untouched.
  - The TTL is not part of the identity. A matching record whose TTL differs
    from O(ttl) is updated in place.
  - Every change raises the zone's SOA serial, as C(samba-tool dns) does, so
    secondaries (zone transfers) and BIND9_DLZ notifications pick it up.
  - The module is idempotent and supports check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - The C(samba) Python bindings (C(python3-samba)) on the host that runs the
    module.
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
      - Reconciled on every run - an existing record with a different TTL is
        updated in place and reported as a change.
    type: int
    default: 900
  state:
    description:
      - Whether the record should exist (C(present)) or not (C(absent)).
    type: str
    default: present
    choices: [present, absent]
seealso:
  - module: jomrr.samba.samba_dns_record_info
    description: Query DNS records from a Samba AD DC.
  - module: jomrr.samba.samba_dns_zone
    description: Manage the DNS zone a record lives in.
notes:
  - The DC is reached over the network, so the module does not have to run on a
    domain controller. Any host with the C(samba) bindings that can reach
    O(server) over LDAP and obtain a Kerberos ticket for its realm will do;
    running on the DC itself, with O(server) pointing at it, is the simplest
    topology.
  - The zone must already exist; managing zones is out of scope for this module.
  - Removing the last record of a name leaves a tombstoned node behind, the
    same state C(samba-tool dns delete) produces; Samba's garbage collection
    removes it later.
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
    ttl:
      description: The time-to-live of the record, in seconds.
      returned: always
      type: int
      sample: 900
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

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb, connection_argument_spec
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_dns_record_logic as logic


class SambaDnsRecordIO:
    """DNS record I/O over the shared LDAP connection.

    DNS records are the multi-valued ``dnsRecord`` attribute (NDR-packed
    ``dnsp.DnssrvRpcRecord``) on ``dnsNode`` objects under the zone. All reads and
    writes go through the ``SamDB`` that ``connect_samdb`` opens (GSSAPI sign+seal
    LDAP with the caller's credentials) - no RPC - the same connection base as
    the other modules. The ``samba``/``ldb`` bindings are imported lazily via the
    shared module_utils helpers, so importing this module never requires them.
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

    def _read_node(self, node_dn):
        """Return ``(raw dnsRecord values, tombstoned)`` of a node, or None if absent.

        Unlike the read path this deliberately sees tombstoned nodes: ``add``
        has to revive one rather than create a node that already exists.
        """
        ldb = samba_user_io.load_ldb()
        try:
            res = self.samdb.search(base=node_dn, scope=ldb.SCOPE_BASE, attrs=["dnsRecord", "dNSTombstoned"])
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                return None
            raise
        if len(res) == 0:
            return None
        element = res[0].get("dnsRecord")
        raw = list(element) if element is not None else []
        tombstoned = (samba_user_io.first_value(res[0], "dNSTombstoned") or "").upper() == "TRUE"
        return raw, tombstoned

    def zone_exists(self, zone):
        """True if the DNS zone exists."""
        return self._zone_dn(zone) is not None

    def read(self, zone, name):
        """Return the managed record specs at ``name``, or None if name is absent."""
        return samba_dns_io.read_node_specs(self.samdb, self._node_dn(zone, name))

    def _unpack(self, raw):
        """Unpack raw dnsRecord values into records (tombstones included)."""
        ndr = samba_dns_io.load_ndr()
        dnsp = samba_dns_io.load_dnsp()
        return [ndr.ndr_unpack(dnsp.DnssrvRpcRecord, value) for value in raw]

    def _live_records(self, raw):
        """Unpack raw values into records, dropping tombstones."""
        dnsp = samba_dns_io.load_dnsp()
        return [rec for rec in self._unpack(raw) if rec.wType != dnsp.DNS_TYPE_TOMBSTONE]

    def _revive(self, node_dn, raw, spec, serial):
        """Bring a tombstoned node back to life with the desired record on it.

        When the last record of a name is removed, samba keeps the dnsNode as a
        tombstone (``dNSTombstoned=TRUE`` plus a single tombstone record) instead
        of deleting it, and the DNS server never answers such a node. Merely
        appending a value would leave the flag set, so the records are replaced
        (live ones kept, the tombstone dropped, the desired one added) and the
        flag is cleared in one modify - the state samba's own
        ``dns_common_replace`` writes when it revives a node.
        """
        ldb = samba_user_io.load_ldb()
        ndr = samba_dns_io.load_ndr()
        records = [rec for rec in self._live_records(raw) if not self._matches(rec, spec)]
        records.append(samba_dns_io.build_record(spec, serial))
        message = ldb.Message(node_dn)
        message["dnsRecord"] = ldb.MessageElement(
            [ndr.ndr_pack(rec) for rec in records], ldb.FLAG_MOD_REPLACE, "dnsRecord"
        )
        message["dNSTombstoned"] = ldb.MessageElement("FALSE", ldb.FLAG_MOD_REPLACE, "dNSTombstoned")
        self.samdb.modify(message)

    def _create_node(self, node_dn, spec, serial):
        """Create a new dnsNode holding the single desired record."""
        ldb = samba_user_io.load_ldb()
        ndr = samba_dns_io.load_ndr()
        message = ldb.Message(node_dn)
        message["objectClass"] = ldb.MessageElement(["top", "dnsNode"], ldb.FLAG_MOD_ADD, "objectClass")
        message["dnsRecord"] = ldb.MessageElement(
            [ndr.ndr_pack(samba_dns_io.build_record(spec, serial))], ldb.FLAG_MOD_ADD, "dnsRecord"
        )
        self.samdb.add(message)

    def _serial(self, zone):
        """Raise the zone's SOA serial for the change about to be written; return it."""
        return samba_dns_io.bump_soa_serial(self.samdb, self._zone_dn(zone))

    def _matching_values(self, raw, spec):
        """Return the raw dnsRecord values whose record has the identity of ``spec``."""
        ndr = samba_dns_io.load_ndr()
        dnsp = samba_dns_io.load_dnsp()
        return [value for value in raw if self._matches(ndr.ndr_unpack(dnsp.DnssrvRpcRecord, value), spec)]

    @staticmethod
    def _is_tombstone(value):
        """True if a raw dnsRecord value holds a tombstone record."""
        ndr = samba_dns_io.load_ndr()
        dnsp = samba_dns_io.load_dnsp()
        return ndr.ndr_unpack(dnsp.DnssrvRpcRecord, value).wType == dnsp.DNS_TYPE_TOMBSTONE

    @staticmethod
    def _ttl(value):
        """Return the TTL stored in a raw dnsRecord value."""
        ndr = samba_dns_io.load_ndr()
        dnsp = samba_dns_io.load_dnsp()
        return ndr.ndr_unpack(dnsp.DnssrvRpcRecord, value).dwTtlSeconds

    def add(self, zone, name, spec):
        """Add the record, creating or reviving the node if needed. Returns False if present.

        An existing live node is extended with a single ``dnsRecord`` value
        (FLAG_MOD_ADD), so other records on the name - including the SOA at the
        apex - are left untouched rather than rewritten. A tombstoned node is
        revived instead (see :meth:`_revive`). The zone serial is raised right
        before the write, as samba-tool does, never for a no-op.
        """
        ldb = samba_user_io.load_ldb()
        ndr = samba_dns_io.load_ndr()
        node_dn = self._node_dn(zone, name)
        node = self._read_node(node_dn)
        serial = None
        if node is None:
            serial = self._serial(zone)
            try:
                self._create_node(node_dn, spec, serial)
                return True
            except ldb.LdbError as err:
                if err.args[0] != ldb.ERR_ENTRY_ALREADY_EXISTS:
                    raise
                # Created concurrently between the read and the add; fall through
                # to the modify path against the now-existing node.
                node = self._read_node(node_dn)
                if node is None:
                    raise
        raw, tombstoned = node
        if tombstoned:
            self._revive(node_dn, raw, spec, self._serial(zone) if serial is None else serial)
            return True
        if any(self._matches(rec, spec) for rec in self._live_records(raw)):
            return False
        if serial is None:
            serial = self._serial(zone)
        message = ldb.Message(node_dn)
        message["dnsRecord"] = ldb.MessageElement(
            [ndr.ndr_pack(samba_dns_io.build_record(spec, serial))], ldb.FLAG_MOD_ADD, "dnsRecord"
        )
        try:
            self.samdb.modify(message)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_ATTRIBUTE_OR_VALUE_EXISTS:
                # Added concurrently with identical bytes; the desired state holds.
                return False
            raise
        return True

    def update(self, zone, name, spec):
        """Give the record with the identity of ``spec`` the desired TTL.

        Returns False if the stored TTL already matches. The old value is
        deleted and the rebuilt one added in a single modify (compare-and-swap):
        a value rewritten concurrently fails with ERR_NO_SUCH_ATTRIBUTE and the
        node is re-read rather than overwritten. A record gone meanwhile is
        added again, so the desired state holds either way.
        """
        ldb = samba_user_io.load_ldb()
        ndr = samba_dns_io.load_ndr()
        node_dn = self._node_dn(zone, name)
        attempt = 0
        while True:
            node = self._read_node(node_dn)
            if node is None or node[1]:
                return self.add(zone, name, spec)
            matched = self._matching_values(node[0], spec)
            if not matched:
                return self.add(zone, name, spec)
            if all(self._ttl(value) == spec["ttl"] for value in matched):
                return False
            serial = self._serial(zone)
            message = ldb.Message(node_dn)
            message.add(ldb.MessageElement(matched, ldb.FLAG_MOD_DELETE, "dnsRecord"))
            message.add(ldb.MessageElement(
                [ndr.ndr_pack(samba_dns_io.build_record(spec, serial))], ldb.FLAG_MOD_ADD, "dnsRecord"
            ))
            try:
                self.samdb.modify(message)
                return True
            except ldb.LdbError as err:
                attempt += 1
                if err.args[0] != ldb.ERR_NO_SUCH_ATTRIBUTE or attempt >= samba_dns_io.CAS_RETRIES:
                    raise

    def remove(self, zone, name, spec):
        """Remove the record. Returns False if it was already absent.

        Only the exact stored values of the matching record are deleted, so a
        record added concurrently on the same name survives (the attribute is
        never rewritten as a whole). When the last live record goes, the node
        is tombstoned in the same modify - a tombstone record plus
        ``dNSTombstoned=TRUE``, the state samba itself leaves behind for its
        garbage collection. A value that vanished meanwhile fails with
        ERR_NO_SUCH_ATTRIBUTE and the node is re-read.
        """
        ldb = samba_user_io.load_ldb()
        ndr = samba_dns_io.load_ndr()
        node_dn = self._node_dn(zone, name)
        attempt = 0
        while True:
            node = self._read_node(node_dn)
            if node is None or node[1]:
                return False
            raw = node[0]
            matched = self._matching_values(raw, spec)
            if not matched:
                return False
            stale = [value for value in raw if value not in matched and self._is_tombstone(value)]
            live_left = len(raw) - len(matched) - len(stale)
            serial = self._serial(zone)
            message = ldb.Message(node_dn)
            message.add(ldb.MessageElement(matched + stale, ldb.FLAG_MOD_DELETE, "dnsRecord"))
            if live_left == 0:
                message.add(ldb.MessageElement(
                    [ndr.ndr_pack(samba_dns_io.tombstone_record(serial))], ldb.FLAG_MOD_ADD, "dnsRecord"
                ))
                message["dNSTombstoned"] = ldb.MessageElement("TRUE", ldb.FLAG_MOD_REPLACE, "dNSTombstoned")
            try:
                self.samdb.modify(message)
                return True
            except ldb.LdbError as err:
                attempt += 1
                if err.args[0] != ldb.ERR_NO_SUCH_ATTRIBUTE or attempt >= samba_dns_io.CAS_RETRIES:
                    raise

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
    argument_spec.update(connection_argument_spec())
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
