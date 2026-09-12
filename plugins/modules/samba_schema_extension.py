#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to extend the schema of a Samba AD domain with a known extension."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_schema_extension
short_description: Extend the schema of a Samba AD domain with a known extension
version_added: 2.0.0
description:
  - Add one of the schema extensions the collection knows to the domain's
    schema, exactly as its published definition specifies, and complete an
    extension that is only partly present.
  - C(laps) is the Windows LAPS schema (the seven C(msLAPS-*) attributes, the
    C(ms-LAPS-Encrypted-Password-Attributes) property set and their place on
    the C(computer) class), from Microsoft's LAPS technical reference.
    C(sshpublickey) is the OpenSSH C(sshPublicKey) attribute with its
    C(ldapPublicKey) auxiliary class linked to C(user), C(ldapcompat) the
    C(entryUUID)/C(nsUniqueId) attributes with C(ldapCompatPerson); both from
    the Samba wiki's schema extension LDIFs, their C(schemaIDGUID) included.
  - Schema is only ever extended, never removed, so there is no C(absent);
    missing entries are added, list properties gain missing values, and a
    differing property is set - what the directory considers immutable (an
    OID, a syntax) it refuses and the module reports that.
  - Works on the local C(sam.ldb) of the schema master with the C(samba) Python
    bindings, as C(ldbmodify --option="dsdb:schema update allowed"=true) does,
    in one transaction per phase (attributes and rights, then classes, then
    the links into existing classes) with a schema reload in between.
  - The module is idempotent and supports check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run on the schema master, as root, with the C(samba) Python bindings
    installed; the module refuses to run on any other DC.
options:
  extension:
    description:
      - The extension to add.
    type: str
    required: true
    choices:
      - laps
      - ldapcompat
      - sshpublickey
notes:
  - This module acts on the local machine and has no connection options; run it
    on the schema master (C(hosts:) that DC, or C(delegate_to) it).
  - Schema changes replicate to every DC of the forest and cannot be undone.
  - The directory assigns the C(schemaIDGUID) of the Windows LAPS attributes;
    Microsoft publishes none for them. The property set GUID, which Windows
    LAPS delegation uses, is the published one.
"""

EXAMPLES = r"""
- name: Prepare the schema for Windows LAPS
  jomrr.samba.samba_schema_extension:
    extension: laps

- name: Let user accounts carry OpenSSH public keys
  jomrr.samba.samba_schema_extension:
    extension: sshpublickey
"""

RETURN = r"""
extension:
  description: The extension that was ensured.
  returned: success
  type: str
  sample: laps
changes:
  description:
    - What was added or completed, one entry per schema object, in the order
      applied; empty when the extension was already complete. In check mode,
      what would be done.
  returned: success
  type: list
  elements: str
  sample:
    - add attributeSchema msLAPS-Password
    - add controlAccessRight ms-LAPS-Encrypted-Password-Attributes
    - modify classSchema computer (mayContain)
"""

import importlib
import traceback
import uuid

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import fail_without_bindings
from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_schema_catalog as catalog
from ansible_collections.jomrr.samba.plugins.module_utils import samba_schema_logic as logic


class SambaSchemaIO:
    """Schema reads and writes on the local ``sam.ldb`` of the schema master.

    The database is opened by path with a system session, the same
    credential-free local path the setup modules use, with schema updates
    allowed for this process. All ``samba`` imports are lazy, so importing
    this module never requires the bindings.
    """

    def __init__(self):
        param = importlib.import_module("samba.param")
        auth = importlib.import_module("samba.auth")
        samdb_mod = importlib.import_module("samba.samdb")
        load_parm = param.LoadParm()
        load_parm.load_default()
        # Schema writes are refused unless the process allows them explicitly,
        # the switch ldbmodify --option="dsdb:schema update allowed"=true sets.
        load_parm.set("dsdb:schema update allowed", "yes")
        self.samdb = samdb_mod.SamDB(
            url=load_parm.private_path("sam.ldb"), session_info=auth.system_session(), lp=load_parm
        )

    def schema_dn(self):
        """The schema naming context."""
        return str(self.samdb.get_schema_basedn())

    def config_dn(self):
        """The configuration naming context."""
        return str(self.samdb.get_config_basedn())

    def require_schema_master(self):
        """Fail unless this DC holds the schema FSMO role."""
        ldb = samba_ldb.load_ldb()
        schema = self.samdb.search(base=self.schema_dn(), scope=ldb.SCOPE_BASE, attrs=["fSMORoleOwner"])[0]
        owner = str(schema["fSMORoleOwner"][0])
        if ldb.Dn(self.samdb, owner) != ldb.Dn(self.samdb, self.samdb.get_dsServiceName()):
            raise logic.SambaSchemaError(
                "schema changes must run on the schema master (%s); this DC is %s"
                % (owner, self.samdb.get_dsServiceName())
            )

    def _find(self, base, expression, attrs):
        """One-level search below ``base``; the single match as a record, or None."""
        ldb = samba_ldb.load_ldb()
        res = self.samdb.search(base=base, scope=ldb.SCOPE_ONELEVEL, expression=expression, attrs=attrs)
        if len(res) == 0:
            return None
        message = res[0]
        record = {"_dn": str(message.dn)}
        for attr in attrs:
            element = message.get(attr)
            if element is None:
                record[attr] = []
            elif attr in catalog.GUID_PROPERTIES:
                record[attr] = [str(uuid.UUID(bytes_le=bytes(value))) for value in element]
            else:
                record[attr] = [str(value) for value in element]
        return record

    def find_schema(self, name, attrs):
        """The schema entry with this lDAPDisplayName, or None."""
        ldb = samba_ldb.load_ldb()
        return self._find(self.schema_dn(), "(lDAPDisplayName=%s)" % ldb.binary_encode(name), attrs)

    def find_right(self, rights_guid, attrs):
        """The extended right with this rightsGuid, or None."""
        ldb = samba_ldb.load_ldb()
        base = "CN=Extended-Rights,%s" % self.config_dn()
        return self._find(base, "(rightsGuid=%s)" % ldb.binary_encode(rights_guid), attrs)

    @staticmethod
    def _stored(attr, values):
        """The values as the directory stores them (GUIDs in binary form)."""
        if attr in catalog.GUID_PROPERTIES:
            return [uuid.UUID(value).bytes_le for value in values]
        return list(values)

    def apply(self, operations):
        """Apply one phase's operations in a single transaction."""
        ldb = samba_ldb.load_ldb()
        label = "schema transaction"
        self.samdb.transaction_start()
        try:
            for operation in operations:
                label = operation["label"]
                message = ldb.Message(ldb.Dn(self.samdb, operation["dn"]))
                if operation["action"] == "add":
                    for attr, values in operation["values"].items():
                        message[attr] = ldb.MessageElement(self._stored(attr, values), ldb.FLAG_MOD_ADD, attr)
                    self.samdb.add(message)
                    continue
                for attr, values in operation["replace"].items():
                    message[attr] = ldb.MessageElement(self._stored(attr, values), ldb.FLAG_MOD_REPLACE, attr)
                for attr, values in operation["add"].items():
                    message[attr] = ldb.MessageElement(self._stored(attr, values), ldb.FLAG_MOD_ADD, attr)
                self.samdb.modify(message)
            self.samdb.transaction_commit()
        except Exception as exc:
            self.samdb.transaction_cancel()
            raise logic.SambaSchemaError("%s failed: %s" % (label, samba_ldb.error_text(exc)))

    def schema_update_now(self):
        """Make the directory reload its schema (rootDSE schemaUpdateNow)."""
        self.samdb.set_schema_update_now()


def main():
    """Module entry point."""
    argument_spec = dict(
        extension=dict(type="str", required=True, choices=sorted(catalog.EXTENSIONS)),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    fail_without_bindings(module)

    try:
        result = logic.run(module.params, module.check_mode, SambaSchemaIO())
    except logic.SambaSchemaError as exc:
        module.fail_json(msg=to_native(exc))
    except Exception as exc:
        module.fail_json(
            msg="samba_schema_extension failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
