#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to manage organizational units in a Samba AD DC."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_ou
short_description: Manage organizational units in a Samba AD DC
version_added: 0.1.0
description:
  - Create, modify and remove organizational units (OUs) in a Samba Active
    Directory Domain Controller.
  - Talks to the directory through the native C(samba) Python bindings
    (C(samba.samdb.SamDB)), not through C(samba-tool) subprocesses.
  - The module is idempotent and supports check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run on a Samba AD DC host with the C(samba) Python bindings installed.
options:
  name:
    description:
      - The name (RDN value) of the organizational unit.
    type: str
    required: true
  path:
    description:
      - The distinguished name of the parent under which the OU lives, for
        example C(DC=example,DC=com) for a top-level OU or
        C(OU=Dept,DC=example,DC=com) for a nested one.
      - The OU's distinguished name is built as C(OU=<name>,<path>). The parent
        must already exist; missing parents are not created (no partial
        hierarchy is built).
    type: str
    required: true
  description:
    description:
      - A free-form description of the OU, mapped to the LDAP C(description)
        attribute.
    type: str
  state:
    description:
      - Whether the OU should exist (C(present)) or not (C(absent)).
      - C(absent) only removes an empty OU; if it still contains child objects
        the module fails rather than deleting them. Recursive deletion is not
        supported.
    type: str
    default: present
    choices:
      - present
      - absent
notes:
  - This module must be executed on a Samba AD DC where the C(samba) Python
    bindings and the directory are available.
"""

EXAMPLES = r"""
- name: Ensure a top-level OU exists
  jomrr.samba.samba_ou:
    name: Staff
    path: DC=example,DC=com
    description: All staff accounts
    state: present

- name: Ensure a nested OU exists (its parent must already exist)
  jomrr.samba.samba_ou:
    name: Engineering
    path: OU=Staff,DC=example,DC=com
    state: present

- name: Remove an empty OU
  jomrr.samba.samba_ou:
    name: Engineering
    path: OU=Staff,DC=example,DC=com
    state: absent
"""

RETURN = r"""
action:
  description:
    - The action that was performed.
    - One of C(created), C(modified), C(deleted) or C(unchanged).
  returned: success
  type: str
  sample: created
ou:
  description: The resulting OU state.
  returned: success
  type: dict
  contains:
    name:
      description: The name (RDN value) of the OU.
      returned: always
      type: str
      sample: Staff
    path:
      description: The parent distinguished name.
      returned: always
      type: str
      sample: DC=example,DC=com
    state:
      description: Whether the OU exists after the run.
      returned: always
      type: str
      sample: present
    dn:
      description: The distinguished name of the OU object.
      returned: when the OU exists
      type: str
      sample: OU=Staff,DC=example,DC=com
    description:
      description: The description of the OU.
      returned: when the OU exists
      type: str
      sample: All staff accounts
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_ou_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_ou_logic as logic


class SambaOuIO:
    """LDB read/write operations for organizational units.

    The ldb bindings are imported lazily (via the shared
    ``samba_user_io.load_ldb``), so importing this module never requires them.
    DNs are built with ``ldb.Dn.set_component`` so the name value is escaped and
    cannot inject extra DN components.
    """

    def __init__(self, samdb):
        self.samdb = samdb

    def _ou_dn(self, name, path):
        """Build the OU distinguished name safely from ``name`` and ``path``."""
        try:
            parent = samba_user_io.parse_dn(self.samdb, path)
        except ValueError:
            raise logic.SambaOuError("path '%s' is not a valid distinguished name" % path)
        return samba_user_io.build_child_dn(self.samdb, "OU", name, parent)

    def read_current(self, name, path):
        """Return the normalized current state of the OU or ``None``."""
        ldb = samba_user_io.load_ldb()
        dn = self._ou_dn(name, path)
        try:
            res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=samba_ou_io.OU_ATTRS)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                return None
            raise
        if len(res) == 0:
            return None
        return samba_ou_io.message_to_state(res[0])

    def create_ou(self, name, path, description):
        """Create the OU. A concurrent create or a missing parent fail cleanly."""
        ldb = samba_user_io.load_ldb()
        dn = self._ou_dn(name, path)
        try:
            self.samdb.create_ou(dn, description=description)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_ENTRY_ALREADY_EXISTS:
                raise logic.SambaOuError("OU '%s' already exists (created concurrently?)" % dn)
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                raise logic.SambaOuError(
                    "parent path '%s' does not exist; create it first" % path
                )
            raise

    def set_description(self, dn, description):
        """Replace the description, mapping a vanished object to a clear error."""
        ldb = samba_user_io.load_ldb()
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, dn)
        message["description"] = ldb.MessageElement(description, ldb.FLAG_MOD_REPLACE, "description")
        try:
            self.samdb.modify(message)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                raise logic.SambaOuError("OU '%s' vanished before it could be modified" % dn)
            raise

    def delete_ou(self, dn):
        """Delete an empty OU by DN.

        Returns ``False`` if it was already gone (idempotent no-op). A non-empty
        OU fails cleanly (the DC rejects deleting a non-leaf), which also covers
        the race where a child appears just before deletion.
        """
        ldb = samba_user_io.load_ldb()
        try:
            self.samdb.delete(ldb.Dn(self.samdb, dn))
            return True
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                return False
            if err.args[0] == ldb.ERR_NOT_ALLOWED_ON_NON_LEAF:
                raise logic.SambaOuError("OU '%s' is not empty; it contains child objects" % dn)
            raise


def main():
    """Module entry point."""
    argument_spec = dict(
        name=dict(type="str", required=True),
        path=dict(type="str", required=True),
        description=dict(type="str"),
        state=dict(type="str", default="present", choices=["present", "absent"]),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)
    ou_io = SambaOuIO(samdb)

    try:
        result = logic.run(module.params, module.check_mode, ou_io)
    except logic.SambaOuError as exc:
        module.fail_json(msg=to_native(exc))
    except Exception as exc:
        module.fail_json(
            msg="samba_ou failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
