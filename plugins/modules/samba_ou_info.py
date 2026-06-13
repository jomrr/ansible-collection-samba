#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to query organizational units from a Samba AD DC."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_ou_info
short_description: Query organizational units from a Samba AD DC
version_added: 0.1.0
description:
  - Read organizational units (OUs) from a Samba Active Directory Domain
    Controller.
  - Talks to the directory through the native C(samba) Python bindings
    (C(samba.samdb.SamDB)), not through C(samba-tool) subprocesses.
  - This module is read-only; it never changes the directory and always reports
    C(changed=false).
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run on a Samba AD DC host with the C(samba) Python bindings installed.
options:
  name:
    description:
      - Restrict the query to the OU with this name (its RDN value), looked up
        directly beneath O(path).
      - If omitted, all OUs in the subtree below O(path) are returned.
    type: str
  path:
    description:
      - The distinguished name to search under, for example
        C(DC=example,DC=com) or C(OU=Staff,DC=example,DC=com).
      - With O(name), it is the parent the named OU is looked up directly below.
      - Without O(name), it is the root of the subtree that is listed.
      - If omitted, the domain root is used.
    type: str
notes:
  - This module must be executed on a Samba AD DC where the C(samba) Python
    bindings and the directory are available.
"""

EXAMPLES = r"""
- name: Look up a single OU directly below the domain root
  jomrr.samba.samba_ou_info:
    name: Staff
    path: DC=example,DC=com
  register: staff_ou

- name: Fetch all OUs in the domain
  jomrr.samba.samba_ou_info:
  register: all_ous

- name: Fetch the OUs below a parent OU
  jomrr.samba.samba_ou_info:
    path: OU=Staff,DC=example,DC=com
  register: staff_children

- name: Show the distinguished name of every OU
  ansible.builtin.debug:
    msg: "{{ all_ous.ous | map(attribute='dn') | list }}"
"""

RETURN = r"""
ous:
  description:
    - The matching organizational units. Empty when none matched.
  returned: success
  type: list
  elements: dict
  contains:
    name:
      description: The name (RDN value) of the OU.
      returned: always
      type: str
      sample: Staff
    path:
      description: The parent distinguished name of the OU.
      returned: always
      type: str
      sample: DC=example,DC=com
    state:
      description: Always C(present) for a returned OU.
      returned: always
      type: str
      sample: present
    dn:
      description: The distinguished name of the OU object.
      returned: always
      type: str
      sample: OU=Staff,DC=example,DC=com
    description:
      description: The description of the OU.
      returned: always
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


def query(samdb, name, path):
    """Return a list of public OU states.

    With ``name`` the single OU directly below ``path`` is returned; without it,
    every OU in the subtree below ``path`` (the domain root when ``path`` is
    omitted) is returned. The ``name`` is escaped via ``ldb.binary_encode``
    before it enters the search filter, so it cannot break out into LDAP filter
    syntax. A missing ``path`` base maps to an empty result.
    """
    ldb = samba_user_io.load_ldb()
    base = path if path is not None else samdb.domain_dn()
    if name is None:
        scope = ldb.SCOPE_SUBTREE
        expression = "(objectClass=organizationalUnit)"
    else:
        scope = ldb.SCOPE_ONELEVEL
        expression = "(&(objectClass=organizationalUnit)(ou=%s))" % ldb.binary_encode(name)
    try:
        res = samdb.search(base=base, scope=scope, expression=expression, attrs=samba_ou_io.OU_ATTRS)
    except ldb.LdbError as err:
        if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return []
        raise
    return [
        logic.public_state(samba_ou_io.message_to_state(message), message.dn.get_rdn_value(), str(message.dn.parent()))
        for message in res
    ]


def main():
    """Module entry point."""
    argument_spec = dict(
        name=dict(type="str"),
        path=dict(type="str"),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)

    try:
        ous = query(samdb, module.params["name"], module.params["path"])
    except Exception as exc:
        module.fail_json(
            msg="samba_ou_info failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(changed=False, ous=ous)


if __name__ == "__main__":
    main()
