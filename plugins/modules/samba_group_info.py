#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to query groups from a Samba AD DC via the python bindings."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_group_info
short_description: Query groups from a Samba AD DC
version_added: 0.1.0
extends_documentation_fragment:
  - jomrr.samba.connection
description:
  - Read groups from a Samba Active Directory Domain Controller.
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
      - Restrict the query to the group with this name (its C(sAMAccountName)).
      - If omitted, all groups are returned.
    type: str
    aliases:
      - samaccountname
notes:
  - This module must be executed on a Samba AD DC where the C(samba) Python
    bindings and the directory are available.
"""

EXAMPLES = r"""
- name: Look up a single group
  jomrr.samba.samba_group_info:
    name: engineers
  register: engineers_info

- name: Fetch all groups
  jomrr.samba.samba_group_info:
  register: all_groups

- name: Show the scope and category of every group
  ansible.builtin.debug:
    msg: "{{ all_groups.groups | map(attribute='scope') | list }}"
"""

RETURN = r"""
groups:
  description:
    - The matching groups. Empty when no group matched.
  returned: success
  type: list
  elements: dict
  contains:
    name:
      description: The name of the group.
      returned: always
      type: str
      sample: engineers
    state:
      description: Always C(present) for a returned group.
      returned: always
      type: str
      sample: present
    dn:
      description: The distinguished name of the group object.
      returned: always
      type: str
      sample: CN=engineers,CN=Users,DC=example,DC=com
    scope:
      description: The group scope, decoded from C(groupType).
      returned: always
      type: str
      sample: global
    category:
      description: The group category, decoded from C(groupType).
      returned: always
      type: str
      sample: security
    description:
      description: The description of the group.
      returned: always
      type: str
      sample: Engineering staff
    gid_number:
      description: The POSIX group ID (C(gidNumber)), or null if unset.
      returned: always
      type: int
      sample: 10000
    members:
      description: The distinguished names of the group members.
      returned: always
      type: list
      elements: str
      sample:
        - CN=Jane Doe,CN=Users,DC=example,DC=com
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb, connection_argument_spec
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_group_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_group_logic as logic


def query(samdb, name):
    """Return a list of public group states; all groups when ``name`` is None.

    The ``name`` is escaped via ``ldb.binary_encode`` before it enters the
    search filter, so it cannot break out into LDAP filter syntax.
    """
    ldb = samba_user_io.load_ldb()
    if name is None:
        expression = "(objectClass=group)"
    else:
        expression = "(&(objectClass=group)(sAMAccountName=%s))" % ldb.binary_encode(name)
    res = samdb.search(
        base=samdb.domain_dn(),
        scope=ldb.SCOPE_SUBTREE,
        expression=expression,
        attrs=samba_group_io.GROUP_ATTRS,
    )
    return [
        logic.public_state(samba_group_io.message_to_state(message), samba_user_io.first_value(message, "sAMAccountName"))
        for message in res
    ]


def main():
    """Module entry point."""
    argument_spec = dict(
        name=dict(type="str", aliases=["samaccountname"]),
    )
    argument_spec.update(connection_argument_spec())
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)

    try:
        groups = query(samdb, module.params["name"])
    except Exception as exc:
        module.fail_json(
            msg="samba_group_info failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(changed=False, groups=groups)


if __name__ == "__main__":
    main()
