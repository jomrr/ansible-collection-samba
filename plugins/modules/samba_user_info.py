#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to query users from a Samba AD DC via the python bindings."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_user_info
short_description: Query users from a Samba AD DC
version_added: 0.1.0
extends_documentation_fragment:
  - jomrr.samba.connection
description:
  - Read user accounts from a Samba Active Directory Domain Controller.
  - Talks to the directory through the native C(samba) Python bindings
    (C(samba.samdb.SamDB)), not through C(samba-tool) subprocesses.
  - This module is read-only; it never changes the directory and always reports
    C(changed=false).
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run on a Samba AD DC host with the C(samba) Python bindings installed.
options:
  username:
    description:
      - Restrict the query to the user with this logon name (the
        C(sAMAccountName)).
      - If omitted, all user accounts are returned.
    type: str
    aliases:
      - name
      - samaccountname
seealso:
  - module: jomrr.samba.samba_user
    description: Manage users in a Samba AD DC.
notes:
  - This module must be executed on a Samba AD DC where the C(samba) Python
    bindings and the directory are available.
  - Only real user accounts are returned; computer accounts are excluded.
"""

EXAMPLES = r"""
- name: Look up a single user
  jomrr.samba.samba_user_info:
    username: jdoe
  register: jdoe_info

- name: Fetch all users
  jomrr.samba.samba_user_info:
  register: all_users

- name: Show the e-mail addresses of all users
  ansible.builtin.debug:
    msg: "{{ all_users.users | map(attribute='email') | list }}"
"""

RETURN = r"""
users:
  description:
    - The matching users. Empty when no user matched.
  returned: success
  type: list
  elements: dict
  contains:
    username:
      description: The logon name of the user.
      returned: always
      type: str
      sample: jdoe
    state:
      description: Always C(present) for a returned user.
      returned: always
      type: str
      sample: present
    dn:
      description: The distinguished name of the user object.
      returned: always
      type: str
      sample: CN=Jane Doe,CN=Users,DC=example,DC=com
    given_name:
      description: The given name of the user.
      returned: always
      type: str
      sample: Jane
    surname:
      description: The surname of the user.
      returned: always
      type: str
      sample: Doe
    display_name:
      description: The display name of the user.
      returned: always
      type: str
      sample: Jane Doe
    email:
      description: The e-mail address of the user.
      returned: always
      type: str
      sample: jane.doe@example.com
    description:
      description: The description of the user.
      returned: always
      type: str
      sample: Example user
    uid_number:
      description: The POSIX user ID (C(uidNumber)), or null if unset.
      returned: always
      type: int
      sample: 10001
    gid_number:
      description: The POSIX primary group ID (C(gidNumber)), or null if unset.
      returned: always
      type: int
      sample: 10000
    unix_home_directory:
      description: The POSIX home directory (C(unixHomeDirectory)), or null if unset.
      returned: always
      type: str
      sample: /home/jdoe
    login_shell:
      description: The POSIX login shell (C(loginShell)), or null if unset.
      returned: always
      type: str
      sample: /bin/bash
    gecos:
      description: The POSIX GECOS field (C(gecos)), or null if unset.
      returned: always
      type: str
      sample: Jane Doe
    enabled:
      description: Whether the account is enabled.
      returned: always
      type: bool
      sample: true
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb, connection_argument_spec
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_logic as logic


def query(samdb, username):
    """Return a list of public user states; all users when ``username`` is None.

    The ``username`` is escaped via ``ldb.binary_encode`` before it enters the
    search filter, so it cannot break out into LDAP filter syntax.
    """
    ldb = samba_user_io.load_ldb()
    base_filter = "(&(objectCategory=person)(objectClass=user)%s)"
    if username is None:
        expression = base_filter % ""
    else:
        expression = base_filter % ("(sAMAccountName=%s)" % ldb.binary_encode(username))
    res = samdb.search(
        base=samdb.domain_dn(),
        scope=ldb.SCOPE_SUBTREE,
        expression=expression,
        attrs=samba_user_io.USER_ATTRS,
    )
    return [
        logic.public_state(samba_user_io.message_to_state(message), samba_user_io.first_value(message, "sAMAccountName"))
        for message in res
    ]


def main():
    """Module entry point."""
    argument_spec = dict(
        username=dict(type="str", aliases=["name", "samaccountname"]),
    )
    argument_spec.update(connection_argument_spec())
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)

    try:
        users = query(samdb, module.params["username"])
    except Exception as exc:
        module.fail_json(
            msg="samba_user_info failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(changed=False, users=users)


if __name__ == "__main__":
    main()
