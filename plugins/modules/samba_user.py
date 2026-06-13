#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to manage users in a Samba AD DC via the python bindings."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_user
short_description: Manage users in a Samba AD DC
version_added: 0.1.0
description:
  - Create, modify and remove user accounts in a Samba Active Directory Domain
    Controller.
  - Talks to the directory through the native C(samba) Python bindings
    (C(samba.samdb.SamDB)), not through C(samba-tool) subprocesses.
  - The module is idempotent and supports check mode. Only attributes that are
    explicitly set are compared and changed; unset attributes are left
    untouched.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run on a Samba AD DC host with the C(samba) Python bindings installed.
options:
  username:
    description:
      - The logon name of the user (the C(sAMAccountName)).
    type: str
    required: true
    aliases:
      - name
      - samaccountname
  given_name:
    description:
      - The given (first) name of the user, mapped to the LDAP C(givenName)
        attribute.
    type: str
  surname:
    description:
      - The surname (last name) of the user, mapped to the LDAP C(sn) attribute.
    type: str
  display_name:
    description:
      - The display name of the user, mapped to the LDAP C(displayName)
        attribute.
    type: str
  email:
    description:
      - The e-mail address of the user, mapped to the LDAP C(mail) attribute.
    type: str
  description:
    description:
      - A free-form description of the user, mapped to the LDAP C(description)
        attribute.
    type: str
  enabled:
    description:
      - Whether the account is enabled.
      - Mapped to the C(ACCOUNTDISABLE) bit of the C(userAccountControl)
        attribute.
    type: bool
    default: true
  password:
    description:
      - The initial password for the account.
      - Only used when the user is created; it is never read back and never
        compared, so it does not affect idempotency and is not changed on
        subsequent runs.
      - Required when a new user has to be created.
    type: str
  state:
    description:
      - Whether the user should exist (C(present)) or not (C(absent)).
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
- name: Ensure a user exists and is enabled
  jomrr.samba.samba_user:
    username: jdoe
    given_name: Jane
    surname: Doe
    display_name: Jane Doe
    email: jane.doe@example.com
    description: Example user
    password: "{{ vaulted_initial_password }}"
    enabled: true
    state: present

- name: Disable a user without changing anything else
  jomrr.samba.samba_user:
    username: jdoe
    enabled: false

- name: Update only the display name (other attributes are left untouched)
  jomrr.samba.samba_user:
    username: jdoe
    display_name: Jane M. Doe

- name: Remove a user
  jomrr.samba.samba_user:
    username: jdoe
    state: absent
"""

RETURN = r"""
action:
  description:
    - The action that was performed.
    - One of C(created), C(modified), C(deleted) or C(unchanged).
  returned: success
  type: str
  sample: modified
user:
  description: The resulting user state.
  returned: success
  type: dict
  contains:
    username:
      description: The logon name of the user.
      returned: always
      type: str
      sample: jdoe
    state:
      description: Whether the user exists after the run.
      returned: always
      type: str
      sample: present
    dn:
      description: The distinguished name of the user object.
      returned: when the user exists
      type: str
      sample: CN=Jane Doe,CN=Users,DC=example,DC=com
    given_name:
      description: The given name of the user.
      returned: when the user exists
      type: str
      sample: Jane
    surname:
      description: The surname of the user.
      returned: when the user exists
      type: str
      sample: Doe
    display_name:
      description: The display name of the user.
      returned: when the user exists
      type: str
      sample: Jane Doe
    email:
      description: The e-mail address of the user.
      returned: when the user exists
      type: str
      sample: jane.doe@example.com
    description:
      description: The description of the user.
      returned: when the user exists
      type: str
      sample: Example user
    enabled:
      description: Whether the account is enabled.
      returned: when the user exists
      type: bool
      sample: true
"""

import importlib
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_logic as logic


class SambaUserIO:
    """LDB read/write operations for users.

    All ``samba``/``ldb`` imports are performed lazily inside the methods via
    :func:`importlib.import_module`, so importing this module never requires the
    bindings (keeping the static sanity phase green).
    """

    def __init__(self, samdb):
        self.samdb = samdb

    @staticmethod
    def _ldb():
        """Import and return the ``ldb`` module lazily."""
        return importlib.import_module("ldb")

    def read_current(self, username):
        """Return the normalized current state of ``username`` or ``None``."""
        ldb = self._ldb()
        expression = "(&(objectClass=user)(sAMAccountName=%s))" % ldb.binary_encode(username)
        res = self.samdb.search(
            base=self.samdb.domain_dn(),
            scope=ldb.SCOPE_SUBTREE,
            expression=expression,
            attrs=samba_user_io.USER_ATTRS,
        )
        if len(res) == 0:
            return None
        return samba_user_io.message_to_state(res[0])

    def create_user(self, username, password):
        """Create the base user object.

        A concurrent creation (the object already exists at write time) is
        turned into a clear error instead of a raw traceback.
        """
        ldb = self._ldb()
        try:
            self.samdb.newuser(username, password)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_ENTRY_ALREADY_EXISTS:
                raise logic.SambaUserError(
                    "user '%s' already exists (created concurrently?)" % username
                )
            raise

    def apply_attrs(self, dn, attr_changes):
        """Replace the given simple attributes on the user object.

        Fails cleanly if the object was removed (concurrent delete) before the
        modify reached the DC.
        """
        ldb = self._ldb()
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, dn)
        for name, value in attr_changes.items():
            ldap_attr = logic.ATTR_TO_LDAP[name]
            message[ldap_attr] = ldb.MessageElement(value, ldb.FLAG_MOD_REPLACE, ldap_attr)
        self._modify(message, dn)

    def set_enabled(self, dn, current_uac, enabled):
        """Toggle the ACCOUNTDISABLE bit of ``userAccountControl``.

        Fails cleanly if the object was removed (concurrent delete) before the
        modify reached the DC.
        """
        ldb = self._ldb()
        if enabled:
            new_uac = current_uac & ~logic.UAC_ACCOUNTDISABLE
        else:
            new_uac = current_uac | logic.UAC_ACCOUNTDISABLE
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, dn)
        message["userAccountControl"] = ldb.MessageElement(
            str(new_uac), ldb.FLAG_MOD_REPLACE, "userAccountControl"
        )
        self._modify(message, dn)

    def _modify(self, message, dn):
        """Apply an LDB modify, mapping a vanished object to a clear error."""
        ldb = self._ldb()
        try:
            self.samdb.modify(message)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                raise logic.SambaUserError(
                    "user '%s' vanished before it could be modified" % dn
                )
            raise

    def delete_user(self, dn):
        """Delete the user object by DN.

        Returns ``True`` if it was deleted, ``False`` if it was already gone
        (concurrent delete) - which is an idempotent no-op, not an error.
        """
        ldb = self._ldb()
        try:
            self.samdb.delete(ldb.Dn(self.samdb, dn))
            return True
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                return False
            raise


def main():
    """Module entry point."""
    argument_spec = dict(
        username=dict(type="str", required=True, aliases=["name", "samaccountname"]),
        given_name=dict(type="str"),
        surname=dict(type="str"),
        display_name=dict(type="str"),
        email=dict(type="str"),
        description=dict(type="str"),
        enabled=dict(type="bool", default=True),
        password=dict(type="str", no_log=True),
        state=dict(type="str", default="present", choices=["present", "absent"]),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)
    user_io = SambaUserIO(samdb)

    try:
        result = logic.run(module.params, module.check_mode, user_io)
    except logic.SambaUserError as exc:
        module.fail_json(msg=to_native(exc))
    except Exception as exc:
        module.fail_json(
            msg="samba_user failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
