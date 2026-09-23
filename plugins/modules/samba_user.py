# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to manage users in a Samba AD DC via the python bindings."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_user
short_description: Manage users in a Samba AD DC
version_added: 0.1.0
extends_documentation_fragment:
  - jomrr.samba.connection
description:
  - Create, modify and remove user accounts in a Samba Active Directory Domain
    Controller.
  - Talks to the directory through the native C(samba) Python bindings
    (C(samba.samdb.SamDB)), not through C(samba-tool) subprocesses.
  - The module is idempotent and supports check mode. Only attributes that are
    explicitly set are compared and changed; unset attributes are left
    untouched, including the enabled state (see I(enabled)).
  - An empty string removes an attribute from the account, for example
    C(description="") . The POSIX integer attributes I(uid_number) and
    I(gid_number) cannot be removed this way.
  - Only user accounts (LDAP C(objectCategory=person)) are managed; computer
    accounts are never matched, even by an exact C(sAMAccountName).
author:
  - Jonas Mauer (@jomrr)
requirements:
  - The C(samba) Python bindings (C(python3-samba)) on the host that runs the
    module.
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
      - If omitted when the user is created, samba derives it from
        I(given_name) and I(surname), as C(samba-tool user create) does. An
        existing user's display name only changes when it is set explicitly.
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
  uid_number:
    description:
      - The POSIX user ID, mapped to the RFC2307 C(uidNumber) attribute.
      - Requires a domain provisioned with C(--use-rfc2307); setting it on a
        domain without RFC2307 fails before any change is made.
    type: int
  gid_number:
    description:
      - The POSIX primary group ID, mapped to the RFC2307 C(gidNumber)
        attribute.
      - Requires a domain provisioned with C(--use-rfc2307); setting it on a
        domain without RFC2307 fails before any change is made.
    type: int
  unix_home_directory:
    description:
      - The POSIX home directory, mapped to the RFC2307 C(unixHomeDirectory)
        attribute.
      - Requires a domain provisioned with C(--use-rfc2307).
    type: str
  login_shell:
    description:
      - The POSIX login shell, mapped to the RFC2307 C(loginShell) attribute.
      - Requires a domain provisioned with C(--use-rfc2307).
    type: str
  gecos:
    description:
      - The POSIX GECOS field, mapped to the RFC2307 C(gecos) attribute.
      - Requires a domain provisioned with C(--use-rfc2307).
    type: str
  enabled:
    description:
      - Whether the account is enabled.
      - Mapped to the C(ACCOUNTDISABLE) bit of the C(userAccountControl)
        attribute.
      - If omitted, a new account is created enabled and the state of an
        existing account is left unchanged, like every other unset attribute.
        Set C(true) or C(false) explicitly to enforce a state.
    type: bool
  password:
    description:
      - The password for the account.
      - By default it is only applied when the user is created; use
        I(update_password) to also set it on an existing user.
      - It is never read back and never compared, so it never appears in the
        return value or the diff.
      - Required when a new user has to be created.
    type: str
  update_password:
    description:
      - C(on_create) (the default) only sets I(password) when the user is
        created; an existing user's password is left untouched, so repeated
        runs stay idempotent (C(changed=false)).
      - C(always) sets I(password) on every run for an existing user as well.
        Because the password cannot be read back to compare, the module then
        always reports C(changed=true) - the write itself is the change.
      - Has no effect unless I(password) is set.
    type: str
    default: on_create
    choices:
      - on_create
      - always
  path:
    description:
      - The distinguished name of the container or OU the user should live in,
        for example C(OU=Staff,DC=example,DC=com). The parent must already
        exist.
      - When omitted, the user is placed in (and, if it exists elsewhere, moved
        to) the domain's default Users container (C(CN=Users,<domain>)).
      - On an existing user a differing location triggers an idempotent move
        (rename); the comparison is a normalized DN comparison, so only a real
        change moves the object.
    type: str
  state:
    description:
      - Whether the user should exist (C(present)) or not (C(absent)).
    type: str
    default: present
    choices:
      - present
      - absent
seealso:
  - module: jomrr.samba.samba_user_info
    description: Query users from a Samba AD DC.
notes:
  - The DC is reached over the network, so the module does not have to run on a
    domain controller. Any host with the C(samba) bindings that can reach
    O(server) over LDAP and obtain a Kerberos ticket for its realm will do;
    running on the DC itself, with O(server) pointing at it, is the simplest
    topology.
  - Computer accounts are not managed by this module. A I(username) that names
    a computer account matches nothing, so C(state=absent) never deletes a
    computer object.
  - Creating a user is all-or-nothing. The account is added in a single
    operation, placed under I(path) with its names, e-mail, description and
    POSIX attributes; only an explicit I(display_name) and C(enabled=false)
    are follow-up writes. LDAP offers no transactions, so if such a follow-up
    fails, the module removes the account it just created and fails with the
    cause; a failed create never leaves a half-configured account behind. A
    password rejected by the domain policy
    is cleaned up by samba's own create helper (it deletes the account it just
    added) and reported cleanly, so no account remains either. Changes to an
    existing user are separate LDAP operations; if one fails, the earlier ones
    stay applied and a re-run completes the rest.
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

- name: Update only the display name (other attributes, including the enabled state, are left untouched)
  jomrr.samba.samba_user:
    username: jdoe
    display_name: Jane M. Doe

- name: Ensure an existing account is enabled (explicit, enabled has no default)
  jomrr.samba.samba_user:
    username: jdoe
    enabled: true

- name: Set the RFC2307/POSIX attributes (domain provisioned with --use-rfc2307)
  jomrr.samba.samba_user:
    username: jdoe
    uid_number: 10001
    gid_number: 10000
    unix_home_directory: /home/jdoe
    login_shell: /bin/bash
    gecos: Jane Doe

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
    uid_number:
      description: The POSIX user ID (C(uidNumber)), or null if unset.
      returned: when the user exists
      type: int
      sample: 10001
    gid_number:
      description: The POSIX primary group ID (C(gidNumber)), or null if unset.
      returned: when the user exists
      type: int
      sample: 10000
    unix_home_directory:
      description: The POSIX home directory (C(unixHomeDirectory)), or null if unset.
      returned: when the user exists
      type: str
      sample: /home/jdoe
    login_shell:
      description: The POSIX login shell (C(loginShell)), or null if unset.
      returned: when the user exists
      type: str
      sample: /bin/bash
    gecos:
      description: The POSIX GECOS field (C(gecos)), or null if unset.
      returned: when the user exists
      type: str
      sample: Jane Doe
    enabled:
      description: Whether the account is enabled.
      returned: when the user exists
      type: bool
      sample: true
"""

from typing import ClassVar

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb, samba_user_io
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb, connection_argument_spec, run_or_fail


class SambaUserIO(samba_ldb.SambaObjectIO):
    """LDB read/write operations for users.

    The shared modify, delete and move operations come from
    :class:`samba_ldb.SambaObjectIO`. The ``samba``/``ldb`` bindings are
    imported lazily (via ``samba_ldb.load_ldb``), so importing this module never
    requires them (keeping the static sanity phase green).
    """

    error_cls = logic.SambaUserError
    noun = "user"

    def read_current(self, username):
        """Return the normalized current state of ``username`` or ``None``."""
        ldb = samba_ldb.load_ldb()
        # objectCategory=person keeps computer accounts (also objectClass=user)
        # out, the same match samba_user_info uses.
        expression = f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={ldb.binary_encode(username)}))"
        res = self.samdb.search(
            base=self.samdb.domain_dn(),
            scope=ldb.SCOPE_SUBTREE,
            expression=expression,
            attrs=samba_user_io.USER_ATTRS,
        )
        if len(res) == 0:
            return None
        return samba_user_io.message_to_state(res[0])

    #: Module attributes samba's ``newuser`` sets on the add, mapped to its
    #: keyword arguments (the logic's ``CREATE_ATTRS``).
    _NEWUSER_KWARGS: ClassVar[dict[str, str]] = {
        "given_name": "givenname",
        "surname": "surname",
        "email": "mailaddress",
        "description": "description",
        "uid_number": "uidnumber",
        "gid_number": "gidnumber",
        "unix_home_directory": "unixhome",
        "login_shell": "loginshell",
        "gecos": "gecos",
    }

    def create_user(self, username, password, path, attrs):
        """Create the user with one ``newuser`` call.

        The account is placed under ``path`` and gets the names, mail,
        description and POSIX attributes on the add itself; samba sets the
        password inside its own cleanup guard. Nothing is renamed or modified
        afterwards for these. A concurrent creation (the object already exists
        at write time) is turned into a clear error instead of a raw traceback.
        """
        ldb = samba_ldb.load_ldb()
        kwargs = {self._NEWUSER_KWARGS[name]: value for name, value in attrs.items()}
        try:
            self.samdb.newuser(username, password, userou=self.container_below_domain(path), **kwargs)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_ENTRY_ALREADY_EXISTS:
                raise logic.SambaUserError(
                    f"user '{username}' already exists (created concurrently?)"
                )
            raise

    def apply_attrs(self, dn, attr_changes):
        """Replace or remove the given scalar attributes on the user object.

        Values are written as text (LDB stores the integer POSIX attributes as
        decimal strings too); ``None`` removes the attribute (the caller's
        empty string). Fails cleanly if the object was removed (concurrent
        delete) before the modify reached the DC.
        """
        ldb = samba_ldb.load_ldb()
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, dn)
        replaced = False
        clears = []
        for name, value in attr_changes.items():
            ldap_attr = logic.ATTR_TO_LDAP[name]
            if value is None:
                clears.append(ldap_attr)
                continue
            message[ldap_attr] = ldb.MessageElement(str(value), ldb.FLAG_MOD_REPLACE, ldap_attr)
            replaced = True
        if replaced:
            self._modify(message, dn)
        for ldap_attr in clears:
            self._clear_attr(dn, ldap_attr)

    def _clear_attr(self, dn, ldap_attr):
        """Remove an attribute; one that is already gone is an idempotent no-op."""
        ldb = samba_ldb.load_ldb()
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, dn)
        message[ldap_attr] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, ldap_attr)
        try:
            self._modify(message, dn)
        except ldb.LdbError as err:
            if err.args[0] != ldb.ERR_NO_SUCH_ATTRIBUTE:
                raise

    def set_enabled(self, dn, current_uac, enabled):
        """Toggle the ACCOUNTDISABLE bit of ``userAccountControl``.

        Fails cleanly if the object was removed (concurrent delete) before the
        modify reached the DC.
        """
        ldb = samba_ldb.load_ldb()
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

    def set_password(self, dn, password):
        """Set the password of an existing user.

        Writes ``unicodePwd`` the way samba's ``setpassword`` does (the quoted
        UTF-16 form; the DC enforces the password policy), but by DN: a user
        removed concurrently surfaces as ERR_NO_SUCH_OBJECT and a policy
        rejection as ERR_CONSTRAINT_VIOLATION, both reported cleanly instead
        of as tracebacks (``setpassword`` itself raises a plain Exception for
        a missing user). The password never appears in a message.
        """
        ldb = samba_ldb.load_ldb()
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, dn)
        message["unicodePwd"] = ldb.MessageElement(
            (f'"{password}"').encode("utf-16-le"), ldb.FLAG_MOD_REPLACE, "unicodePwd"
        )
        try:
            self._modify(message, dn)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_CONSTRAINT_VIOLATION:
                raise logic.SambaUserError(
                    f"the domain password policy rejected the new password for '{dn}'"
                )
            raise


def main():
    """Module entry point."""
    argument_spec = {
        "username": {"type": "str", "required": True, "aliases": ["name", "samaccountname"]},
        "given_name": {"type": "str"},
        "surname": {"type": "str"},
        "display_name": {"type": "str"},
        "email": {"type": "str"},
        "description": {"type": "str"},
        "uid_number": {"type": "int"},
        "gid_number": {"type": "int"},
        "unix_home_directory": {"type": "str"},
        "login_shell": {"type": "str"},
        "gecos": {"type": "str"},
        "enabled": {"type": "bool"},
        "password": {"type": "str", "no_log": True},
        "update_password": {"type": "str", "default": "on_create", "choices": ["on_create", "always"]},
        "path": {"type": "str"},
        "state": {"type": "str", "default": "present", "choices": ["present", "absent"]},
    }
    argument_spec.update(connection_argument_spec())
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)
    user_io = SambaUserIO(samdb)

    result = run_or_fail(module, "samba_user", (logic.SambaUserError,), lambda: logic.run(module.params, module.check_mode, user_io))

    module.exit_json(**result)


if __name__ == "__main__":
    main()
