#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to manage groups in a Samba AD DC via the python bindings."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_group
short_description: Manage groups in a Samba AD DC
version_added: 0.1.0
extends_documentation_fragment:
  - jomrr.samba.connection
description:
  - Create, modify and remove groups in a Samba Active Directory Domain
    Controller, including their type (scope and category) and membership.
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
      - The name of the group (its C(sAMAccountName)).
    type: str
    required: true
    aliases:
      - samaccountname
  scope:
    description:
      - The group scope. Together with I(category) it determines the
        C(groupType) attribute.
    type: str
    default: global
    choices:
      - global
      - domain_local
      - universal
  category:
    description:
      - The group category. Together with I(scope) it determines the
        C(groupType) attribute.
    type: str
    default: security
    choices:
      - security
      - distribution
  description:
    description:
      - A free-form description of the group, mapped to the LDAP C(description)
        attribute.
    type: str
  gid_number:
    description:
      - The POSIX group ID, mapped to the RFC2307 C(gidNumber) attribute.
      - Requires a domain provisioned with C(--use-rfc2307); setting it on a
        domain without RFC2307 fails before any change is made.
    type: int
  members:
    description:
      - Members of the group, given by their C(sAMAccountName) (users, groups
        or computers). The module resolves each name to its DN.
      - If omitted, membership is not managed at all.
      - See I(members_purge) for additive versus authoritative behaviour.
    type: list
    elements: str
  members_purge:
    description:
      - If C(false) (default), I(members) are added if missing; members not
        listed are left in place (additive).
      - If C(true), I(members) is the authoritative set; members not listed are
        removed.
    type: bool
    default: false
  path:
    description:
      - The distinguished name of the container or OU the group should live in,
        for example C(OU=Groups,DC=example,DC=com). The parent must already
        exist.
      - When omitted, the group is placed in (and, if it exists elsewhere,
        moved to) the domain's default Users container (C(CN=Users,<domain>)).
      - On an existing group a differing location triggers an idempotent move
        (rename); the comparison is a normalized DN comparison, so only a real
        change moves the object.
    type: str
  state:
    description:
      - Whether the group should exist (C(present)) or not (C(absent)).
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
- name: Ensure a global security group exists with members
  jomrr.samba.samba_group:
    name: engineers
    scope: global
    category: security
    description: Engineering staff
    members:
      - jdoe
      - asmith
    state: present

- name: Make the membership authoritative (remove anyone not listed)
  jomrr.samba.samba_group:
    name: engineers
    members:
      - jdoe
    members_purge: true

- name: Create a universal distribution group
  jomrr.samba.samba_group:
    name: announce
    scope: universal
    category: distribution

- name: Set the POSIX gid (domain provisioned with --use-rfc2307)
  jomrr.samba.samba_group:
    name: engineers
    gid_number: 10000

- name: Remove a group
  jomrr.samba.samba_group:
    name: engineers
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
group:
  description: The resulting group state.
  returned: success
  type: dict
  contains:
    name:
      description: The name of the group.
      returned: always
      type: str
      sample: engineers
    state:
      description: Whether the group exists after the run.
      returned: always
      type: str
      sample: present
    dn:
      description: The distinguished name of the group object.
      returned: when the group exists
      type: str
      sample: CN=engineers,CN=Users,DC=example,DC=com
    scope:
      description: The group scope.
      returned: when the group exists
      type: str
      sample: global
    category:
      description: The group category.
      returned: when the group exists
      type: str
      sample: security
    description:
      description: The description of the group.
      returned: when the group exists
      type: str
      sample: Engineering staff
    gid_number:
      description: The POSIX group ID (C(gidNumber)), or null if unset.
      returned: when the group exists
      type: int
      sample: 10000
    members:
      description: The distinguished names of the group members.
      returned: when the group exists
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


class SambaGroupIO:
    """LDB read/write operations for groups.

    The samba/ldb bindings are imported lazily (via the shared
    ``samba_user_io.load_ldb``), so importing this module never requires them.
    """

    def __init__(self, samdb):
        self.samdb = samdb

    def read_current(self, name):
        """Return the normalized current state of group ``name`` or ``None``."""
        ldb = samba_user_io.load_ldb()
        expression = "(&(objectClass=group)(sAMAccountName=%s))" % ldb.binary_encode(name)
        res = self.samdb.search(
            base=self.samdb.domain_dn(),
            scope=ldb.SCOPE_SUBTREE,
            expression=expression,
            attrs=samba_group_io.GROUP_ATTRS,
        )
        if len(res) == 0:
            return None
        return samba_group_io.message_to_state(res[0])

    def resolve_member(self, name):
        """Resolve a member's sAMAccountName to its DN; the name is escaped."""
        ldb = samba_user_io.load_ldb()
        expression = "(sAMAccountName=%s)" % ldb.binary_encode(name)
        res = self.samdb.search(
            base=self.samdb.domain_dn(),
            scope=ldb.SCOPE_SUBTREE,
            expression=expression,
            attrs=["distinguishedName"],
        )
        if len(res) == 0:
            raise logic.SambaGroupError("member '%s' not found" % name)
        return str(res[0].dn)

    def create_group(self, name, group_type_value, description):
        """Create the group object via samba's newgroup."""
        ldb = samba_user_io.load_ldb()
        try:
            self.samdb.newgroup(name, grouptype=group_type_value, description=description)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_ENTRY_ALREADY_EXISTS:
                raise logic.SambaGroupError(
                    "group '%s' already exists (created concurrently?)" % name
                )
            raise

    def set_description(self, dn, description):
        """Replace the description attribute, mapping a vanished object cleanly."""
        ldb = samba_user_io.load_ldb()
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, dn)
        message["description"] = ldb.MessageElement(description, ldb.FLAG_MOD_REPLACE, "description")
        self._modify(message, dn)

    def set_gid_number(self, dn, gid_number):
        """Replace the gidNumber (RFC2307 POSIX gid), written as decimal text.

        Fails cleanly if the object was removed (concurrent delete) before the
        modify reached the DC.
        """
        ldb = samba_user_io.load_ldb()
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, dn)
        message["gidNumber"] = ldb.MessageElement(str(gid_number), ldb.FLAG_MOD_REPLACE, "gidNumber")
        self._modify(message, dn)

    def rfc2307_provisioned(self):
        """True if the domain was provisioned with C(--use-rfc2307)."""
        return samba_user_io.rfc2307_provisioned(self.samdb)

    def set_group_type(self, dn, group_type_value):
        """Replace the groupType. A rejected scope/category change fails cleanly."""
        ldb = samba_user_io.load_ldb()
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, dn)
        message["groupType"] = ldb.MessageElement(
            logic.normalise_int32(group_type_value), ldb.FLAG_MOD_REPLACE, "groupType"
        )
        try:
            self.samdb.modify(message)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                raise logic.SambaGroupError("group '%s' vanished before it could be modified" % dn)
            if err.args[0] in (ldb.ERR_UNWILLING_TO_PERFORM, ldb.ERR_CONSTRAINT_VIOLATION):
                raise logic.SambaGroupError(
                    "samba rejected the scope/category change for group '%s'" % dn
                )
            raise

    def add_member(self, group_dn, member_dn):
        """Add a member DN. Returns False if it was already a member (no-op)."""
        return self._member_op(group_dn, member_dn, add=True)

    def remove_member(self, group_dn, member_dn):
        """Remove a member DN. Returns False if it was already absent (no-op)."""
        return self._member_op(group_dn, member_dn, add=False)

    def delete_group(self, dn):
        """Delete the group by DN. Returns False if it was already gone (no-op)."""
        ldb = samba_user_io.load_ldb()
        try:
            self.samdb.delete(ldb.Dn(self.samdb, dn))
            return True
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                return False
            raise

    def _member_op(self, group_dn, member_dn, add):
        """Add or remove one member; concurrent-change races become no-ops."""
        ldb = samba_user_io.load_ldb()
        flag = ldb.FLAG_MOD_ADD if add else ldb.FLAG_MOD_DELETE
        already = ldb.ERR_ATTRIBUTE_OR_VALUE_EXISTS if add else ldb.ERR_NO_SUCH_ATTRIBUTE
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, group_dn)
        message["member"] = ldb.MessageElement(member_dn, flag, "member")
        try:
            self.samdb.modify(message)
            return True
        except ldb.LdbError as err:
            if err.args[0] == already:
                return False
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                raise logic.SambaGroupError("group '%s' vanished before its membership could be changed" % group_dn)
            raise

    def _modify(self, message, dn):
        """Apply an LDB modify, mapping a vanished object to a clear error."""
        ldb = samba_user_io.load_ldb()
        try:
            self.samdb.modify(message)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                raise logic.SambaGroupError("group '%s' vanished before it could be modified" % dn)
            raise

    def _desired_parent(self, path):
        """Return the desired parent DN (path, or the default Users container)."""
        if path is None:
            return samba_user_io.default_users_dn(self.samdb)
        try:
            return samba_user_io.parse_dn(self.samdb, path)
        except ValueError:
            raise logic.SambaGroupError("path '%s' is not a valid distinguished name" % path)

    def parent_exists(self, path):
        """Return True if the desired parent container exists."""
        return samba_user_io.dn_exists(self.samdb, self._desired_parent(path))

    def needs_move(self, current_dn, path):
        """Return True if the object's parent differs from the desired location."""
        return not samba_user_io.same_parent(self.samdb, current_dn, self._desired_parent(path))

    def move(self, current_dn, path):
        """Move (rename) the group under the desired parent, preserving its RDN."""
        ldb = samba_user_io.load_ldb()
        target = samba_user_io.reparent_dn(self.samdb, current_dn, self._desired_parent(path))
        try:
            self.samdb.rename(samba_user_io.parse_dn(self.samdb, current_dn), target)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                raise logic.SambaGroupError("group vanished before it could be moved")
            if err.args[0] == ldb.ERR_ENTRY_ALREADY_EXISTS:
                raise logic.SambaGroupError("an object already exists at the target location")
            raise
        return str(target)


def main():
    """Module entry point."""
    argument_spec = dict(
        name=dict(type="str", required=True, aliases=["samaccountname"]),
        scope=dict(type="str", default="global", choices=["global", "domain_local", "universal"]),
        category=dict(type="str", default="security", choices=["security", "distribution"]),
        description=dict(type="str"),
        gid_number=dict(type="int"),
        members=dict(type="list", elements="str"),
        members_purge=dict(type="bool", default=False),
        path=dict(type="str"),
        state=dict(type="str", default="present", choices=["present", "absent"]),
    )
    argument_spec.update(connection_argument_spec())
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)
    group_io = SambaGroupIO(samdb)

    try:
        result = logic.run(module.params, module.check_mode, group_io)
    except logic.SambaGroupError as exc:
        module.fail_json(msg=to_native(exc))
    except Exception as exc:
        module.fail_json(
            msg="samba_group failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
