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
  - The module is idempotent and supports check mode. Only options that are
    explicitly set are compared and changed; in particular the type of an
    existing group changes only when I(scope) or I(category) is given, so a
    task that merely updates the description of a built-in group such as
    C(DnsAdmins) never tries to convert it.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - The C(samba) Python bindings (C(python3-samba)) on the host that runs the
    module.
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
      - If omitted, a new group is created as C(global) and the scope of an
        existing group is left unchanged.
    type: str
    choices:
      - global
      - domain_local
      - universal
  category:
    description:
      - The group category. Together with I(scope) it determines the
        C(groupType) attribute.
      - If omitted, a new group is created as C(security) and the category of
        an existing group is left unchanged.
    type: str
    choices:
      - security
      - distribution
  description:
    description:
      - A free-form description of the group, mapped to the LDAP C(description)
        attribute.
      - Set to an empty string to remove the description.
    type: str
  gid_number:
    description:
      - The POSIX group ID, mapped to the RFC2307 C(gidNumber) attribute.
      - Requires a domain provisioned with C(--use-rfc2307); setting it on a
        domain without RFC2307 fails before any change is made.
    type: int
  members:
    description:
      - Members of the group, each given by its C(sAMAccountName) (users,
        groups or computers) or by its distinguished name (any value that
        contains C(=), which a C(sAMAccountName) cannot). Names are resolved
        to DNs; DNs are checked to exist.
      - M(jomrr.samba.samba_group_info) returns members as distinguished
        names, so its output can be fed back here unchanged.
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
seealso:
  - module: jomrr.samba.samba_group_info
    description: Query groups from a Samba AD DC.
notes:
  - The DC is reached over the network, so the module does not have to run on a
    domain controller. Any host with the C(samba) bindings that can reach
    O(server) over LDAP and obtain a Kerberos ticket for its realm will do;
    running on the DC itself, with O(server) pointing at it, is the simplest
    topology.
  - Creating a group is all-or-nothing. The group is added in a single
    operation, placed under I(path) with its type, description and
    I(gid_number); members are added afterwards. LDAP offers no transactions,
    so if adding a member fails, the module removes the group it just created
    and fails with the cause. Changes to an existing group are separate
    LDAP operations; if one fails, the earlier ones stay applied and a re-run
    completes the rest.
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

- name: Update the description of a built-in group (its domain-local type stays untouched)
  jomrr.samba.samba_group:
    name: DnsAdmins
    description: DNS administrators

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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.samba.plugins.module_utils import samba_group_io, samba_ldb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_group_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb, connection_argument_spec, run_or_fail


class SambaGroupIO(samba_ldb.SambaObjectIO):
    """LDB read/write operations for groups.

    The shared modify, delete and move operations come from
    :class:`samba_ldb.SambaObjectIO`; the samba/ldb bindings are imported lazily
    (via ``samba_ldb.load_ldb``), so importing this module never requires them.
    """

    error_cls = logic.SambaGroupError
    noun = "group"

    def read_current(self, name):
        """Return the normalized current state of group ``name`` or ``None``."""
        ldb = samba_ldb.load_ldb()
        expression = f"(&(objectClass=group)(sAMAccountName={ldb.binary_encode(name)}))"
        res = self.samdb.search(
            base=self.samdb.domain_dn(),
            scope=ldb.SCOPE_SUBTREE,
            expression=expression,
            attrs=samba_group_io.GROUP_ATTRS,
        )
        if len(res) == 0:
            return None
        return samba_group_io.message_to_state(res[0])

    #: Names resolved per LDAP search; keeps the OR filter of a large member
    #: list bounded.
    _RESOLVE_BATCH = 200

    def resolve_members(self, members):
        """Resolve member references to DNs.

        A member is a sAMAccountName or, when it contains ``=`` (a character a
        sAMAccountName cannot hold), a distinguished name - the form
        samba_group_info returns, so its output can be fed back. Names are
        resolved with one search per batch (an OR filter, every name escaped)
        instead of one per member; DNs are checked with one base-scoped read
        each and taken in the directory's own spelling. The DNs come back in
        the order given; members that do not exist are reported together in
        one error. sAMAccountName matches case-insensitively, so results are
        mapped back by lower-cased name, which is why that attribute (and only
        it) is requested.
        """
        ldb = samba_ldb.load_ldb()
        wanted = list(dict.fromkeys(members))
        found = {}
        names = []
        for member in wanted:
            if "=" not in member:
                names.append(member)
                continue
            try:
                dn = samba_ldb.parse_dn(self.samdb, member)
            except ValueError:
                raise logic.SambaGroupError(f"member '{member}' is not a valid distinguished name")
            stored = samba_ldb.lookup_dn(self.samdb, dn)
            if stored is not None:
                found[member.lower()] = stored
        for start in range(0, len(names), self._RESOLVE_BATCH):
            batch = names[start:start + self._RESOLVE_BATCH]
            expression = "(|{})".format("".join(
                f"(sAMAccountName={ldb.binary_encode(member)})" for member in batch
            ))
            res = self.samdb.search(
                base=self.samdb.domain_dn(),
                scope=ldb.SCOPE_SUBTREE,
                expression=expression,
                attrs=["sAMAccountName"],
            )
            for message in res:
                account = samba_ldb.first_value(message, "sAMAccountName") or ""
                found[account.lower()] = str(message.dn)
        missing = [member for member in wanted if member.lower() not in found]
        if missing:
            raise logic.SambaGroupError("members not found: {}".format(", ".join(missing)))
        return [found[member.lower()] for member in members]

    def create_group(self, name, group_type_value, description, path, gid_number):
        """Create the group with one ``newgroup`` call.

        The group is placed under ``path`` and gets its type, description and
        gidNumber on the add itself; nothing is renamed or modified afterwards
        for these. A concurrent creation is turned into a clear error.
        """
        ldb = samba_ldb.load_ldb()
        try:
            self.samdb.newgroup(
                name, groupou=self.container_below_domain(path), grouptype=group_type_value,
                description=description, gidnumber=gid_number,
            )
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_ENTRY_ALREADY_EXISTS:
                raise logic.SambaGroupError(
                    f"group '{name}' already exists (created concurrently?)"
                )
            raise

    def set_description(self, dn, description):
        """Replace the description, or remove it when ``description`` is None.

        Removing a description that is already gone is an idempotent no-op; a
        vanished object fails cleanly.
        """
        ldb = samba_ldb.load_ldb()
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, dn)
        if description is None:
            message["description"] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "description")
        else:
            message["description"] = ldb.MessageElement(description, ldb.FLAG_MOD_REPLACE, "description")
        try:
            self._modify(message, dn)
        except ldb.LdbError as err:
            if description is not None or err.args[0] != ldb.ERR_NO_SUCH_ATTRIBUTE:
                raise

    def set_gid_number(self, dn, gid_number):
        """Replace the gidNumber (RFC2307 POSIX gid), written as decimal text.

        Fails cleanly if the object was removed (concurrent delete) before the
        modify reached the DC.
        """
        ldb = samba_ldb.load_ldb()
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, dn)
        message["gidNumber"] = ldb.MessageElement(str(gid_number), ldb.FLAG_MOD_REPLACE, "gidNumber")
        self._modify(message, dn)

    def set_group_type(self, dn, group_type_value):
        """Replace the groupType. A rejected scope/category change fails cleanly."""
        ldb = samba_ldb.load_ldb()
        message = ldb.Message()
        message.dn = ldb.Dn(self.samdb, dn)
        message["groupType"] = ldb.MessageElement(
            logic.normalise_int32(group_type_value), ldb.FLAG_MOD_REPLACE, "groupType"
        )
        try:
            self._modify(message, dn)
        except ldb.LdbError as err:
            if err.args[0] in (ldb.ERR_UNWILLING_TO_PERFORM, ldb.ERR_CONSTRAINT_VIOLATION):
                raise logic.SambaGroupError(
                    f"samba rejected the scope/category change for group '{dn}'"
                )
            raise

    def add_member(self, group_dn, member_dn):
        """Add a member DN. Returns False if it was already a member (no-op)."""
        return self._member_op(group_dn, member_dn, add=True)

    def remove_member(self, group_dn, member_dn):
        """Remove a member DN. Returns False if it was already absent (no-op)."""
        return self._member_op(group_dn, member_dn, add=False)

    def _member_op(self, group_dn, member_dn, add):
        """Add or remove one member; concurrent-change races become no-ops."""
        ldb = samba_ldb.load_ldb()
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
                raise logic.SambaGroupError(f"group '{group_dn}' vanished before its membership could be changed")
            raise


def main():
    """Module entry point."""
    argument_spec = {
        "name": {"type": "str", "required": True, "aliases": ["samaccountname"]},
        "scope": {"type": "str", "choices": ["global", "domain_local", "universal"]},
        "category": {"type": "str", "choices": ["security", "distribution"]},
        "description": {"type": "str"},
        "gid_number": {"type": "int"},
        "members": {"type": "list", "elements": "str"},
        "members_purge": {"type": "bool", "default": False},
        "path": {"type": "str"},
        "state": {"type": "str", "default": "present", "choices": ["present", "absent"]},
    }
    argument_spec.update(connection_argument_spec())
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)
    group_io = SambaGroupIO(samdb)

    result = run_or_fail(module, "samba_group", (logic.SambaGroupError,), lambda: logic.run(module.params, module.check_mode, group_io))

    module.exit_json(**result)


if __name__ == "__main__":
    main()
