# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to keep computer accounts in a container of a Samba AD DC."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_computer
short_description: Keep a computer account in a container of a Samba AD DC
version_added: 2.2.0
extends_documentation_fragment:
  - jomrr.samba.connection
description:
  - Move an existing computer account into the desired container or OU of a
    Samba Active Directory Domain Controller.
  - Talks to the directory through the native C(samba) Python bindings
    (C(samba.samdb.SamDB)), not through C(samba-tool) subprocesses.
  - The module never creates or deletes a computer account. Accounts come from
    a join - C(jomrr.samba.samba_join_member), C(jomrr.samba.samba_join_sssd)
    or a Windows domain join - so one module places every kind of computer.
  - Domain controller accounts (DCs and read-only DCs) are never matched, so a
    domain controller is never moved out of C(OU=Domain Controllers).
  - The module is idempotent and supports check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - The C(samba) Python bindings (C(python3-samba)) on the host that runs the
    module.
options:
  name:
    description:
      - The name of the computer, its C(sAMAccountName) without the trailing
        C($); a trailing C($) is accepted as well.
    type: str
    required: true
  path:
    description:
      - The distinguished name of the container or OU the computer account
        should live in, for example C(OU=Servers,DC=example,DC=com). The parent
        must already exist.
      - When omitted, the account is placed in (and, if it is elsewhere, moved
        to) the domain's default Computers container (C(CN=Computers,<domain>),
        or where it is redirected to).
      - The comparison is a normalized DN comparison, so only a real change
        moves the account; the move is a rename that keeps its RDN.
    type: str
seealso:
  - module: jomrr.samba.samba_computer_info
    description: Query computer accounts from a Samba AD DC.
  - module: jomrr.samba.samba_join_member
    description: Join a host as a member server, creating its account in an OU.
  - module: jomrr.samba.samba_join_sssd
    description: Join a host to an existing domain via adcli for SSSD.
notes:
  - The DC is reached over the network, so the module does not have to run on a
    domain controller. Any host with the C(samba) bindings that can reach
    O(server) over LDAP and obtain a Kerberos ticket for its realm will do;
    running on the DC itself, with O(server) pointing at it, is the simplest
    topology.
  - An account that does not exist is an error, not a no-op; the module places
    accounts, it does not create them.
"""

EXAMPLES = r"""
- name: Keep a member server's account in the Servers OU
  jomrr.samba.samba_computer:
    name: FILESRV1
    path: OU=Servers,DC=example,DC=com

- name: Move a Windows client back to the default Computers container
  jomrr.samba.samba_computer:
    name: WS042
"""

RETURN = r"""
action:
  description:
    - The action that was performed, C(modified) (the account was moved) or
      C(unchanged).
  returned: success
  type: str
  sample: modified
computer:
  description:
    - The computer account after the run; in check mode, where it is before a
      pending move.
  returned: success
  type: dict
  contains:
    name:
      description: The name of the computer, its sAMAccountName without the trailing C($).
      returned: always
      type: str
      sample: FILESRV1
    dn:
      description: The distinguished name of the computer account.
      returned: always
      type: str
      sample: CN=FILESRV1,OU=Servers,DC=example,DC=com
    dns_host_name:
      description: The DNS host name of the computer (C(dNSHostName)), or null if unset.
      returned: always
      type: str
      sample: filesrv1.example.com
    description:
      description: The description of the computer account, or null if unset.
      returned: always
      type: str
      sample: File server
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.samba.plugins.module_utils import samba_computer_io, samba_ldb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_computer_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb, connection_argument_spec, run_or_fail


class SambaComputerIO(samba_ldb.SambaObjectIO):
    """LDB read and move for computer accounts.

    The location checks and the move come from :class:`samba_ldb.SambaObjectIO`;
    only the lookup and the default container (Computers instead of Users) are
    computer-specific. The ``samba``/``ldb`` bindings are imported lazily, so
    importing this module never requires them.
    """

    error_cls = logic.SambaComputerError
    noun = "computer"

    def _default_container_dn(self):
        """Return the default container of computer accounts: the Computers container."""
        return samba_ldb.default_computers_dn(self.samdb)

    def find(self, name):
        """Return the normalized state of the computer ``name``, or None."""
        found = samba_computer_io.search(self.samdb, name)
        return found[0] if found else None


def main():
    """Module entry point."""
    argument_spec = {
        "name": {"type": "str", "required": True},
        "path": {"type": "str"},
    }
    argument_spec.update(connection_argument_spec())
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)
    computer_io = SambaComputerIO(samdb)

    result = run_or_fail(
        module, "samba_computer", (logic.SambaComputerError,),
        lambda: logic.run(module.params, module.check_mode, computer_io),
    )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
