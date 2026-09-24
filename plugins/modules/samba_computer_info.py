# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to query computer accounts from a Samba AD DC via the python bindings."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_computer_info
short_description: Query computer accounts from a Samba AD DC
version_added: 2.2.0
extends_documentation_fragment:
  - jomrr.samba.connection
description:
  - Read computer accounts from a Samba Active Directory Domain Controller.
  - Talks to the directory through the native C(samba) Python bindings
    (C(samba.samdb.SamDB)), not through C(samba-tool) subprocesses.
  - This module is read-only; it never changes the directory and always reports
    C(changed=false).
author:
  - Jonas Mauer (@jomrr)
requirements:
  - The C(samba) Python bindings (C(python3-samba)) on the host that runs the
    module.
options:
  name:
    description:
      - Restrict the query to the computer with this name, its
        C(sAMAccountName) without the trailing C($); a trailing C($) is
        accepted as well.
      - If omitted, all computer accounts are returned.
    type: str
seealso:
  - module: jomrr.samba.samba_computer
    description: Keep a computer account in a container of a Samba AD DC.
notes:
  - The DC is reached over the network, so the module does not have to run on a
    domain controller. Any host with the C(samba) bindings that can reach
    O(server) over LDAP and obtain a Kerberos ticket for its realm will do;
    running on the DC itself, with O(server) pointing at it, is the simplest
    topology.
  - Returns the accounts C(jomrr.samba.samba_computer) manages; domain
    controller accounts (DCs and read-only DCs) and managed service accounts
    are excluded.
"""

EXAMPLES = r"""
- name: Look up a single computer
  jomrr.samba.samba_computer_info:
    name: FILESRV1
  register: filesrv1_info

- name: Fetch all computer accounts
  jomrr.samba.samba_computer_info:
  register: all_computers

- name: Show where each computer account lives
  ansible.builtin.debug:
    msg: "{{ all_computers.computers | map(attribute='dn') | list }}"
"""

RETURN = r"""
computers:
  description:
    - The matching computer accounts. Empty when none matched.
  returned: success
  type: list
  elements: dict
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
from ansible_collections.jomrr.samba.plugins.module_utils import samba_computer_io
from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb, connection_argument_spec, run_or_fail


def main():
    """Module entry point."""
    argument_spec = {
        "name": {"type": "str"},
    }
    argument_spec.update(connection_argument_spec())
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)

    computers = run_or_fail(module, "samba_computer_info", (), lambda: samba_computer_io.search(samdb, module.params["name"]))

    module.exit_json(changed=False, computers=computers)


if __name__ == "__main__":
    main()
