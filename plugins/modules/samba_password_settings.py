# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to manage fine-grained password settings objects in a Samba AD DC."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_password_settings
short_description: Manage fine-grained password settings objects (PSOs) in a Samba AD DC
version_added: 2.0.0
extends_documentation_fragment:
  - jomrr.samba.connection
  - jomrr.samba.password_settings
description:
  - Create, modify and remove fine-grained password settings objects (PSOs,
    C(msDS-PasswordSettings)) and manage the exact set of users and global
    security groups they apply to, as C(samba-tool domain passwordsettings pso)
    does.
  - Talks to the directory through the native C(samba) Python bindings
    (C(samba.samdb.SamDB) over LDAP), not through C(samba-tool) subprocesses.
  - A new PSO copies every setting not given from the domain policy; an
    existing PSO keeps its own values for settings not given.
  - The module is idempotent and supports check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - The C(samba) Python bindings (C(python3-samba)) on the host that runs the
    module.
options:
  name:
    description:
      - The name of the PSO (its C(CN) below the Password Settings Container).
    type: str
    required: true
  precedence:
    description:
      - The policy's priority when several PSOs apply to a user; the lowest
        value wins.
      - Required when O(state=present).
    type: int
  applies_to:
    description:
      - The exact set of users and global security groups the PSO applies to,
        each given by its C(sAMAccountName) or its distinguished name.
      - Subjects not listed are removed; an empty list removes every assignment.
      - PSOs apply to users and global security groups only, not to
        organizational units.
    type: list
    elements: str
    default: []
  state:
    description:
      - Whether the PSO should exist (C(present)) or not (C(absent)).
    type: str
    default: present
    choices:
      - present
      - absent
seealso:
  - module: jomrr.samba.samba_password_policy
    description: Manage the domain password policy.
notes:
  - The DC is reached over the network, so the module does not have to run on a
    domain controller. Any host with the C(samba) bindings that can reach
    O(server) over LDAP and obtain a Kerberos ticket for its realm will do;
    running on the DC itself, with O(server) pointing at it, is the simplest
    topology.
  - Ages and timers are stored as the directory's negative 100-nanosecond ticks,
    encoded exactly as C(samba-tool) does; C(maximum_age_days=0) becomes the
    directory's "never".
"""

EXAMPLES = r"""
- name: A stricter policy for the domain admins and one service account
  jomrr.samba.samba_password_settings:
    server: dc1.example.com
    bind_username: Administrator
    bind_password: "{{ vault_dc_admin_password }}"
    name: admins
    precedence: 10
    applies_to:
      - Domain Admins
      - svc_backup
    settings:
      minimum_length: 16
      history_length: 24
      maximum_age_days: 60
      complexity: true
    state: present

- name: Remove a fine-grained policy
  jomrr.samba.samba_password_settings:
    server: dc1.example.com
    bind_username: Administrator
    bind_password: "{{ vault_dc_admin_password }}"
    name: admins
    state: absent
"""

RETURN = r"""
dn:
  description: The distinguished name of the PSO.
  returned: success
  type: str
  sample: CN=admins,CN=Password Settings Container,CN=System,DC=example,DC=com
state:
  description: Whether the PSO exists after the run.
  returned: success
  type: str
  sample: present
precedence:
  description: The PSO's priority.
  returned: when the PSO is present
  type: int
  sample: 10
applies_to:
  description: The distinguished names the PSO applies to, sorted.
  returned: when the PSO is present
  type: list
  elements: str
  sample:
    - CN=Domain Admins,CN=Users,DC=example,DC=com
settings:
  description: The PSO's settings after the run, every setting whether given or not.
  returned: when the PSO is present
  type: dict
  contains:
    minimum_length:
      description: Minimum password length in characters.
      returned: always
      type: int
      sample: 16
    history_length:
      description: Number of previous passwords that cannot be reused.
      returned: always
      type: int
      sample: 24
    minimum_age_days:
      description: Minimum password age in days.
      returned: always
      type: int
      sample: 1
    maximum_age_days:
      description: Maximum password age in days; C(0) means never.
      returned: always
      type: int
      sample: 60
    lockout_threshold:
      description: Failed sign-ins before lockout; C(0) means no lockout.
      returned: always
      type: int
      sample: 5
    lockout_duration_minutes:
      description: Lockout duration in minutes.
      returned: always
      type: int
      sample: 30
    lockout_window_minutes:
      description: Minutes after which the failed sign-in counter resets.
      returned: always
      type: int
      sample: 30
    complexity:
      description: Whether password complexity is required.
      returned: always
      type: bool
      sample: true
    reversible_encryption:
      description: Whether passwords are stored with reversible encryption.
      returned: always
      type: bool
      sample: false
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.samba.plugins.module_utils import samba_password_policy_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import connect_samdb, connection_argument_spec, run_or_fail
from ansible_collections.jomrr.samba.plugins.module_utils.samba_password_policy_io import PasswordPolicyIO


def main():
    """Module entry point."""
    argument_spec = {
        "name": {"type": "str", "required": True},
        "precedence": {"type": "int"},
        "applies_to": {"type": "list", "elements": "str", "default": []},
        "settings": {"type": "dict", "default": {}, "options": logic.settings_argument_spec()},
        "state": {"type": "str", "default": "present", "choices": ["present", "absent"]},
    }
    argument_spec.update(connection_argument_spec())
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[("state", "present", ["precedence"])],
    )

    samdb = connect_samdb(module)
    policy_io = PasswordPolicyIO(samdb)

    result = run_or_fail(
        module, "samba_password_settings", (logic.SambaPasswordPolicyError,),
        lambda: logic.run_pso(module.params, module.check_mode, policy_io),
    )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
