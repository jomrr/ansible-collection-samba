# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to manage the domain password policy of a Samba AD DC."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_password_policy
short_description: Manage the domain password policy of a Samba AD DC
version_added: 2.0.0
extends_documentation_fragment:
  - jomrr.samba.connection
  - jomrr.samba.password_settings
description:
  - Manage the domain's password and lockout policy, the attributes of the
    domain object that C(samba-tool domain passwordsettings) manages.
  - Talks to the directory through the native C(samba) Python bindings
    (C(samba.samdb.SamDB) over LDAP), not through C(samba-tool) subprocesses.
  - Only the settings given are compared and changed; the other bits of the
    domain's C(pwdProperties) flag word are preserved.
  - The module is idempotent and supports check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - The C(samba) Python bindings (C(python3-samba)) on the host that runs the
    module.
seealso:
  - module: jomrr.samba.samba_password_settings
    description: Manage fine-grained password settings objects (PSOs).
notes:
  - The DC is reached over the network, so the module does not have to run on a
    domain controller. Any host with the C(samba) bindings that can reach
    O(server) over LDAP and obtain a Kerberos ticket for its realm will do;
    running on the DC itself, with O(server) pointing at it, is the simplest
    topology.
  - Ages and timers are stored as the directory's negative 100-nanosecond ticks,
    encoded exactly as C(samba-tool) does; C(maximum_age_days=0) and the lockout
    timers at C(0) become the directory's "never".
"""

EXAMPLES = r"""
- name: Require longer passwords and lock accounts after five failed sign-ins
  jomrr.samba.samba_password_policy:
    server: dc1.example.com
    bind_username: Administrator
    bind_password: "{{ vault_dc_admin_password }}"
    settings:
      minimum_length: 12
      history_length: 24
      maximum_age_days: 90
      lockout_threshold: 5
      lockout_duration_minutes: 30
      lockout_window_minutes: 30
      complexity: true

- name: Let passwords never expire, touching nothing else
  jomrr.samba.samba_password_policy:
    server: dc1.example.com
    bind_username: Administrator
    bind_password: "{{ vault_dc_admin_password }}"
    settings:
      maximum_age_days: 0
"""

RETURN = r"""
dn:
  description: The distinguished name of the domain object that carries the policy.
  returned: success
  type: str
  sample: DC=example,DC=com
settings:
  description: The policy after the run, every setting whether given or not.
  returned: success
  type: dict
  contains:
    minimum_length:
      description: Minimum password length in characters.
      returned: always
      type: int
      sample: 12
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
      sample: 90
    lockout_threshold:
      description: Failed sign-ins before lockout; C(0) means no lockout.
      returned: always
      type: int
      sample: 5
    lockout_duration_minutes:
      description: Lockout duration in minutes; C(0) means until an administrator unlocks.
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
        "settings": {"type": "dict", "default": {}, "options": logic.settings_argument_spec()},
    }
    argument_spec.update(connection_argument_spec())
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    samdb = connect_samdb(module)
    policy_io = PasswordPolicyIO(samdb)

    result = run_or_fail(
        module, "samba_password_policy", (logic.SambaPasswordPolicyError,),
        lambda: logic.run_domain(module.params, module.check_mode, policy_io),
    )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
