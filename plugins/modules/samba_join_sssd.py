#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to join a host to a domain via adcli, writing a keytab for SSSD."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_join_sssd
short_description: Join a host to an existing domain via adcli for SSSD
version_added: 0.1.0
description:
  - Join the local host to an existing Active Directory domain using C(adcli),
    which creates the machine account and writes a Kerberos B(keytab)
    (C(/etc/krb5.keytab)) that SSSD then uses to authenticate to the domain.
  - This is the SSSD branch of the join family. Unlike C(jomrr.samba.samba_join_dc)
    and C(jomrr.samba.samba_join_member) (which use the native C(samba) bindings),
    this module runs the C(adcli) command line tool - there is no Python binding
    for it. It is the one deliberate subprocess in the collection, kept isolated
    to this module.
  - This is a setup module and runs B(locally on the host that is joining) (for
    example with C(delegate_to) the joining host); there is no remote mode and
    it is not part of the C(jomrr.samba.all) action group.
  - It performs B(only) the join act (creating the machine account and writing
    the keytab) and its idempotency detection. It does B(not) write sssd.conf,
    wire up nsswitch/PAM, or enable or start the SSSD daemon - that is the
    caller's or a role's responsibility.
  - Idempotency is binary and decided locally. A machine principal for the
    realm (C(host/<fqdn>) or C(<NAME>$)) in the keytab means the host is joined;
    no domain controller is contacted for that decision, so an unreachable or
    degraded DC can never look like "not joined" and trigger a re-join. A
    joined host is a no-op (C(changed=false)) unless I(force) is set; a re-join
    simply re-establishes the keytab.
  - Only C(state=present) is supported. Leaving a domain is not offered.
  - Supports check mode - it reads whether the host is already joined and reports
    C(changed) accordingly, but joining itself cannot be performed in check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run locally on the host that is joining, with the C(adcli) command line
    tool installed, typically as root, with network/Kerberos/DNS reachability to
    the domain.
options:
  realm:
    description:
      - The Active Directory domain (DNS) to join, for example
        C(SAMDOM.EXAMPLE.COM). Passed to C(adcli --domain).
    type: str
    required: true
  server:
    description:
      - A specific domain controller to join against, for example
        C(dc1.samdom.example.com). If omitted, C(adcli) locates a DC itself via
        DNS SRV records. Passed to C(adcli --domain-controller).
    type: str
  bind_username:
    description:
      - A domain account with permission to join a machine (typically a Domain
        Admin or an account delegated the right to create computer objects), for
        example C(Administrator). Passed to C(adcli --login-user).
    type: str
    required: true
  bind_password:
    description:
      - The password for O(bind_username).
      - Required when the host is joined (it is not needed when the host already
        has a valid machine account and the run is a no-op).
      - B(Security) - always pass this through Ansible Vault or an external
        secret store. It is marked C(no_log), is fed to C(adcli) on B(stdin)
        (C(--stdin-password)), never on the command line (where it would be
        visible in the process list), and never appears in the return value,
        diff or an error.
    type: str
  computer_ou:
    description:
      - The LDAP DN of an organizational unit to create the computer account in,
        for example C(OU=Linux,DC=samdom,DC=example,DC=com). Passed to
        C(adcli --domain-ou). If omitted, the domain default is used.
    type: str
  host_fqdn:
    description:
      - Override the fully qualified domain name for the machine account. Passed
        to C(adcli --host-fqdn). If omitted, C(adcli) derives it from the host.
    type: str
  force:
    description:
      - Join again even though the keytab already holds a machine principal
        for the realm, re-creating the machine account and rewriting the
        keytab (for example after the computer object was deleted on the
        domain).
      - Always reports a change; I(bind_password) is required.
    type: bool
    default: false
    version_added: 2.0.0
  state:
    description:
      - Whether the host should be joined (C(present)). Only C(present) is
        supported; there is no C(absent).
    type: str
    default: present
    choices:
      - present
notes:
  - This module must be executed on the host that is joining; it acts on the
    local machine and has no remote/connection options.
  - It performs only the join; configuring sssd.conf, nsswitch/PAM and the SSSD
    daemon is out of scope (a role or the caller does that).
seealso:
  - module: jomrr.samba.samba_join_dc
    description: Join a host as an additional domain controller.
  - module: jomrr.samba.samba_join_member
    description: Join a host as a Samba member server (winbind, secrets.tdb).
"""

EXAMPLES = r"""
- name: Join the local host to a domain for SSSD
  jomrr.samba.samba_join_sssd:
    realm: SAMDOM.EXAMPLE.COM
    bind_username: Administrator
    bind_password: "{{ vault_domain_admin_password }}"
    state: present

- name: Join against a specific DC, into a dedicated OU
  jomrr.samba.samba_join_sssd:
    realm: SAMDOM.EXAMPLE.COM
    server: dc1.samdom.example.com
    bind_username: Administrator
    bind_password: "{{ vault_domain_admin_password }}"
    computer_ou: OU=Linux,DC=samdom,DC=example,DC=com
    state: present

- name: Re-create the machine account and keytab of an already joined host
  jomrr.samba.samba_join_sssd:
    realm: SAMDOM.EXAMPLE.COM
    bind_username: Administrator
    bind_password: "{{ vault_domain_admin_password }}"
    force: true
    state: present
"""

RETURN = r"""
joined:
  description: Whether the host has a valid machine account after the run.
  returned: success
  type: bool
  sample: true
domain:
  description:
    - The joined domain's non-secret identifiers.
    - Null in check mode when the host is not yet joined (the join would happen,
      but no data is produced without performing it).
  returned: success
  type: dict
  contains:
    realm:
      description: The domain the host is joined to.
      returned: when the host is joined
      type: str
      sample: SAMDOM.EXAMPLE.COM
    keytab:
      description: The Kerberos keytab adcli writes the host credentials to.
      returned: when the host is joined
      type: str
      sample: /etc/krb5.keytab
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils import samba_join_sssd_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils import samba_keytab

#: adcli's default host keytab (used when --host-keytab is not overridden).
KEYTAB_PATH = "/etc/krb5.keytab"


def is_machine_principal(components):
    """True for the principals adcli writes for the host: ``host/<name>`` or ``<NAME>$``."""
    if not components:
        return False
    return components[0].lower() == "host" or (len(components) == 1 and components[0].endswith("$"))


class SambaJoinSssdIO:
    """Join operations via the ``adcli`` command line tool.

    This is the CLI branch of the join family: no samba bindings are imported.
    ``adcli`` is run through ``module.run_command`` for the join only; the
    password is fed on stdin (``--stdin-password`` + ``data=``), never as an
    argv (which would show in the process list). Whether the host is joined is
    read from the keytab adcli writes - locally, without adcli and without a DC.
    """

    def __init__(self, module):
        self.module = module

    def _adcli(self):
        """Return the path to the adcli binary, or fail clearly if absent."""
        adcli = self.module.get_bin_path("adcli")
        if not adcli:
            raise logic.SambaJoinSssdError(
                "adcli was not found in PATH; samba_join_sssd requires the adcli "
                "command (from the 'adcli' package)"
            )
        return adcli

    def read_state(self):
        """Return the join identity if joined, else None.

        The decision is local: the keytab adcli writes holds the host's machine
        principals for the realm (``host/<fqdn>`` and ``<NAME>$``). No DC is
        contacted, so an unreachable or degraded DC can never look like "not
        joined" and trigger a re-join. A missing keytab means "not joined"; an
        unreadable or malformed one is a clear error.
        """
        realm = self.module.params["realm"]
        try:
            principals = samba_keytab.read_principals(KEYTAB_PATH)
        except FileNotFoundError:
            return None
        except OSError as err:
            raise logic.SambaJoinSssdError("cannot read %s: %s" % (KEYTAB_PATH, to_native(err)))
        except samba_keytab.KeytabError as err:
            raise logic.SambaJoinSssdError("cannot parse %s: %s" % (KEYTAB_PATH, to_native(err)))
        joined = any(
            keytab_realm.upper() == realm.upper() and is_machine_principal(components)
            for keytab_realm, components in principals
        )
        if not joined:
            return None
        return {"realm": realm, "keytab": KEYTAB_PATH}

    def join(self, params):
        """Join the host with ``adcli join`` and return its non-secret identity.

        The bind password is written to adcli's stdin (``--stdin-password`` +
        ``data=``), never placed on the command line. Optional parameters are only
        added when set, so adcli's own defaults (DC discovery via DNS SRV, derived
        FQDN, default OU) apply otherwise. A non-zero rc becomes a clear error.
        """
        adcli = self._adcli()
        argv = [
            adcli,
            "join",
            "--domain=%s" % params["realm"],
            "--login-user=%s" % params["bind_username"],
            "--stdin-password",
        ]
        if params.get("server"):
            argv.append("--domain-controller=%s" % params["server"])
        if params.get("host_fqdn"):
            argv.append("--host-fqdn=%s" % params["host_fqdn"])
        if params.get("computer_ou"):
            argv.append("--domain-ou=%s" % params["computer_ou"])

        # data= feeds the password on stdin; it never appears in argv (and so
        # never in the process list). adcli does not echo it in its output.
        rc, dummy_out, err = self.module.run_command(argv, data=params["bind_password"])
        if rc != 0:
            raise logic.SambaJoinSssdError(
                "adcli join failed (rc=%d): %s" % (rc, to_native(err).strip())
            )
        return {"realm": params["realm"], "keytab": KEYTAB_PATH}


def main():
    """Module entry point."""
    argument_spec = dict(
        realm=dict(type="str", required=True),
        server=dict(type="str"),
        bind_username=dict(type="str", required=True),
        bind_password=dict(type="str", no_log=True),
        computer_ou=dict(type="str"),
        host_fqdn=dict(type="str"),
        force=dict(type="bool", default=False),
        state=dict(type="str", default="present", choices=["present"]),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    join_io = SambaJoinSssdIO(module)

    try:
        result = logic.run(module.params, module.check_mode, join_io)
    except logic.SambaJoinSssdError as exc:
        module.fail_json(msg=to_native(exc))
    except Exception as exc:
        module.fail_json(
            msg="samba_join_sssd failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
