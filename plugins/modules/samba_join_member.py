#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to join a host as a Samba AD member server via the bindings."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_join_member
short_description: Join a host to an existing domain as a Samba AD member server
version_added: 0.1.0
description:
  - Join the local host to an existing Active Directory domain as a member
    server (authenticating against the domain through winbind), using the native
    C(samba) Python bindings (C(samba.net_s3)), not a C(samba-tool) subprocess.
  - This is a setup module and runs B(locally on the host that is joining) (for
    example with C(delegate_to) the joining host); there is no remote mode and
    it is not part of the C(jomrr.samba.all) action group.
  - It performs B(only) the member-join act and its idempotency detection. It
    does B(not) template smb.conf, configure idmap, wire up nsswitch/PAM, or
    enable or start the winbind daemon - that is the caller's or a role's
    responsibility. In particular the join requires a B(pre-configured smb.conf)
    that already sets C(realm), C(workgroup) and C(server role = member server);
    the module joins against that configuration, it does not write it.
  - Idempotency is binary and uses C(net ads testjoin). If the host is already a
    valid member the run is a no-op (C(changed=false)); otherwise it is joined.
    There is no "member of a different domain" case - the domain is fixed by the
    smb.conf - so a re-join simply re-establishes the machine account.
  - Only C(state=present) is supported. Leaving a domain is not offered.
  - Supports check mode - it reads whether the host is already a member and
    reports C(changed) accordingly, but joining itself cannot be performed in
    check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run locally on the host that is to become a member, with the C(samba)
    Python bindings and the C(net) binary installed, typically as root, with a
    pre-configured smb.conf (C(realm), C(workgroup), C(server role = member
    server)) and network/Kerberos/DNS reachability to the existing DC.
options:
  realm:
    description:
      - The Kerberos realm (DNS domain) of the domain to join, for example
        C(SAMDOM.EXAMPLE.COM).
    type: str
    required: true
  server:
    description:
      - The existing domain controller to join against, for example
        C(dc1.samdom.example.com).
    type: str
    required: true
  bind_username:
    description:
      - A domain account with permission to join a member (typically a Domain
        Admin or an account delegated the right to create computer objects), for
        example C(Administrator).
    type: str
    required: true
  bind_password:
    description:
      - The password for O(bind_username).
      - Required when the host is joined (it is not needed when the host is
        already a valid member and the run is a no-op).
      - B(Security) - always pass this through Ansible Vault or an external
        secret store. It is marked C(no_log), is passed to samba only through the
        credentials object (never on a command line) and never appears in the
        return value, diff or an error.
    type: str
  machinepass:
    description:
      - An explicit machine-account password to set for this member. If omitted,
        samba generates a strong random machine password (the recommended
        default).
      - B(Security) - marked C(no_log); never appears in the return value, diff
        or an error.
    type: str
  state:
    description:
      - Whether the host should be a member of the domain (C(present)). Only
        C(present) is supported; there is no C(absent).
    type: str
    default: present
    choices:
      - present
notes:
  - This module must be executed on the host that is joining; it acts on the
    local machine and has no remote/connection options.
  - It performs only the join; a pre-configured smb.conf and all of idmap,
    nsswitch/PAM and the winbind daemon are out of scope (a role or the caller
    does that).
seealso:
  - module: jomrr.samba.samba_join_dc
    description: Join a host as an additional domain controller instead of a member.
  - module: jomrr.samba.samba_provision
    description: Provision a brand-new domain instead of joining an existing one.
"""

EXAMPLES = r"""
- name: Join the local host as a member server of an existing domain
  jomrr.samba.samba_join_member:
    realm: SAMDOM.EXAMPLE.COM
    server: dc1.samdom.example.com
    bind_username: Administrator
    bind_password: "{{ vault_domain_admin_password }}"
    state: present

- name: Join as a member with an explicit machine-account password
  jomrr.samba.samba_join_member:
    realm: SAMDOM.EXAMPLE.COM
    server: dc1.samdom.example.com
    bind_username: Administrator
    bind_password: "{{ vault_domain_admin_password }}"
    machinepass: "{{ vault_machine_password }}"
    state: present
"""

RETURN = r"""
joined:
  description: Whether the host is a member of the domain after the run.
  returned: success
  type: bool
  sample: true
domain:
  description:
    - The joined domain's non-secret identifiers.
    - Null in check mode when the host is not yet a member (the join would
      happen, but no data is produced without performing it).
  returned: success
  type: dict
  contains:
    workgroup:
      description: The NetBIOS (short) domain name the host is a member of.
      returned: when the host is a member
      type: str
      sample: SAMDOM
    netbios_name:
      description: The NetBIOS computer name of this member.
      returned: when the host is a member
      type: str
      sample: MEMBER1
    domainsid:
      description: The domain security identifier (SID).
      returned: when the join is performed
      type: str
      sample: S-1-5-21-1234567890-1234567890-1234567890
"""

import importlib
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import fail_without_bindings
from ansible_collections.jomrr.samba.plugins.module_utils import samba_join_member_logic as logic


class SambaJoinMemberIO:
    """Member-join operations via the ``samba.net_s3`` bindings.

    All ``samba`` imports are lazy (``importlib.import_module`` inside the
    methods), so importing this module never requires the bindings - the same
    pattern as samba_conn. This module is local-only: it probes membership with
    ``net ads testjoin`` (which uses the stored machine secret, so no credentials
    touch the command line) and joins the local host as a member; the join
    credentials reach the existing DC through the credentials object, not a
    command line.
    """

    def __init__(self, module):
        self.module = module

    def _testjoin_rc(self):
        """Return the rc of ``net ads testjoin`` (0 = a valid member)."""
        net_bin = self.module.get_bin_path("net", required=True)
        # testjoin validates the machine account using the secret in secrets.tdb;
        # it needs no bind credentials, so nothing sensitive is ever on argv.
        rc, dummy_out, dummy_err = self.module.run_command([net_bin, "ads", "testjoin"])
        return rc

    def read_state(self):
        """Return the member identity if joined, else None.

        Membership is the rc of ``net ads testjoin`` (not message matching). When
        a member, the non-secret identity is read from the configured smb.conf.
        """
        if self._testjoin_rc() != 0:
            return None
        param = importlib.import_module("samba.param")
        load_parm = param.LoadParm()
        load_parm.load_default()
        return {
            "workgroup": load_parm.get("workgroup"),
            "netbios_name": load_parm.get("netbios name"),
        }

    def join(self, params):
        """Join the local host as a member and return its non-secret identity.

        Mirrors the verified C(samba-tool domain join MEMBER) path: build the s3
        ``LoadParm`` from the existing smb.conf and call
        ``net_s3.Net(creds, s3_lp, server).join_member(netbios_name, machinepass)``.
        The bind password reaches samba only through the credentials object (never
        an argv); C(machinepass=None) is the verified-safe default samba-tool
        itself passes (the binding generates a strong machine password). A failure
        is turned into a clear error instead of a raw traceback.
        """
        net_s3 = importlib.import_module("samba.net_s3")
        credentials = importlib.import_module("samba.credentials")
        param = importlib.import_module("samba.param")
        s3param = importlib.import_module("samba.samba3.param")

        load_parm = param.LoadParm()
        load_parm.load_default()

        # join_member()'s first positional is the member's NetBIOS name and must
        # not be None (the same class of binding guard as join_DC's netbios_name),
        # so derive the loadparm/hostname default samba-tool uses.
        netbios_name = load_parm.get("netbios name")

        creds = credentials.Credentials()
        creds.guess(load_parm)
        creds.set_username(params["bind_username"])
        creds.set_password(params["bind_password"])
        creds.set_realm(params["realm"])

        smb_conf = load_parm.configfile or param.default_path()
        s3_lp = s3param.get_context()
        s3_lp.load(smb_conf)

        net = net_s3.Net(creds, s3_lp, server=params["server"])
        try:
            sid, domain_name = net.join_member(netbios_name, machinepass=params["machinepass"])
        except logic.SambaJoinMemberError:
            raise
        except Exception as exc:
            raise logic.SambaJoinMemberError("joining the domain failed: %s" % to_native(exc))

        return {
            "workgroup": to_native(domain_name),
            "netbios_name": to_native(netbios_name),
            "domainsid": to_native(sid),
        }


def main():
    """Module entry point."""
    argument_spec = dict(
        realm=dict(type="str", required=True),
        server=dict(type="str", required=True),
        bind_username=dict(type="str", required=True),
        bind_password=dict(type="str", no_log=True),
        machinepass=dict(type="str", no_log=True),
        state=dict(type="str", default="present", choices=["present"]),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    fail_without_bindings(module)
    join_io = SambaJoinMemberIO(module)

    try:
        result = logic.run(module.params, module.check_mode, join_io)
    except logic.SambaJoinMemberError as exc:
        module.fail_json(msg=to_native(exc))
    except Exception as exc:
        module.fail_json(
            msg="samba_join_member failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
