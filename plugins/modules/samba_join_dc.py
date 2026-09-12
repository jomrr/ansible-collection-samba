#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to join a host as an additional Samba AD DC via the bindings."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_join_dc
short_description: Join a host to an existing domain as an additional Samba AD DC
version_added: 0.1.0
description:
  - Join the local host to an existing Active Directory domain as an additional
    Samba Domain Controller, through the native C(samba) Python bindings
    (C(samba.join)), not through C(samba-tool) subprocesses.
  - This is a setup module and runs B(locally on the host that is joining) (for
    example with C(delegate_to) the joining host); there is no remote mode and
    it is not part of the C(jomrr.samba.all) action group.
  - It performs B(only) the DC-join act and its idempotency detection. It does
    not template smb.conf, enable or start the C(samba) daemon, or wire up any
    host service stack - that is the caller's or a role's responsibility.
  - Idempotency is binary. If the host is not yet a DC it is joined; if it is
    already a DC of the target domain the run is a no-op (C(changed=false)). If
    the host is already a DC of a B(different) domain the module fails and never
    overwrites that existing role.
  - Only C(state=present) is supported. Demoting or leaving a domain is not
    offered.
  - Supports check mode - it reads whether the host is already a DC of the target
    and reports C(changed) accordingly, but joining itself cannot be performed in
    check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run locally on the host that is to become a DC, with the C(samba) Python
    bindings installed, typically as root, with network reachability and
    Kerberos/DNS resolution to the existing DC.
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
      - A domain account with permission to join a DC (typically a Domain or
        Enterprise Admin), for example C(Administrator).
    type: str
    required: true
  bind_password:
    description:
      - The password for O(bind_username).
      - Required when the host is joined (it is not needed when the host is
        already a DC of the target domain and the run is a no-op).
      - B(Security) - always pass this through Ansible Vault or an external
        secret store. It is marked C(no_log), is passed to samba only through the
        credentials object (never on a command line) and never appears in the
        return value, diff or an error.
    type: str
  domain:
    description:
      - The NetBIOS (short) domain name. If omitted it is derived from the
        existing domain.
    type: str
  netbios_name:
    description:
      - The NetBIOS computer name for this new DC. If omitted it is derived from
        the host name.
    type: str
  site:
    description:
      - The Active Directory site to place this DC in. If omitted samba chooses
        the default site.
    type: str
  dns_backend:
    description:
      - The DNS backend for this DC.
    type: str
    default: SAMBA_INTERNAL
    choices:
      - SAMBA_INTERNAL
      - BIND9_DLZ
      - BIND9_FLATFILE
      - NONE
  use_kerberos:
    description:
      - How the join authenticates to the existing domain controller.
      - C(required) (the default) authenticates with Kerberos only and fails
        rather than falling back to NTLM - the same stance as the object
        modules of this collection.
      - C(desired) tries Kerberos first and falls back to NTLM when no KDC can
        be reached, for hosts whose Kerberos client setup (KDC discovery,
        clock) is not complete at join time. NTLM never sends the password in
        plain text, but it is the weaker mechanism.
    type: str
    default: required
    choices:
      - required
      - desired
    version_added: 2.0.0
  state:
    description:
      - Whether the host should be a DC of the domain (C(present)). Only
        C(present) is supported; there is no C(absent).
    type: str
    default: present
    choices:
      - present
notes:
  - This module must be executed on the host that is joining; it acts on the
    local machine and has no remote/connection options.
  - It performs only the join; configuring smb.conf, the daemon and any host
    service stack is out of scope (a role or the caller does that).
seealso:
  - module: jomrr.samba.samba_provision
    description: Provision a brand-new domain instead of joining an existing one.
"""

EXAMPLES = r"""
- name: Join the local host as an additional DC of an existing domain
  jomrr.samba.samba_join_dc:
    realm: SAMDOM.EXAMPLE.COM
    server: dc1.samdom.example.com
    bind_username: Administrator
    bind_password: "{{ vault_domain_admin_password }}"
    state: present

- name: Join as a DC in a specific site with an explicit NetBIOS name
  jomrr.samba.samba_join_dc:
    realm: SAMDOM.EXAMPLE.COM
    server: dc1.samdom.example.com
    bind_username: Administrator
    bind_password: "{{ vault_domain_admin_password }}"
    netbios_name: DC2
    site: Default-First-Site-Name
    state: present
"""

RETURN = r"""
joined:
  description: Whether the host is a DC of the target domain after the run.
  returned: success
  type: bool
  sample: true
domain:
  description:
    - The joined domain's non-secret identifiers.
    - Null in check mode when the host is not yet a DC (the join would happen, but
      no data is produced without performing it).
  returned: success
  type: dict
  contains:
    domaindn:
      description: The domain distinguished name.
      returned: when the host is a DC
      type: str
      sample: DC=samdom,DC=example,DC=com
    domainsid:
      description: The domain security identifier (SID).
      returned: when the host is a DC
      type: str
      sample: S-1-5-21-1234567890-1234567890-1234567890
output:
  description:
    - What samba printed while joining (its progress narration, one entry per
      line). Captured so it cannot corrupt the module result, and returned for
      diagnostics; when the join fails, its last lines are quoted in the error.
  returned: when the host was joined in this run
  type: list
  elements: str
  sample:
    - "Adding CN=DC2,OU=Domain Controllers,DC=samdom,DC=example,DC=com"
    - "Replicating critical objects from the base DN of the domain"
"""

import importlib
import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import (
    KERBEROS_CHOICES,
    apply_kerberos_policy,
    fail_without_bindings,
)
from ansible_collections.jomrr.samba.plugins.module_utils import samba_local
from ansible_collections.jomrr.samba.plugins.module_utils import samba_join_dc_logic as logic


class SambaJoinDcIO:
    """DC-join operations via the ``samba.join`` bindings.

    All ``samba`` imports are lazy (``importlib.import_module`` inside the
    methods), so importing this module never requires the bindings - the same
    pattern as samba_conn. This module is local-only: it opens the local
    ``sam.ldb`` by path for the idempotency check and joins the local host as a
    DC; the credentials reach the existing DC through the credentials object, not
    a command line.
    """

    def __init__(self, module):
        self.module = module
        #: What samba printed during the join (None until a join ran).
        self.output = None

    def read_state(self):
        """Return the local host's DC identity, or None if it is not a DC."""
        try:
            return samba_local.read_local_domain()
        except samba_local.LocalSamdbError as exc:
            raise logic.SambaJoinDcError(to_native(exc))

    def join(self, params):
        """Join the local host as a DC and return its non-secret identity.

        Maps the module options to ``samba.join.join_DC()``. The password reaches
        samba only through the credentials object (never as an argv). A failure
        (wrong credentials, unreachable DC, non-empty private dir) is turned into
        a clear error instead of a raw traceback, and the join logger is silenced
        so it cannot echo anything sensitive. What samba prints during the join
        is captured into ``output`` instead of reaching the module's stdout.
        """
        join_mod = importlib.import_module("samba.join")
        credentials = importlib.import_module("samba.credentials")
        param = importlib.import_module("samba.param")

        load_parm = param.LoadParm()
        load_parm.load_default()

        # join_DC() requires a netbios_name: the whole SPN/DN setup in
        # DCJoinContext is guarded by `if netbios_name:`, so passing None makes
        # the join fail internally. When the caller omits it, derive the same
        # default samba-tool uses - the host's NetBIOS name from loadparm (the
        # hostname's first label, upper-cased and length-clamped).
        netbios_name = params["netbios_name"] or load_parm.get("netbios name")

        creds = credentials.Credentials()
        creds.guess(load_parm)
        creds.set_username(params["bind_username"])
        creds.set_password(params["bind_password"])
        creds.set_realm(params["realm"])
        # guess() takes the Kerberos policy from smb.conf (usually "desired");
        # the module decides it explicitly, Kerberos required by default.
        apply_kerberos_policy(creds, credentials, params["use_kerberos"])

        join_logger = logging.getLogger("jomrr.samba.samba_join_dc")
        join_logger.addHandler(logging.NullHandler())
        join_logger.propagate = False

        # samba.join narrates the join with print(); inside the module that
        # would land on the process's stdout, which carries the JSON result.
        transcript = samba_local.Transcript()
        try:
            with transcript:
                join_mod.join_DC(
                    logger=join_logger,
                    server=params["server"],
                    creds=creds,
                    lp=load_parm,
                    site=params["site"],
                    netbios_name=netbios_name,
                    domain=params["domain"],
                    dns_backend=params["dns_backend"],
                )
        except logic.SambaJoinDcError:
            raise
        except Exception as exc:
            raise logic.SambaJoinDcError(
                "joining the domain failed: %s%s" % (to_native(exc), transcript.tail())
            )
        self.output = transcript.lines

        domain = samba_local.read_local_domain()
        if domain is None:
            raise logic.SambaJoinDcError("the domain database was not present after the join")
        return {"domaindn": domain["domaindn"], "domainsid": domain["domainsid"]}


def main():
    """Module entry point."""
    argument_spec = dict(
        realm=dict(type="str", required=True),
        server=dict(type="str", required=True),
        bind_username=dict(type="str", required=True),
        bind_password=dict(type="str", no_log=True),
        domain=dict(type="str"),
        netbios_name=dict(type="str"),
        site=dict(type="str"),
        dns_backend=dict(type="str", default="SAMBA_INTERNAL", choices=logic.DNS_BACKENDS),
        use_kerberos=dict(type="str", default="required", choices=KERBEROS_CHOICES),
        state=dict(type="str", default="present", choices=["present"]),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    fail_without_bindings(module)
    join_io = SambaJoinDcIO(module)

    try:
        result = logic.run(module.params, module.check_mode, join_io)
    except logic.SambaJoinDcError as exc:
        module.fail_json(msg=to_native(exc))
    except Exception as exc:
        module.fail_json(
            msg="samba_join_dc failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    if join_io.output is not None:
        result["output"] = join_io.output
    module.exit_json(**result)


if __name__ == "__main__":
    main()
