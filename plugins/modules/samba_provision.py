#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to provision a Samba AD DC via the native python bindings."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_provision
short_description: Provision a Samba AD domain controller
version_added: 0.1.0
description:
  - Provision a host as the first Samba Active Directory Domain Controller of a
    new domain, through the native C(samba) Python bindings
    (C(samba.provision)), not through C(samba-tool) subprocesses.
  - This is a setup module and is unlike the object modules in this collection.
    It must run B(locally on the host that is becoming the DC) (for example with
    C(delegate_to) the future DC); there is no remote mode and no connection
    options, because there is no DC to connect to yet.
  - Idempotency is binary - whether a DC is already provisioned here or not.
    If the host is already provisioned this is a no-op (C(changed=false)); an
    existing domain is never re-provisioned and never reconciled against the
    parameters. Only the first-time provisioning is performed.
  - Only C(state=present) is supported. Destroying a domain is deliberately not
    offered, and joining an existing domain is out of scope for this module.
  - Supports check mode - it reads whether the host is already provisioned and
    reports C(changed) accordingly, but provisioning itself cannot be performed
    in check mode.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run locally on the host that is to become the DC, with the C(samba)
    Python bindings installed, typically as root.
options:
  realm:
    description:
      - The Kerberos realm (the DNS domain) of the new domain, for example
        C(SAMDOM.EXAMPLE.COM).
    type: str
    required: true
  domain:
    description:
      - The NetBIOS (short) domain name, for example C(SAMDOM).
    type: str
    required: true
  hostname:
    description:
      - The host name of the domain controller.
      - If omitted, samba derives it from the system.
    type: str
  admin_password:
    description:
      - The password for the domain C(Administrator) account.
      - Required when the host is provisioned (it is not needed when the host is
        already provisioned and the run is a no-op).
      - Must satisfy the domain password complexity policy; samba rejects a weak
        password and provisioning fails.
      - B(Security) - always pass this through Ansible Vault or an external
        secret store. It is marked C(no_log) and is never returned, logged or
        echoed in an error.
    type: str
  dns_backend:
    description:
      - The DNS backend for the domain.
    type: str
    default: SAMBA_INTERNAL
    choices:
      - SAMBA_INTERNAL
      - BIND9_DLZ
      - BIND9_FLATFILE
      - NONE
  server_role:
    description:
      - The server role to provision. Only a domain controller is supported.
    type: str
    default: dc
    choices:
      - dc
  function_level:
    description:
      - The domain and forest functional level of the new domain.
    type: str
    default: "2008_R2"
    choices:
      - "2000"
      - "2003"
      - "2008"
      - "2008_R2"
      - "2012"
      - "2012_R2"
      - "2016"
  use_rfc2307:
    description:
      - Whether to provision the domain with RFC2307 (NIS) support, enabling the
        POSIX attributes managed by M(jomrr.samba.samba_user) and
        M(jomrr.samba.samba_group).
    type: bool
    default: false
  state:
    description:
      - Whether the DC should exist (C(present)). Only C(present) is supported;
        there is no C(absent).
    type: str
    default: present
    choices:
      - present
notes:
  - This module must be executed on the host that is to become the DC; it acts
    on the local machine and has no remote/connection options.
  - An already-provisioned host is an idempotent no-op; the existing domain is
    never modified by this module.
seealso:
  - module: jomrr.samba.samba_user
    description: Manage users once the domain controller is provisioned.
"""

EXAMPLES = r"""
- name: Provision a domain controller with the internal DNS backend
  jomrr.samba.samba_provision:
    realm: SAMDOM.EXAMPLE.COM
    domain: SAMDOM
    admin_password: "{{ vault_dc_admin_password }}"
    state: present

- name: Provision a DC with RFC2307/POSIX support and an explicit host name
  jomrr.samba.samba_provision:
    realm: SAMDOM.EXAMPLE.COM
    domain: SAMDOM
    hostname: dc1
    admin_password: "{{ vault_dc_admin_password }}"
    use_rfc2307: true
    function_level: "2016"
    state: present
"""

RETURN = r"""
provisioned:
  description: Whether the host is provisioned as a DC after the run.
  returned: success
  type: bool
  sample: true
domain:
  description:
    - The provisioned domain's non-secret identifiers.
    - Null in check mode when the host is not yet provisioned (provisioning would
      happen, but no data is produced without performing it).
  returned: success
  type: dict
  contains:
    domaindn:
      description: The domain distinguished name.
      returned: when the host is provisioned
      type: str
      sample: DC=samdom,DC=example,DC=com
    domainsid:
      description: The domain security identifier (SID).
      returned: when the host is provisioned
      type: str
      sample: S-1-5-21-1234567890-1234567890-1234567890
"""

import importlib
import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import fail_without_bindings
from ansible_collections.jomrr.samba.plugins.module_utils import samba_local
from ansible_collections.jomrr.samba.plugins.module_utils import samba_provision_logic as logic


class SambaProvisionIO:
    """Local provisioning operations via the ``samba.provision`` bindings.

    All ``samba`` imports are lazy (``importlib.import_module`` inside the
    methods), so importing this module never requires the bindings - the same
    pattern as samba_conn, which keeps the static sanity phase green. This module
    is local-only: it opens the local ``sam.ldb`` by path and provisions the
    local host; there is no ``ldap://`` connection (no DC exists to connect to).
    """

    def __init__(self, module):
        self.module = module

    @staticmethod
    def _load_parm():
        """Build a default-loaded LoadParm (lazy import)."""
        param = importlib.import_module("samba.param")
        load_parm = param.LoadParm()
        load_parm.load_default()
        return load_parm

    def read_state(self):
        """Return the existing DC's non-secret identity, or None if not provisioned.

        Delegates the local ``sam.ldb`` open to the shared ``samba_local`` helper
        (also used by samba_join_dc). A missing database means "not provisioned";
        a present-but-unopenable one is a partial/broken install and is reported
        as a clear error, never a silent re-provision.
        """
        try:
            domain = samba_local.read_local_domain()
        except samba_local.LocalSamdbError as exc:
            raise logic.SambaProvisionError(to_native(exc))
        if domain is None:
            return None
        return {"domaindn": domain["domaindn"], "domainsid": domain["domainsid"]}

    def provision(self, params):
        """Provision the local host as a DC and return its non-secret identity.

        Maps the module options to ``samba.provision.provision()`` with the
        verified parameter mapping. The admin password is passed only to samba
        and never returned, logged or echoed in an error. A failure (including a
        weak password rejected by samba, or a non-empty private dir) is turned
        into a clear error instead of a raw traceback.
        """
        provision_mod = importlib.import_module("samba.provision")
        auth = importlib.import_module("samba.auth")
        functional_level = importlib.import_module("samba.functional_level")
        load_parm = self._load_parm()

        # provision()'s logger emits at INFO, and one of those lines can carry a
        # generated admin password; route it to a null handler that never reaches
        # Ansible's output.
        provision_logger = logging.getLogger("jomrr.samba.samba_provision")
        provision_logger.addHandler(logging.NullHandler())
        provision_logger.propagate = False

        try:
            result = provision_mod.provision(
                provision_logger,
                auth.system_session(),
                realm=params["realm"],
                domain=params["domain"],
                hostname=params["hostname"],
                adminpass=params["admin_password"],
                dns_backend=params["dns_backend"],
                serverrole=params["server_role"],
                dom_for_fun_level=functional_level.string_to_level(params["function_level"]),
                use_rfc2307=params["use_rfc2307"],
                lp=load_parm,
            )
        except logic.SambaProvisionError:
            raise
        except Exception as exc:
            raise logic.SambaProvisionError("provisioning the domain failed: %s" % to_native(exc))

        return {"domaindn": result.domaindn, "domainsid": str(result.domainsid)}


def main():
    """Module entry point."""
    argument_spec = dict(
        realm=dict(type="str", required=True),
        domain=dict(type="str", required=True),
        hostname=dict(type="str"),
        admin_password=dict(type="str", no_log=True),
        dns_backend=dict(type="str", default="SAMBA_INTERNAL", choices=logic.DNS_BACKENDS),
        server_role=dict(type="str", default="dc", choices=logic.SERVER_ROLES),
        function_level=dict(type="str", default="2008_R2", choices=logic.FUNCTION_LEVELS),
        use_rfc2307=dict(type="bool", default=False),
        state=dict(type="str", default="present", choices=["present"]),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    fail_without_bindings(module)
    provision_io = SambaProvisionIO(module)

    try:
        result = logic.run(module.params, module.check_mode, provision_io)
    except logic.SambaProvisionError as exc:
        module.fail_json(msg=to_native(exc))
    except Exception as exc:
        module.fail_json(
            msg="samba_provision failed: %s" % to_native(exc),
            exception=traceback.format_exc(),
        )

    module.exit_json(**result)


if __name__ == "__main__":
    main()
