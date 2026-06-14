# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared connection documentation fragment for the jomrr.samba modules."""

from __future__ import annotations


class ModuleDocFragment(object):
    """Connection options common to all jomrr.samba modules."""

    DOCUMENTATION = r"""
options:
  server:
    description:
      - The DNS host name of the Samba AD domain controller to connect to, for
        example C(dc1.example.com).
      - The module connects over LDAP (port 389) using SASL/GSSAPI with signing
        and sealing; the traffic is encrypted by the GSSAPI layer (no LDAPS or
        StartTLS is used).
    type: str
    required: true
  bind_username:
    description:
      - The user name to authenticate (bind) as, for example C(Administrator).
      - Every directory operation is authorized by the DC against this
        principal, so use an account with exactly the privileges it needs.
    type: str
    required: true
  bind_password:
    description:
      - The password for O(bind_username).
      - B(Security) - always pass this through Ansible Vault or an external
        secret store. Never write it in plain text in a playbook, inventory or
        variable file. The value is marked C(no_log) so it is scrubbed from
        module output, but that does not protect a plain-text value at rest.
    type: str
    required: true
  realm:
    description:
      - The Kerberos realm, for example C(EXAMPLE.COM).
      - If omitted it is derived from O(server) (the domain part, uppercased).
    type: str
notes:
  - Modules authenticate to the DC with explicit caller credentials over LDAP
    using SASL/GSSAPI sign and seal. Sealing is required; if the DC does not
    offer it the connection fails rather than falling back to an unencrypted
    bind.
  - The Kerberos ticket obtained from O(bind_username) and O(bind_password) is
    kept in an in-memory credential cache and is never written to disk; it dies
    with the module process.
  - B(Always) supply O(bind_password) via Ansible Vault or an external secret
    store; plain-text credentials in playbooks or inventory are strongly
    discouraged.
"""
