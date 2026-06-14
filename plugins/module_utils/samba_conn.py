# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared connection layer for the jomrr.samba modules.

All modules authenticate to the DC with explicit caller credentials over LDAP
using SASL/GSSAPI with signing and sealing (the GSSAPI layer encrypts the
traffic; no LDAPS/StartTLS). See architecture/decisions.md (Connection model).

Security properties enforced here (not optional, no parameter weakens them):
  * Kerberos is required (``MUST_USE_KERBEROS``) - the bind fails rather than
    silently falling back to NTLM.
  * The Kerberos ticket obtained from username/password is held in an in-memory
    credential cache (``MEMORY:``) - it never touches disk and dies with the
    process.
  * LDAP SASL wrapping is forced to ``seal`` - the bind requires encryption and
    fails if the server cannot provide it; it never downgrades to plain.
  * Credentials never appear in returns, diffs or error messages (``password``
    is also ``no_log``).

CRITICAL DESIGN CONSTRAINT (unchanged): the ``samba`` bindings are absent in the
ansible-test sanity container, so every ``samba`` import is lazy (via
importlib.import_module inside a function) and existence is checked with
find_spec - no module-level import, nothing for a linter to flag, no ignore
entry.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import traceback

from ansible.module_utils.basic import missing_required_lib


def connection_argument_spec():
    """Return the argument_spec fragment for the shared connection options.

    Merged into every module's argument_spec; documented by the
    ``jomrr.samba.connection`` doc fragment.
    """
    return dict(
        server=dict(type="str", required=True),
        bind_username=dict(type="str", required=True),
        bind_password=dict(type="str", required=True, no_log=True),
        realm=dict(type="str"),
    )


def has_samba_bindings() -> bool:
    """Return True if the samba python bindings are importable."""
    return importlib.util.find_spec("samba") is not None


def fail_without_bindings(module) -> None:
    """Fail the module cleanly if the samba bindings are unavailable."""
    if not has_samba_bindings():
        module.fail_json(msg=missing_required_lib("samba"))


def _realm_from_server(server):
    """Derive the Kerberos realm from a server FQDN (its domain part, uppercased)."""
    parts = server.split(".", 1)
    return parts[1].upper() if len(parts) == 2 else server.upper()


def build_credentials(module):
    """Build GSSAPI credentials with required Kerberos and an in-memory ccache.

    The Kerberos ticket obtained from the bind credentials is kept in a
    process-private in-memory credential cache, pointed at via ``KRB5CCNAME``, so
    it never lands on disk and dies with the module process. ``set_named_ccache``
    is intentionally NOT used: on some samba builds the GSSAPI layer cannot import
    a ccache set that way, whereas pointing ``KRB5CCNAME`` at a ``MEMORY:`` cache
    works uniformly. Authentication failures surface at connect time and are
    reported without echoing any credential.
    """
    credentials = importlib.import_module("samba.credentials")
    os.environ["KRB5CCNAME"] = "MEMORY:jomrr_samba_%d" % os.getpid()
    creds = credentials.Credentials()
    creds.set_username(module.params["bind_username"])
    creds.set_password(module.params["bind_password"])
    creds.set_realm(module.params.get("realm") or _realm_from_server(module.params["server"]))
    # Require Kerberos: fail instead of silently downgrading to NTLM.
    creds.set_kerberos_state(credentials.MUST_USE_KERBEROS)
    return creds


def connect_samdb(module):
    """Open and return a GSSAPI sign+seal LDAP SamDB connection.

    All samba imports happen here via importlib - regular function calls, so no
    deferred-import lint warning.
    """
    fail_without_bindings(module)

    try:
        param = importlib.import_module("samba.param")
        samdb_mod = importlib.import_module("samba.samdb")
    except ImportError:
        module.fail_json(msg=missing_required_lib("samba"), exception=traceback.format_exc())

    load_parm = param.LoadParm()
    load_parm.load_default()
    # Force the SASL security layer to sealing (encryption). With "seal" the bind
    # requires confidentiality and fails rather than downgrading to sign/plain.
    load_parm.set("client ldap sasl wrapping", "seal")

    creds = build_credentials(module)
    server = module.params["server"]
    try:
        return samdb_mod.SamDB(url="ldap://%s" % server, credentials=creds, lp=load_parm)
    except Exception:
        # Never echo the exception (it can carry the principal); credentials and
        # ticket must not leak into the error.
        module.fail_json(
            msg="could not connect to the Samba AD DC at '%s' over LDAP with "
                "GSSAPI sign+seal; verify the server, credentials, realm and that "
                "the DC offers sealing" % server
        )
