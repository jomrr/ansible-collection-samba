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
  * The password never appears in returns, diffs or error messages (it is also
    ``no_log``). The bind user and realm are not secrets: a failed connection
    names them together with its cause.

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

from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb


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


#: Kerberos policy choices of the join modules. The object modules have no
#: choice: they always require Kerberos (see build_credentials).
KERBEROS_CHOICES = ["required", "desired"]


def apply_kerberos_policy(creds, credentials, use_kerberos):
    """Set the Kerberos policy on a ``samba.credentials.Credentials`` object.

    ``required`` authenticates with Kerberos only and fails rather than falling
    back to NTLM (the collection's default stance). ``desired`` tries Kerberos
    and falls back to NTLM when no KDC can be reached - the samba-tool default,
    for hosts whose Kerberos client setup is not complete at join time.
    """
    if use_kerberos == "required":
        creds.set_kerberos_state(credentials.MUST_USE_KERBEROS)
    else:
        creds.set_kerberos_state(credentials.AUTO_USE_KERBEROS)


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


def _bind_realm(module):
    """Return the realm to authenticate against (``realm``, or derived from ``server``)."""
    return module.params.get("realm") or _realm_from_server(module.params["server"])


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
    creds.set_realm(_bind_realm(module))
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
    except Exception as exc:
        module.fail_json(msg=_connect_error(module, creds, load_parm, exc))


#: NTSTATUS names ldb reports when the DC was never reached: no authentication
#: happened, so a Kerberos diagnosis would add nothing.
_TRANSPORT_STATUS = (
    "NT_STATUS_CONNECTION_REFUSED",
    "NT_STATUS_CONNECTION_RESET",
    "NT_STATUS_CONNECTION_DISCONNECTED",
    "NT_STATUS_HOST_UNREACHABLE",
    "NT_STATUS_NETWORK_UNREACHABLE",
    "NT_STATUS_IO_TIMEOUT",
    "NT_STATUS_OBJECT_NAME_NOT_FOUND",
)


def _connect_error(module, creds, load_parm, exc):
    """Explain a failed connection so its causes can be told apart.

    ldb reports a bare NTSTATUS for the bind (``NT_STATUS_INVALID_PARAMETER``
    for any Kerberos failure), so once the DC was reached a second kinit into a
    throw-away in-memory cache asks the KDC for the reason: a wrong password, an
    unreachable KDC or a clock skew each read differently there. A ticket that
    is obtained fine puts the failure on the LDAP side (sealing refused, no
    service ticket for the name). The extra attempt happens on this failure path
    only. The bind user and realm are not secrets and are named; the password
    never appears (ldb and kinit report codes and principals, and ``no_log``
    scrubs it anyway).
    """
    server = module.params["server"]
    principal = "%s@%s" % (module.params["bind_username"], _bind_realm(module))
    cause = samba_ldb.error_text(exc)
    if any(status in cause for status in _TRANSPORT_STATUS):
        return "could not reach the Samba AD DC at '%s' over LDAP (port 389): %s" % (server, cause)
    try:
        creds.get_named_ccache(load_parm, "MEMORY:jomrr_samba_diag_%d" % os.getpid())
    except Exception as kerberos_exc:
        return (
            "could not connect to the Samba AD DC at '%s' as '%s': no Kerberos ticket could "
            "be obtained (%s); LDAP reported: %s"
            % (server, principal, samba_ldb.error_text(kerberos_exc), cause)
        )
    return (
        "could not connect to the Samba AD DC at '%s' as '%s': a Kerberos ticket was obtained "
        "but the GSSAPI sign+seal LDAP bind failed (%s); check that the DC offers sealing and "
        "that '%s' is the DC's host name as registered in Kerberos" % (server, principal, cause, server)
    )
