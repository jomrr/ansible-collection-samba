# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared local-directory helper for the setup modules (samba_provision,
samba_join_dc).

These modules act on the LOCAL host before any reachable DC exists, so they open
the local ``sam.ldb`` by path with a system session - the credential-free local
path the object modules abandoned (see Connection Model) - rather than the
``ldap://`` GSSAPI layer. All ``samba`` imports are lazy (the sanity container
has no ``samba``), the same constraint as samba_conn.
"""

from __future__ import annotations

import importlib
import os

from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb


class LocalSamdbError(Exception):
    """A local ``sam.ldb`` exists but could not be opened (for lack of
    privileges, or as an AD DC: a partial/broken install)."""


def read_local_domain():
    """Return the local DC's identity, or ``None`` if the host is not a DC.

    :returns: ``{"domaindn", "domainsid", "dnsdomain"}`` when a local ``sam.ldb``
        opens as an AD DC; ``None`` when there is no ``sam.ldb`` (the host is not
        a DC).
    :raises LocalSamdbError: when a ``sam.ldb`` exists but cannot be opened - for
        lack of privileges, or as an AD DC (a partial/broken install); the two are
        reported apart, and neither is ever a silent overwrite.

    The path comes from ``lp.private_path`` (smb.conf-respecting, not hardcoded);
    ``dnsdomain`` is samba's own ``domain_dns_name()`` (lowercased) so callers can
    match it against a requested realm.
    """
    param = importlib.import_module("samba.param")
    load_parm = param.LoadParm()
    load_parm.load_default()
    path = load_parm.private_path("sam.ldb")
    if not os.path.exists(path):
        return None

    auth = importlib.import_module("samba.auth")
    samdb_mod = importlib.import_module("samba.samdb")
    try:
        samdb = samdb_mod.SamDB(url=path, session_info=auth.system_session(), lp=load_parm)
        domaindn = samdb.domain_dn()
        domainsid = str(samdb.get_domain_sid())
        dnsdomain = samdb.domain_dns_name().lower()
    except Exception as exc:
        ldb = importlib.import_module("ldb")
        cause = samba_ldb.error_text(exc)
        if isinstance(exc, ldb.LdbError) and exc.args[0] == ldb.ERR_INSUFFICIENT_ACCESS_RIGHTS:
            raise LocalSamdbError(
                "a Samba database exists at '%s' but this process (uid %d) is not allowed to "
                "open it: %s; run the module with the privileges of the Samba installation"
                % (path, os.geteuid(), cause)
            )
        raise LocalSamdbError(
            "a Samba database exists at '%s' but could not be opened as an AD DC; "
            "the host appears partially provisioned or corrupt: %s" % (path, cause)
        )
    return {"domaindn": domaindn, "domainsid": domainsid, "dnsdomain": dnsdomain}
