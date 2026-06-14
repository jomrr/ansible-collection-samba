# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""DNS management RPC connection and zone operations for samba_dns_zone.

Zone create/delete go through the C(dnsserver) RPC (C(DnssrvOperation2)) - unlike
DNS records, which use the local LDB. This was verified against samba 4.23.8:
there is no clean LDB zone-create (provision's are bespoke), and the RPC
C(ZoneCreate)/C(DeleteZoneFromDs) do the full, correct setup server-side.

The RPC is authenticated with the DC's own machine account (read from
secrets.ldb, available locally), so no credential is taken as a module parameter.
All ``samba`` imports are lazy (via importlib inside the functions), so importing
this module never requires the bindings and the static sanity phase stays green.
"""

from __future__ import annotations

import importlib
import traceback

from ansible.module_utils.basic import missing_required_lib


def _load(name):
    """Import and return a module lazily."""
    return importlib.import_module(name)


def connect_dnsserver(module, samdb):
    """Open a machine-account dnsserver RPC connection.

    Returns ``(conn, server)`` where ``server`` is the local DC's DNS host name
    (needed as the server argument of the RPC operations). Fails the module
    cleanly if the bindings are missing or the RPC server is unreachable.
    """
    try:
        dnsserver = _load("samba.dcerpc.dnsserver")
        param = _load("samba.param")
        credentials = _load("samba.credentials")
    except ImportError:
        module.fail_json(msg=missing_required_lib("samba"), exception=traceback.format_exc())

    load_parm = param.LoadParm()
    load_parm.load_default()
    creds = credentials.Credentials()
    creds.guess(load_parm)
    creds.set_machine_account(load_parm)
    server = samdb.host_dns_name()
    try:
        conn = dnsserver.dnsserver("ncacn_ip_tcp:%s[sign]" % server, load_parm, creds)
    except RuntimeError as exc:
        module.fail_json(msg="could not connect to the DNS RPC server '%s': %s" % (server, exc))
    return conn, server


def create_zone(conn, server, name, replication):
    """Create an AD-integrated primary zone (forward or reverse, per the name).

    ``replication`` is ``domain`` or ``forest`` (the directory partition / scope).
    Secure dynamic updates are enabled afterwards, matching ``samba-tool``.
    Returns ``False`` if the zone already exists (idempotent no-op / TOCTOU race).
    """
    dnsserver = _load("samba.dcerpc.dnsserver")
    dnsp = _load("samba.dcerpc.dnsp")
    werror = _load("samba.werror")
    werror_error = _load("samba").WERRORError

    info = dnsserver.DNS_RPC_ZONE_CREATE_INFO_LONGHORN()
    info.pszZoneName = name
    info.dwZoneType = dnsp.DNS_ZONE_TYPE_PRIMARY
    info.fAging = 0
    info.fDsIntegrated = 1
    info.fLoadExisting = 1
    info.dwDpFlags = (
        dnsserver.DNS_DP_FOREST_DEFAULT if replication == "forest" else dnsserver.DNS_DP_DOMAIN_DEFAULT
    )
    version = dnsserver.DNS_CLIENT_VERSION_LONGHORN
    try:
        conn.DnssrvOperation2(version, 0, server, None, 0, "ZoneCreate",
                              dnsserver.DNSSRV_TYPEID_ZONE_CREATE, info)
    except werror_error as err:
        if err.args[0] == werror.WERR_DNS_ERROR_ZONE_ALREADY_EXISTS:
            return False
        raise

    name_and_param = dnsserver.DNS_RPC_NAME_AND_PARAM()
    name_and_param.pszNodeName = "AllowUpdate"
    name_and_param.dwParam = dnsp.DNS_ZONE_UPDATE_SECURE
    conn.DnssrvOperation2(version, 0, server, name, 0, "ResetDwordProperty",
                          dnsserver.DNSSRV_TYPEID_NAME_AND_PARAM, name_and_param)
    return True


def delete_zone(conn, server, name):
    """Delete a zone and all the records it contains.

    Returns ``False`` if the zone did not exist (idempotent no-op / TOCTOU race).
    """
    dnsserver = _load("samba.dcerpc.dnsserver")
    werror = _load("samba.werror")
    werror_error = _load("samba").WERRORError
    try:
        conn.DnssrvOperation2(dnsserver.DNS_CLIENT_VERSION_LONGHORN, 0, server, name, 0,
                              "DeleteZoneFromDs", dnsserver.DNSSRV_TYPEID_NULL, None)
    except werror_error as err:
        if err.args[0] == werror.WERR_DNS_ERROR_ZONE_DOES_NOT_EXIST:
            return False
        raise
    return True
