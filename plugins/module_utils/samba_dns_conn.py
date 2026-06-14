# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""DNS management RPC connection and zone operations for samba_dns_zone.

Zone create/delete go through the C(dnsserver) RPC (C(DnssrvOperation2)) - unlike
DNS records, which use the local LDB. The RPC is authenticated with the same
explicit caller credentials as the LDAP connection (GSSAPI, in-memory ccache;
the machine-account path is gone) and is sealed. All ``samba`` imports are lazy.
"""

from __future__ import annotations

import importlib

from ansible_collections.jomrr.samba.plugins.module_utils import samba_conn


def _load(name):
    """Import and return a module lazily."""
    return importlib.import_module(name)


def connect_dnsserver(module):
    """Open a sealed dnsserver RPC connection with the caller's GSSAPI credentials.

    Returns ``(conn, server)``. Fails the module cleanly (without echoing any
    credential) if the RPC server is unreachable.
    """
    dnsserver = _load("samba.dcerpc.dnsserver")
    param = _load("samba.param")
    load_parm = param.LoadParm()
    load_parm.load_default()
    creds = samba_conn.build_credentials(module)
    server = module.params["server"]
    try:
        conn = dnsserver.dnsserver("ncacn_ip_tcp:%s[seal]" % server, load_parm, creds)
    except RuntimeError:
        module.fail_json(
            msg="could not connect to the DNS RPC server at '%s'; verify the "
                "server, credentials and realm" % server
        )
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
