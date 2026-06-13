# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared LDB read and DN helpers for the samba object modules.

The user-specific mapping lives here too, but the DN helpers are generic and are
reused by samba_group and samba_ou (so the safe DN construction is not
duplicated). The ``samba``/``ldb`` bindings are imported lazily (via importlib
inside a function), so importing this module never requires them - that keeps the
static sanity phase green, the same constraint as in samba_conn.py.
"""

from __future__ import annotations

import importlib

from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_logic as logic

#: LDAP attributes read to build the normalized user state.
USER_ATTRS = [
    "sAMAccountName",
    "givenName",
    "sn",
    "displayName",
    "mail",
    "description",
    "userAccountControl",
]


def load_ldb():
    """Import and return the ``ldb`` module lazily."""
    return importlib.import_module("ldb")


def first_value(message, attr):
    """Return the first value of an LDB message attribute as ``str`` or ``None``."""
    element = message.get(attr)
    if element is None or len(element) == 0:
        return None
    return str(element[0])


def parse_dn(samdb, text):
    """Parse a DN string into an ldb.Dn (raises ValueError if malformed)."""
    return load_ldb().Dn(samdb, text)


def build_child_dn(samdb, rdn_attr, name, parent_dn):
    """Build ``<rdn_attr>=<name>,<parent_dn>`` with the name value safely escaped.

    Uses ``ldb.Dn.set_component`` so DN metacharacters in ``name`` cannot inject
    extra DN components.
    """
    ldb = load_ldb()
    dn = ldb.Dn(samdb, "%s=placeholder" % rdn_attr)
    dn.set_component(0, rdn_attr, name)
    dn.add_base(parent_dn)
    return dn


def default_users_dn(samdb):
    """Return the well-known Users container DN (CN=Users,<domaindn>)."""
    dsdb = importlib.import_module("samba.dsdb")
    return samdb.get_wellknown_dn(samdb.get_default_basedn(), dsdb.DS_GUID_USERS_CONTAINER)


def same_parent(samdb, object_dn, parent_dn):
    """True if ``object_dn``'s parent equals ``parent_dn`` (normalized DN compare)."""
    return parse_dn(samdb, object_dn).parent() == parent_dn


def dn_exists(samdb, dn):
    """True if ``dn`` exists in the directory."""
    ldb = load_ldb()
    try:
        samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=[])
        return True
    except ldb.LdbError as err:
        if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return False
        raise


def reparent_dn(samdb, object_dn, parent_dn):
    """Return ``object_dn``'s RDN under ``parent_dn`` (move target; RDN preserved)."""
    source = parse_dn(samdb, object_dn)
    return build_child_dn(samdb, source.get_rdn_name(), source.get_rdn_value(), parent_dn)


def message_to_state(message):
    """Map an LDB user message to the normalized current-state dict."""
    uac_raw = first_value(message, "userAccountControl")
    uac = int(uac_raw) if uac_raw is not None else 0
    return {
        "given_name": first_value(message, "givenName"),
        "surname": first_value(message, "sn"),
        "display_name": first_value(message, "displayName"),
        "email": first_value(message, "mail"),
        "description": first_value(message, "description"),
        "enabled": not bool(uac & logic.UAC_ACCOUNTDISABLE),
        "_dn": str(message.dn),
        "_uac": uac,
    }
