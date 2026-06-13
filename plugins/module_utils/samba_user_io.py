# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared LDB read helpers for the samba_user and samba_user_info modules.

The ``samba``/``ldb`` bindings are imported lazily (via importlib inside a
function), so importing this module never requires them - that keeps the static
sanity phase green, the same constraint as in samba_conn.py.
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
