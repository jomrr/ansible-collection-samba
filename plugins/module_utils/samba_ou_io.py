# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared LDB read helpers for the samba_ou and samba_ou_info modules.

Imports nothing from ``samba`` directly; the lazy ldb access and the generic
``first_value`` helper come from ``samba_user_io``. This keeps importing the
module binding-free, so the unit tests run without the samba bindings.
"""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io

#: LDAP attributes read to build the normalized OU state. The name (RDN value)
#: and the parent come from the object DN, so only the description is read here.
OU_ATTRS = ["description"]


def message_to_state(message):
    """Map an LDB OU message to the normalized current-state dict."""
    return {
        "description": samba_user_io.first_value(message, "description"),
        "_dn": str(message.dn),
    }
