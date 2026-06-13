# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared LDB read helpers for the samba_group and samba_group_info modules.

Imports nothing from ``samba`` directly; the lazy ldb access and the generic
``first_value`` helper come from ``samba_user_io``. This keeps importing the
module binding-free, so the unit tests run without the samba bindings.
"""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_io

#: LDAP attributes read to build the normalized group state.
GROUP_ATTRS = ["sAMAccountName", "groupType", "description", "member"]


def message_to_state(message):
    """Map an LDB group message to the normalized current-state dict."""
    group_type_raw = samba_user_io.first_value(message, "groupType")
    members_element = message.get("member")
    members = [str(value) for value in members_element] if members_element is not None else []
    return {
        "description": samba_user_io.first_value(message, "description"),
        "group_type": int(group_type_raw) if group_type_raw is not None else 0,
        "members": members,
        "_dn": str(message.dn),
    }
