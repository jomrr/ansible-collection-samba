# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""User attribute mapping shared by the samba_user and samba_user_info modules.

Only the user-specific part lives here: which attributes make up a user and how
an LDB message maps to the normalized state. The generic LDB and DN helpers are
in ``samba_ldb``. Imports nothing from ``samba``, so importing this module never
requires the bindings.
"""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_logic as logic

#: LDAP attributes read to build the normalized user state.
USER_ATTRS = [
    "sAMAccountName",
    "givenName",
    "sn",
    "displayName",
    "mail",
    "description",
    "uidNumber",
    "gidNumber",
    "unixHomeDirectory",
    "loginShell",
    "gecos",
    "userAccountControl",
]


def message_to_state(message):
    """Map an LDB user message to the normalized current-state dict."""
    uac_raw = samba_ldb.first_value(message, "userAccountControl")
    uac = int(uac_raw) if uac_raw is not None else 0
    return {
        "given_name": samba_ldb.first_value(message, "givenName"),
        "surname": samba_ldb.first_value(message, "sn"),
        "display_name": samba_ldb.first_value(message, "displayName"),
        "email": samba_ldb.first_value(message, "mail"),
        "description": samba_ldb.first_value(message, "description"),
        "uid_number": samba_ldb.int_value(message, "uidNumber"),
        "gid_number": samba_ldb.int_value(message, "gidNumber"),
        "unix_home_directory": samba_ldb.first_value(message, "unixHomeDirectory"),
        "login_shell": samba_ldb.first_value(message, "loginShell"),
        "gecos": samba_ldb.first_value(message, "gecos"),
        "enabled": not bool(uac & logic.UAC_ACCOUNTDISABLE),
        "_dn": str(message.dn),
        "_uac": uac,
    }
