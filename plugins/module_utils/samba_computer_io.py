# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Computer accounts, shared by the samba_computer and samba_computer_info modules.

Which accounts count as managed computers, which attributes are read, how an LDB
message maps to the normalized state, and the one search both modules run. The
generic LDB and DN helpers are in ``samba_ldb``. Imports nothing from ``samba``
at import time, so importing this module never requires the bindings.
"""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb

#: LDAP attributes read to build the normalized computer state.
COMPUTER_ATTRS = ["sAMAccountName", "dNSHostName", "description"]

#: userAccountControl bits of domain controller accounts: UF_SERVER_TRUST_ACCOUNT
#: (8192, a DC) and UF_PARTIAL_SECRETS_ACCOUNT (67108864, a read-only DC).
DC_ACCOUNT_BITS = 8192 | 67108864


def computer_filter(escaped_account=None):
    """Return the LDAP filter for the managed computer accounts.

    ``objectCategory=computer`` leaves out the managed service accounts (their
    category differs), and the bitwise-OR matching rule leaves out every account
    with a domain controller bit, so a DC is never matched. ``escaped_account``
    (an ``ldb.binary_encode``-escaped sAMAccountName) restricts it to one account.
    """
    account = f"(sAMAccountName={escaped_account})" if escaped_account else ""
    return f"(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.804:={DC_ACCOUNT_BITS})){account})"


def account_name(name):
    """Return the sAMAccountName of the computer ``name``: ``name$`` (a trailing ``$`` is accepted)."""
    return name if name.endswith("$") else f"{name}$"


def message_to_state(message):
    """Map an LDB computer message to the normalized state."""
    account = samba_ldb.first_value(message, "sAMAccountName")
    return {
        "name": account.removesuffix("$"),
        "dn": str(message.dn),
        "dns_host_name": samba_ldb.first_value(message, "dNSHostName"),
        "description": samba_ldb.first_value(message, "description"),
    }


def search(samdb, name=None):
    """Return the states of the managed computer accounts, or of the one named ``name``.

    The account name is escaped via ``ldb.binary_encode`` before it enters the
    filter, so it cannot break out into LDAP filter syntax.
    """
    ldb = samba_ldb.load_ldb()
    account = None if name is None else ldb.binary_encode(account_name(name))
    res = samdb.search(
        base=samdb.domain_dn(),
        scope=ldb.SCOPE_SUBTREE,
        expression=computer_filter(account),
        attrs=COMPUTER_ATTRS,
    )
    return [message_to_state(message) for message in res]
