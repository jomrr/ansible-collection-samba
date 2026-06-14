# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for the ``samba_join_dc`` module.

Imports nothing from ``samba``. Idempotency is binary - is this host already a
DC of the target domain - with a three-way discriminator (not a DC / a DC of the
target / a DC of a *different* domain). The join act and the local ``sam.ldb``
probe happen through an injected ``io`` object, so this layer is unit-testable
without the bindings.
"""

from __future__ import annotations


class SambaJoinDcError(Exception):
    """User-facing error the module turns into ``fail_json``."""


#: DNS backends ``samba.join.join_DC()`` accepts (same set as provision).
DNS_BACKENDS = ["SAMBA_INTERNAL", "BIND9_DLZ", "BIND9_FLATFILE", "NONE"]


def run(params, check_mode, io):
    """Orchestrate the binary DC-join decision.

    ``io`` provides ``read_state`` (``None`` when the host is not a DC, a dict
    ``{"dnsdomain", "domaindn", "domainsid"}`` when it is, raising
    :class:`SambaJoinDcError` when a local database exists but cannot be opened)
    and ``join`` (performs the join, returning the non-secret result). Injecting
    it keeps this function testable without the bindings.

    ``state`` is always ``present``. The three discriminator cases:
      * not a DC -> join.
      * already a DC of the target realm -> idempotent no-op; never re-join.
      * already a DC of a *different* domain -> a clear error; the host's
        existing DC role is never overwritten.
    """
    realm = params["realm"].lower()
    current = io.read_state()

    if current is not None:
        if current["dnsdomain"] == realm:
            return {
                "changed": False,
                "joined": True,
                "domain": {"domaindn": current["domaindn"], "domainsid": current["domainsid"]},
            }
        raise SambaJoinDcError(
            "this host is already a domain controller of '%s', not the join target "
            "'%s'; refusing to overwrite an existing domain" % (current["dnsdomain"], realm)
        )

    if not params.get("bind_password"):
        raise SambaJoinDcError("bind_password is required to join a domain")

    if check_mode:
        return {"changed": True, "joined": False, "domain": None}

    domain = io.join(params)
    return {"changed": True, "joined": True, "domain": domain}
