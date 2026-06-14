# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for the ``samba_join_member`` module.

Imports nothing from ``samba``. Idempotency is binary - is this host already a
valid member of the configured domain (``net ads testjoin``) - with a two-way
discriminator (a member / not a member). Unlike ``samba_join_dc`` there is no
"member of a *different* domain" case: which domain the host is a member of is
fixed by the role-provided smb.conf that ``testjoin`` and the join both read, so
re-joining simply re-establishes the machine account, which is the intended
member-join semantics. The join act and the membership probe happen through an
injected ``io`` object, so this layer is unit-testable without the bindings.
"""

from __future__ import annotations


class SambaJoinMemberError(Exception):
    """User-facing error the module turns into ``fail_json``."""


def run(params, check_mode, io):
    """Orchestrate the binary member-join decision.

    ``io`` provides ``read_state`` (``None`` when the host is not a member, a
    dict ``{"workgroup", "netbios_name"}`` when it is) and ``join`` (performs the
    join, returning the non-secret result). Injecting it keeps this function
    testable without the bindings.

    ``state`` is always ``present``. The two cases:
      * already a valid member -> idempotent no-op; never re-join.
      * not a member -> join.
    """
    current = io.read_state()

    if current is not None:
        return {"changed": False, "joined": True, "domain": current}

    if not params.get("bind_password"):
        raise SambaJoinMemberError("bind_password is required to join a domain")

    if check_mode:
        return {"changed": True, "joined": False, "domain": None}

    domain = io.join(params)
    return {"changed": True, "joined": True, "domain": domain}
