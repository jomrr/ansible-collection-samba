# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for the ``samba_join_member`` module.

Imports nothing from ``samba``. Idempotency is binary - does this host hold a
machine account for the configured domain in its local secrets store - with a
two-way discriminator (a member / not a member) that is decided locally, never
by contacting a DC. Unlike ``samba_join_dc`` there is no "member of a
*different* domain" case: which domain the host is a member of is fixed by the
role-provided smb.conf, so re-joining (``force``) simply re-establishes the
machine account, which is the intended member-join semantics. The join act and
the local probe happen through an injected ``io`` object, so this layer is
unit-testable without the bindings.
"""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils import samba_lifecycle_logic as lifecycle


class SambaJoinMemberError(Exception):
    """User-facing error the module turns into ``fail_json``."""


def run(params, check_mode, io):
    """Orchestrate the binary member-join decision.

    ``io`` provides ``read_state`` (``None`` when the host is not a member, a
    dict ``{"workgroup", "netbios_name"}`` when it is; decided from the local
    secrets store) and ``join`` (performs the join, returning the non-secret
    result). Injecting it keeps this function testable without the bindings.

    ``state`` is always ``present``. The cases:
      * already a member and not ``force`` -> idempotent no-op; never re-join.
      * not a member, or ``force`` -> join (a real change).
    The decision is the shared :func:`samba_lifecycle_logic.ensure`.
    """
    return lifecycle.ensure(
        io.read_state(), params, check_mode, io.join, SambaJoinMemberError,
        flag="joined", secret="bind_password", action="join a domain",
    )
