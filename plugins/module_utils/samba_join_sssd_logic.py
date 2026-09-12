# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, CLI-free logic for the ``samba_join_sssd`` module.

This is the SSSD/adcli branch of the join family - the deliberate CLI exception
to the collection's bindings-only rule: the join is an ``adcli`` subprocess that
writes a Kerberos keytab, not a samba binding (no Python binding for ``adcli``
exists). This layer touches neither ``samba`` nor ``adcli``; it decides
joined/not-joined from an injected ``io`` object (which runs ``adcli``), so it is
unit-testable without the tool.

Idempotency is binary - does the local keytab hold a machine principal for the
realm - with a two-way discriminator (joined / not joined) that is decided
locally, never by contacting a DC. Like ``samba_join_member`` there is no
"member of a different domain" case; the realm is an explicit parameter and a
re-join (``force``) simply re-establishes the keytab.
"""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils import samba_lifecycle_logic as lifecycle


class SambaJoinSssdError(Exception):
    """User-facing error the module turns into ``fail_json``."""


def run(params, check_mode, io):
    """Orchestrate the binary adcli-join decision.

    ``io`` provides ``read_state`` (``None`` when the host is not joined, a dict
    ``{"realm", "keytab"}`` when it is; decided from the local keytab) and
    ``join`` (runs ``adcli join``, returning the non-secret result, raising
    :class:`SambaJoinSssdError` when ``adcli`` itself is missing). Injecting it
    keeps this function testable without adcli.

    ``state`` is always ``present``. The cases:
      * already joined and not ``force`` -> idempotent no-op.
      * not joined, or ``force`` -> join (a real change).
    The decision is the shared :func:`samba_lifecycle_logic.ensure`.
    """
    return lifecycle.ensure(
        io.read_state(), params, check_mode, io.join, SambaJoinSssdError,
        flag="joined", secret="bind_password", action="join a domain",
    )
