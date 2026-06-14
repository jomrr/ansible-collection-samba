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

Idempotency is binary - is this host already a valid member (``adcli testjoin``
rc) - with a two-way discriminator (a member / not a member). Like
``samba_join_member`` there is no "member of a different domain" case; the realm
is an explicit parameter and a re-join simply re-establishes the keytab.
"""

from __future__ import annotations


class SambaJoinSssdError(Exception):
    """User-facing error the module turns into ``fail_json``."""


def run(params, check_mode, io):
    """Orchestrate the binary adcli-join decision.

    ``io`` provides ``read_state`` (``None`` when the host is not joined, a dict
    ``{"realm", "keytab"}`` when it is, raising :class:`SambaJoinSssdError` when
    ``adcli`` itself is missing) and ``join`` (runs ``adcli join``, returning the
    non-secret result). Injecting it keeps this function testable without adcli.

    ``state`` is always ``present``. The two cases:
      * already joined (``adcli testjoin`` rc 0) -> idempotent no-op.
      * not joined -> join.
    """
    current = io.read_state()

    if current is not None:
        return {"changed": False, "joined": True, "domain": current}

    if not params.get("bind_password"):
        raise SambaJoinSssdError("bind_password is required to join a domain")

    if check_mode:
        return {"changed": True, "joined": False, "domain": None}

    domain = io.join(params)
    return {"changed": True, "joined": True, "domain": domain}
