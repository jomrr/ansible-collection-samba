# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for the ``samba_provision`` module.

Imports nothing from ``samba``. Idempotency here is binary - "is this host
already a DC, yes or no" - not the read-diff-write of the object modules. The
actual provisioning and the local ``sam.ldb`` probe happen through an injected
``io`` object, so this layer is unit-testable without the bindings.
"""

from __future__ import annotations


class SambaProvisionError(Exception):
    """User-facing error the module turns into ``fail_json``."""


#: Friendly domain/forest function level strings, mapped to the
#: ``DS_DOMAIN_FUNCTION_*`` constants by ``samba.functional_level.string_to_level``
#: in the io layer. Verified against samba 4.23.8.
FUNCTION_LEVELS = ["2000", "2003", "2008", "2008_R2", "2012", "2012_R2", "2016"]

#: DNS backends ``samba.provision.provision()`` accepts.
DNS_BACKENDS = ["SAMBA_INTERNAL", "BIND9_DLZ", "BIND9_FLATFILE", "NONE"]

#: Server roles this module provisions. Only a domain controller; ``serverrole``
#: is canonicalized by samba to "active directory domain controller".
SERVER_ROLES = ["dc"]


def run(params, check_mode, io):
    """Orchestrate the binary provision decision.

    ``io`` provides ``read_state`` (returns ``None`` when the host is not
    provisioned, a non-secret identity dict when it is, and raises
    :class:`SambaProvisionError` when a database exists but cannot be opened) and
    ``provision`` (performs the provisioning, returning the non-secret result).
    Injecting it keeps this function testable without the bindings.

    ``state`` is always ``present``. An already-provisioned host is an idempotent
    no-op: it is never re-provisioned and never reconciled against the
    parameters - ``present`` means only "ensure a DC exists here".
    """
    current = io.read_state()
    if current is not None:
        return {"changed": False, "provisioned": True, "domain": current}

    if not params.get("admin_password"):
        raise SambaProvisionError("admin_password is required to provision a new domain")

    if check_mode:
        return {"changed": True, "provisioned": False, "domain": None}

    domain = io.provision(params)
    return {"changed": True, "provisioned": True, "domain": domain}
