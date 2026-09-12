# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared, samba-free decision of the lifecycle modules.

``samba_provision`` and the three join modules all make the same binary "is this
host already set up?" decision; only what is read, what is performed and how the
result is labelled differ. That decision lives here once: each module's
``*_logic.run`` reads its local state and calls :func:`ensure`.
"""

from __future__ import annotations


def ensure(current, params, check_mode, perform, error_cls, flag, secret, action):
    """Decide and, unless in check mode, perform a binary one-time setup.

    :param current: the locally read state - ``None`` when the host is not set
        up, a non-secret identity dict when it is.
    :param perform: callable ``perform(params)`` that does the setup and returns
        the non-secret result.
    :param error_cls: the module's user-facing error class.
    :param flag: the result key reporting the state (``provisioned``/``joined``).
    :param secret: the parameter that must be set to perform the setup.
    :param action: what the secret is needed for, named in the error.

    A host that is already set up is an idempotent no-op unless the module
    offers ``force`` and it is set; the setup is then redone (a real change).
    Otherwise the secret is required, check mode reports the change without
    performing it, and a real run performs it.
    """
    if current is not None and not params.get("force"):
        return {"changed": False, flag: True, "domain": current}

    if not params.get(secret):
        raise error_cls("%s is required to %s" % (secret, action))

    if check_mode:
        return {"changed": True, flag: current is not None, "domain": current}

    return {"changed": True, flag: True, "domain": perform(params)}
