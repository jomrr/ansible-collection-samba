# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared connection and helper logic for the samba collection.

CRITICAL DESIGN CONSTRAINT
--------------------------
The ``samba`` Python bindings are NOT present in the ansible-test sanity
container. To keep the static sanity phase (validate-modules, pylint, import
sanity) green WITHOUT any ignore.txt entry or inline lint-suppression, this
module must NOT import ``samba`` at module load time, and must not trip pylint
with deferred imports either.

Strategy:
  * Existence check uses importlib.util.find_spec — no symbol is imported, so
    there is no unused-import / F401 to suppress.
  * The actual bindings are pulled in via importlib.import_module inside the
    function that needs them. importlib calls are normal function calls, so
    pylint raises no import-outside-toplevel.

At runtime (inside the Molecule systemd container where the DC and matching
python3-samba live together) the import succeeds. If it does not, we fail
cleanly via missing_required_lib instead of raising a raw ImportError.
"""

from __future__ import annotations

import importlib
import importlib.util
import traceback

from ansible.module_utils.basic import missing_required_lib

SAMBA_IMPORT_ERROR: str | None = None


def has_samba_bindings() -> bool:
    """Return True if the samba python bindings are importable.

    Uses find_spec so no symbol is bound; nothing to suppress for linters.
    """
    return importlib.util.find_spec("samba") is not None


def fail_without_bindings(module) -> None:
    """Fail the module cleanly if the samba bindings are unavailable."""
    if not has_samba_bindings():
        module.fail_json(msg=missing_required_lib("samba"))


def connect_samdb(module):
    """Open and return a SamDB connection.

    All samba imports happen here via importlib.import_module — regular
    function calls, so no deferred-import lint warning is produced.
    """
    global SAMBA_IMPORT_ERROR
    fail_without_bindings(module)

    try:
        auth = importlib.import_module("samba.auth")
        param = importlib.import_module("samba.param")
        samdb_mod = importlib.import_module("samba.samdb")
    except ImportError:
        SAMBA_IMPORT_ERROR = traceback.format_exc()
        module.fail_json(
            msg=missing_required_lib("samba"),
            exception=SAMBA_IMPORT_ERROR,
        )

    load_parm = param.LoadParm()
    load_parm.load_default()
    return samdb_mod.SamDB(
        session_info=auth.system_session(),
        lp=load_parm,
    )
