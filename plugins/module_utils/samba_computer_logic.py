# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for the ``samba_computer`` module.

The module keeps an existing computer account in a container: it reads the
account, compares its parent with the desired location and moves it there. It
never creates or deletes an account; those come from the joins. The directory
access happens through an injected ``io`` object, so this layer is
unit-testable without the bindings.
"""

from __future__ import annotations


class SambaComputerError(Exception):
    """User-facing error the module turns into ``fail_json``."""


def run(params, check_mode, io):
    """Orchestrate read -> compare the location -> (check mode?) -> move -> report.

    ``io`` provides ``find`` (the account's state, or None) and the location
    helpers ``needs_move``, ``parent_exists`` and ``move``; an omitted ``path``
    means the default Computers container. Injecting it keeps this function
    testable without the samba bindings.
    """
    name = params["name"]
    path = params.get("path")

    current = io.find(name)
    if current is None:
        raise SambaComputerError(f"computer '{name}' does not exist (domain controllers are not managed)")

    move_needed = io.needs_move(current["dn"], path)
    # Validate the target before anything is reported, so check mode fails exactly
    # where a real run would. The default container always exists.
    if move_needed and path is not None and not io.parent_exists(path):
        raise SambaComputerError(f"path '{path}' does not exist; create it first")

    if move_needed and not check_mode:
        current = dict(current, dn=io.move(current["dn"], path))

    return {
        "changed": move_needed,
        "action": "modified" if move_needed else "unchanged",
        "computer": current,
    }
