# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""MIT Kerberos keytab reader (principal names only) for samba_join_sssd.

Pure standard library (``struct``): no samba bindings, no krb5 tooling. The
module only needs to know which principals a keytab holds to decide whether
the host has a machine account for a realm - a local decision that must not
depend on a DC being reachable.

Format (version 2, header ``0x05 0x02``): a sequence of entries, each an
``int32`` size (big-endian; a negative size marks a deleted slot of ``-size``
bytes) followed by ``uint16 num_components``, the realm and every component
as ``uint16 length + bytes``, then ``uint32 name_type``, ``uint32 timestamp``,
``uint8 vno`` and the key (``uint16 enctype``, ``uint16 length``, bytes),
optionally a trailing ``uint32 vno``. Only the names are decoded; keys are
never touched.
"""

from __future__ import annotations

import struct

_VERSION = b"\x05\x02"


class KeytabError(Exception):
    """The file cannot be read as a version 2 MIT keytab."""


def read_principals(path):
    """Return ``[(realm, [component, ...]), ...]`` for every live entry of the keytab at ``path``."""
    with open(path, "rb") as handle:
        return parse_principals(handle.read())


def parse_principals(data):
    """Return ``[(realm, [component, ...]), ...]`` for every live entry in ``data``."""
    if data[:2] != _VERSION:
        raise KeytabError("not a version 2 keytab (header %r)" % (data[:2],))
    principals = []
    pos = 2
    while pos < len(data):
        (size,) = _unpack(">i", data, pos)
        pos += 4
        if size == 0:
            break
        if size < 0:
            pos -= size
            continue
        end = pos + size
        if end > len(data):
            raise KeytabError("truncated keytab entry")
        entry = data[pos:end]
        (count,) = _unpack(">H", entry, 0)
        realm, offset = _counted(entry, 2)
        components = []
        for dummy in range(count):
            component, offset = _counted(entry, offset)
            components.append(component)
        principals.append((realm, components))
        pos = end
    return principals


def _unpack(fmt, data, offset):
    if offset + struct.calcsize(fmt) > len(data):
        raise KeytabError("truncated keytab")
    return struct.unpack_from(fmt, data, offset)


def _counted(data, offset):
    """Read a ``uint16 length + bytes`` string; return ``(text, next offset)``."""
    (length,) = _unpack(">H", data, offset)
    offset += 2
    if offset + length > len(data):
        raise KeytabError("truncated keytab")
    return data[offset:offset + length].decode("utf-8", "replace"), offset + length
