# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the MIT keytab principal reader (pure standard library)."""

from __future__ import annotations

import struct

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_keytab


def _octets(text):
    raw = text.encode()
    return struct.pack(">H", len(raw)) + raw


def entry(realm, components):
    """One live keytab entry (name_type 1, timestamp 0, vno 2, aes256 key of 4 bytes)."""
    body = struct.pack(">H", len(components)) + _octets(realm) + b"".join(_octets(c) for c in components)
    body += struct.pack(">IIB", 1, 0, 2) + struct.pack(">HH", 18, 4) + b"\x00" * 4
    return struct.pack(">i", len(body)) + body


def deleted(size):
    """A deleted slot of ``size`` bytes (negative size marker)."""
    return struct.pack(">i", -size) + b"\x00" * size


def keytab(*parts):
    return b"\x05\x02" + b"".join(parts)


HOST = ("SAMDOM.EXAMPLE.COM", ["host", "client1.samdom.example.com"])
MACHINE = ("SAMDOM.EXAMPLE.COM", ["CLIENT1$"])


def test_reads_every_live_principal(tmp_path):
    path = tmp_path / "krb5.keytab"
    path.write_bytes(keytab(entry(*HOST), entry(*MACHINE)))
    assert samba_keytab.read_principals(str(path)) == [HOST, MACHINE]


def test_skips_deleted_slots():
    data = keytab(entry(*HOST), deleted(17), entry(*MACHINE))
    assert samba_keytab.parse_principals(data) == [HOST, MACHINE]


def test_zero_size_ends_the_keytab():
    data = keytab(entry(*HOST), struct.pack(">i", 0), entry(*MACHINE))
    assert samba_keytab.parse_principals(data) == [HOST]


def test_empty_keytab_has_no_principals():
    assert samba_keytab.parse_principals(keytab()) == []


def test_wrong_version_is_an_error():
    with pytest.raises(samba_keytab.KeytabError):
        samba_keytab.parse_principals(b"\x05\x01" + entry(*HOST)[4:])


def test_truncated_entry_is_an_error():
    data = keytab(entry(*HOST))
    with pytest.raises(samba_keytab.KeytabError):
        samba_keytab.parse_principals(data[:-3])


def test_truncated_component_is_an_error():
    # The entry claims two components but only carries the realm.
    body = struct.pack(">H", 2) + _octets("SAMDOM.EXAMPLE.COM")
    with pytest.raises(samba_keytab.KeytabError):
        samba_keytab.parse_principals(keytab(struct.pack(">i", len(body)) + body))
