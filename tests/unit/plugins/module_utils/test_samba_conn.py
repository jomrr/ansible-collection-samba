# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for samba_conn. These run in the sanity/units container WITHOUT
the samba bindings present, which is exactly what we want to verify: importing
the module_utils must not require samba."""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils import samba_conn


def test_import_does_not_require_samba():
    # The mere import above must succeed without the bindings installed.
    assert hasattr(samba_conn, "has_samba_bindings")


def test_has_samba_bindings_returns_bool():
    assert isinstance(samba_conn.has_samba_bindings(), bool)
