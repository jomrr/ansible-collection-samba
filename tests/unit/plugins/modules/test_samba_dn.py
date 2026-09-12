# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the shared DN/move I/O (samba_ldb helpers + SambaUserIO move).

A fake ``ldb`` whose ``Dn`` models ldb's *normalized* equality is injected, so the
move/no-move decision is exercised without the bindings. The real normalization
is ldb's own (verified against the host bindings and by the molecule idempotence
run); these tests prove the code delegates to ``ldb.Dn`` equality, never to raw
string comparison, and that names are escaped via ``set_component``."""

from __future__ import annotations

import pytest

from ansible_collections.jomrr.samba.plugins.module_utils import samba_user_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb
from ansible_collections.jomrr.samba.plugins.modules import samba_user


class FakeLdbError(Exception):
    pass


class FakeDn:
    """Models ldb.Dn: normalized (casefold, space-insensitive) equality + RDN ops."""

    def __init__(self, text):
        self.text = text
        self.set_calls = []

    def _norm(self):
        return ",".join(part.strip() for part in self.text.split(",")).casefold()

    def __eq__(self, other):
        return isinstance(other, FakeDn) and self._norm() == other._norm()

    def __hash__(self):
        return hash(self._norm())

    def parent(self):
        return FakeDn(",".join(part.strip() for part in self.text.split(",")[1:]))

    def get_rdn_name(self):
        return self.text.split(",")[0].split("=", 1)[0]

    def get_rdn_value(self):
        return self.text.split(",")[0].split("=", 1)[1]

    def set_component(self, num, name, value):
        self.set_calls.append((num, name, value))
        self.text = "%s=%s" % (name, value)

    def add_base(self, parent):
        self.text = self.text + "," + parent.text

    def _parts(self):
        return [part.strip() for part in self.text.split(",") if part.strip()]

    def __len__(self):
        return len(self._parts())

    def is_child_of(self, base):
        mine, theirs = self._norm().split(","), base._norm().split(",")
        return len(mine) >= len(theirs) and mine[len(mine) - len(theirs):] == theirs

    def remove_base_components(self, count):
        self.text = ",".join(self._parts()[:len(self._parts()) - count])

    def get_linearized(self):
        return self.text

    def __str__(self):
        return self.text


class FakeLdb:
    SCOPE_BASE = 0
    ERR_NO_SUCH_OBJECT = 32
    ERR_ENTRY_ALREADY_EXISTS = 68
    LdbError = FakeLdbError

    def Dn(self, samdb, text):
        if "INVALID" in text:
            raise ValueError("not a valid dn")
        return FakeDn(text)


class FakeSamDB:
    def __init__(self, search_error=None, rename_error=None):
        self.search_error = search_error
        self.rename_error = rename_error
        self.renamed = []
        self.newuser_kwargs = None

    def get_default_basedn(self):
        return FakeDn("DC=example,DC=com")

    def search(self, base, scope, attrs):
        if self.search_error is not None:
            raise self.search_error
        return [object()]

    def rename(self, old_dn, new_dn):
        if self.rename_error is not None:
            raise self.rename_error
        self.renamed.append((str(old_dn), str(new_dn)))

    def newuser(self, username, password, **kwargs):
        self.newuser_kwargs = kwargs


@pytest.fixture(autouse=True)
def _patch_ldb(monkeypatch):
    monkeypatch.setattr(samba_ldb, "load_ldb", FakeLdb)


# --- shared helpers ---

def test_same_parent_is_case_and_space_insensitive():
    # The idempotence trap: differing case/spacing must NOT look like a change.
    assert samba_ldb.same_parent(
        FakeSamDB(), "CN=jdoe,ou=eng,dc=example,dc=com", FakeLdb().Dn(None, "OU=Eng, DC=Example,DC=COM"))


def test_same_parent_detects_real_difference():
    assert not samba_ldb.same_parent(
        FakeSamDB(), "CN=jdoe,CN=Users,DC=example,DC=com", FakeLdb().Dn(None, "OU=Eng,DC=example,DC=com"))


def test_build_child_dn_escapes_name_via_set_component():
    parent = FakeLdb().Dn(None, "OU=Eng,DC=example,DC=com")
    dn = samba_ldb.build_child_dn(FakeSamDB(), "CN", "ev,il", parent)
    assert (0, "CN", "ev,il") in dn.set_calls


def test_reparent_preserves_rdn():
    parent = FakeLdb().Dn(None, "OU=Eng,DC=example,DC=com")
    target = samba_ldb.reparent_dn(FakeSamDB(), "CN=Jane Doe,CN=Users,DC=example,DC=com", parent)
    assert target.get_linearized() == "CN=Jane Doe,OU=Eng,DC=example,DC=com"


def test_dn_exists_true_and_false():
    assert samba_ldb.dn_exists(FakeSamDB(), FakeLdb().Dn(None, "OU=Eng,DC=example,DC=com")) is True
    samdb = FakeSamDB(search_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    assert samba_ldb.dn_exists(samdb, FakeLdb().Dn(None, "OU=Missing,DC=example,DC=com")) is False


# --- the container newuser/newgroup take: path relative to the domain ---

def test_container_below_domain_strips_the_domain():
    io = samba_user.SambaUserIO(FakeSamDB())
    assert io.container_below_domain("OU=Eng,DC=example,DC=com") == "OU=Eng"
    assert io.container_below_domain("OU=Sub,OU=Eng,DC=example,DC=com") == "OU=Sub,OU=Eng"


def test_container_below_domain_none_for_default_and_domain_root():
    io = samba_user.SambaUserIO(FakeSamDB())
    assert io.container_below_domain(None) is None
    # The relative form cannot express the root; the move afterwards handles it.
    assert io.container_below_domain("DC=example,DC=com") is None


def test_container_outside_the_domain_is_refused():
    with pytest.raises(logic.SambaUserError):
        samba_user.SambaUserIO(FakeSamDB()).container_below_domain("OU=Other,DC=other,DC=org")


def test_create_user_places_the_account_via_userou():
    samdb = FakeSamDB()
    samba_user.SambaUserIO(samdb).create_user("jdoe", "pw", "OU=Eng,DC=example,DC=com", {"surname": "Doe"})
    assert samdb.newuser_kwargs == {"userou": "OU=Eng", "surname": "Doe"}


def test_default_container_is_read_once_per_run(monkeypatch):
    reads = []

    def default_users_dn(samdb):
        reads.append(samdb)
        return FakeDn("CN=Users,DC=example,DC=com")

    monkeypatch.setattr(samba_ldb, "default_users_dn", default_users_dn)
    io = samba_user.SambaUserIO(FakeSamDB())
    assert io.needs_move("CN=jdoe,CN=Users,DC=example,DC=com", None) is False
    assert io.parent_exists(None) is True
    assert io.needs_move("CN=jdoe,OU=Eng,DC=example,DC=com", None) is True
    # Three questions about the default container, one wellKnownObjects read.
    assert len(reads) == 1


# --- SambaUserIO move wrapper ---

def _io(samdb):
    return samba_user.SambaUserIO(samdb)


def test_needs_move_false_for_normalized_equal_location():
    # current in OU=Eng (lowercase), desired OU=Eng (different case) -> no move.
    assert _io(FakeSamDB()).needs_move("CN=jdoe,ou=eng,dc=example,dc=com", "OU=Eng,DC=example,DC=com") is False


def test_needs_move_true_for_different_location():
    assert _io(FakeSamDB()).needs_move("CN=jdoe,CN=Users,DC=example,DC=com", "OU=Eng,DC=example,DC=com") is True


def test_invalid_path_raises_clean():
    with pytest.raises(logic.SambaUserError):
        _io(FakeSamDB()).needs_move("CN=jdoe,CN=Users,DC=example,DC=com", "INVALID PATH")


def test_move_renames_to_reparented_dn():
    samdb = FakeSamDB()
    new_dn = _io(samdb).move("CN=jdoe,CN=Users,DC=example,DC=com", "OU=Eng,DC=example,DC=com")
    assert new_dn == "CN=jdoe,OU=Eng,DC=example,DC=com"
    assert samdb.renamed == [("CN=jdoe,CN=Users,DC=example,DC=com", "CN=jdoe,OU=Eng,DC=example,DC=com")]


def test_move_vanished_raises_clean():
    samdb = FakeSamDB(rename_error=FakeLdbError(FakeLdb.ERR_NO_SUCH_OBJECT, "gone"))
    with pytest.raises(logic.SambaUserError):
        _io(samdb).move("CN=jdoe,CN=Users,DC=example,DC=com", "OU=Eng,DC=example,DC=com")


def test_move_target_exists_raises_clean():
    samdb = FakeSamDB(rename_error=FakeLdbError(FakeLdb.ERR_ENTRY_ALREADY_EXISTS, "exists"))
    with pytest.raises(logic.SambaUserError):
        _io(samdb).move("CN=jdoe,CN=Users,DC=example,DC=com", "OU=Eng,DC=example,DC=com")
