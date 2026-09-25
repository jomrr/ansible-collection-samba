# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the pure samba_ntacl logic (no samba bindings required)."""

from __future__ import annotations

import pytest
from ansible_collections.jomrr.samba.plugins.module_utils import samba_ntacl_logic as logic

OI = logic.OBJECT_INHERIT
CI = logic.CONTAINER_INHERIT
NP = logic.NO_PROPAGATE_INHERIT
IO = logic.INHERIT_ONLY
ID = logic.INHERITED
FULL = logic.RIGHTS["full"]
MODIFY = logic.RIGHTS["modify"]
READ = logic.RIGHTS["read"]
ADMINS = "S-1-5-21-1-2-3-1101"
WRITE = "S-1-5-21-1-2-3-1102"
ENG = "S-1-5-21-1-2-3-1103"
OWNER = "S-1-5-21-1-2-3-1104"
ROOT_UID = "S-1-22-1-0"
ROOT_GID = "S-1-22-2-0"
CO = logic.CREATOR_OWNER
SIDS = {"projects-admins": ADMINS, "projects-write": WRITE, "engineering-write": ENG,
        "projects-owner": OWNER, "CREATOR OWNER": CO}
BASE = "/srv/share"


def ace(trustee, rights, kind="allow", applies_to="this_folder_subfolders_files"):
    return {"trustee": trustee, "rights": rights, "type": kind, "applies_to": applies_to}


def folder(*aces, protected=False, owner=None, group=None):
    return {"protected": protected, "owner": owner, "group": group, "aces": list(aces)}


def fresh(stored=False, dacl=(), owner=ROOT_UID, group=ROOT_GID, protected=False, auto=False):
    return {"stored": stored, "owner": owner, "group": group, "protected": protected,
            "auto_inherited": auto, "dacl": tuple(dacl)}


def make_params(**over):
    params = {
        "share": "projects", "path": None, "owner": "projects-owner", "group": None,
        "propagate": "inherit", "propagate_owner": "none",
        "aces": [ace("projects-admins", "full"), ace("CREATOR OWNER", "full", applies_to="subfolders_files_only")],
        "folders": {"Engineering": folder(ace("engineering-write", "modify")), "Finance/Reports": folder(protected=True)},
    }
    params.update(over)
    return params


class FakeIO:
    """An in-memory share: path -> [is_dir, state]; records what is changed."""

    def __init__(self, tree=None):
        self.tree = {BASE: [True, fresh()]}
        for rel, entry in (tree or {}).items():
            self.tree[f"{BASE}/{rel}"] = entry
        self.calls = []

    def share_path(self, share):
        return BASE

    def resolve(self, names):
        return {name: SIDS[name] for name in names}

    def device(self, path):
        return 1

    def scan(self, path, device):
        prefix = path + "/"
        return sorted((p[len(prefix):], entry[0]) for p, entry in self.tree.items()
                      if p.startswith(prefix) and "/" not in p[len(prefix):])

    def read(self, path):
        return dict(self.tree[path][1])

    def write(self, path, desired, current):
        self.calls.append(("write", path))
        self.tree[path][1] = dict(desired, stored=True)

    def mkdir(self, path):
        self.calls.append(("mkdir", path))
        self.tree[path] = [True, fresh()]

    def selinux(self, path):
        self.calls.append(("selinux", path))

    def dacl(self, rel):
        return self.tree[f"{BASE}/{rel}"][1]["dacl"]


# --- mappings and order ---

def test_explicit_aces_map_the_fields_and_put_deny_first():
    specs = [ace("projects-admins", "full"), ace("projects-write", "read", kind="deny", applies_to="this_folder")]
    assert logic.explicit_aces(specs, SIDS) == ((1, 0, READ, WRITE), (0, CI | OI, FULL, ADMINS))


# --- the port of se_create_child_secdesc ---

@pytest.mark.parametrize(("flags", "container", "expected"), [
    (OI | CI, True, OI | CI | ID),
    (CI, True, CI | ID),
    (OI, True, OI | IO | ID),          # passed on to the files below
    (OI | NP, True, None),             # not for folders at all
    (CI | NP, True, ID),               # applies here, goes no further
    (OI | CI | IO, True, OI | CI | ID),
    (OI | CI, False, ID),
    (CI, False, None),                 # folders only
])
def test_inherit_flags(flags, container, expected):
    inherited = logic.inherit(((0, flags, FULL, ADMINS),), True, container, OWNER, ROOT_GID)
    assert inherited == (() if expected is None else ((0, expected, FULL, ADMINS),))


def test_inherit_creator_owner_becomes_the_owner_plus_an_inherit_only_ace_on_folders():
    parent = ((0, OI | CI | IO, FULL, CO),)
    assert logic.inherit(parent, True, True, OWNER, ROOT_GID) == ((0, ID, FULL, OWNER), (0, OI | CI | IO | ID, FULL, CO))
    assert logic.inherit(parent, True, False, OWNER, ROOT_GID) == ((0, ID, FULL, OWNER),)
    # Without container inheritance the creator ACE stays inherit-only for the files below.
    assert logic.inherit(((0, OI, FULL, CO),), True, True, OWNER, ROOT_GID) == ((0, OI | IO | ID, FULL, CO),)


def test_inherit_marks_inherited_aces_only_below_an_auto_inherited_parent_and_drops_duplicates():
    parent = ((0, OI | CI, FULL, ADMINS), (0, OI | CI, FULL, ADMINS))
    assert logic.inherit(parent, False, True, OWNER, ROOT_GID) == ((0, OI | CI, FULL, ADMINS),)


# --- the other objects ---

PARENT = logic.state(OWNER, ROOT_GID, False, ((0, OI | CI, FULL, ADMINS),))


def test_other_none_is_left_alone_unless_the_owner_is_propagated():
    current = fresh(stored=True, dacl=((0, 0, READ, WRITE),))
    assert logic.other_desired(current, PARENT, False, (OWNER, ROOT_GID), "none", "none") is None
    desired = logic.other_desired(current, PARENT, False, (OWNER, ROOT_GID), "none", "parent")
    assert (desired["owner"], desired["dacl"]) == (OWNER, current["dacl"])


def test_other_inherit_keeps_own_aces_of_a_stored_acl_and_recomputes_the_inherited():
    stale = (0, ID, READ, ENG)
    current = fresh(stored=True, dacl=((0, 0, READ, WRITE), stale))
    desired = logic.other_desired(current, PARENT, False, (OWNER, ROOT_GID), "inherit", "none")
    assert desired["dacl"] == ((0, 0, READ, WRITE), (0, ID, FULL, ADMINS))
    # Without a stored NT ACL the ACEs are synthesized from the POSIX mode, not its own.
    unstored = logic.other_desired(fresh(dacl=((0, 0, READ, WRITE),)), PARENT, False, (OWNER, ROOT_GID), "inherit", "none")
    assert unstored["dacl"] == ((0, ID, FULL, ADMINS),)


def test_other_inherit_leaves_a_protected_object_and_replace_resets_it():
    current = fresh(stored=True, protected=True, dacl=((0, 0, READ, WRITE),))
    assert logic.other_desired(current, PARENT, False, (OWNER, ROOT_GID), "inherit", "none") is None
    desired = logic.other_desired(current, PARENT, False, (OWNER, ROOT_GID), "replace", "none")
    assert (desired["protected"], desired["dacl"]) == (False, ((0, ID, FULL, ADMINS),))


# --- input checks ---

@pytest.mark.parametrize("key", ["/abs", "..", "a/../..", ".", "a/.."])
def test_folders_must_be_below_the_root(key):
    with pytest.raises(logic.SambaNtaclError, match="below the share root"):
        logic.normalize_folders({key: folder()})


def test_folders_may_not_be_listed_twice():
    with pytest.raises(logic.SambaNtaclError, match="twice"):
        logic.normalize_folders({"A": folder(), "A/": folder()})


# --- a whole run ---

def test_first_run_creates_the_folders_and_writes_root_managed_and_intermediate():
    io = FakeIO()
    result = logic.run(make_params(), False, io)
    assert result == {"changed": True, "changed_managed": [".", "Engineering", "Finance/Reports"], "changed_other": 1}
    eng, fin, rep = (f"{BASE}/{rel}" for rel in ("Engineering", "Finance", "Finance/Reports"))
    assert io.calls == [
        ("write", BASE),
        ("mkdir", eng), ("write", eng), ("selinux", eng),
        ("mkdir", fin), ("write", fin), ("selinux", fin),
        ("mkdir", rep), ("write", rep), ("selinux", rep),
    ]
    root = io.tree[BASE][1]
    assert (root["owner"], root["group"], root["protected"]) == (OWNER, ROOT_GID, True)
    inherited = ((0, OI | CI | ID, FULL, ADMINS), (0, ID, FULL, OWNER), (0, OI | CI | IO | ID, FULL, CO))
    assert io.dacl("Engineering") == ((0, OI | CI, MODIFY, ENG),) + inherited
    assert io.dacl("Finance") == inherited
    assert io.dacl("Finance/Reports") == ()
    assert io.tree[rep][1]["protected"] is True


def test_second_run_is_a_no_op():
    io = FakeIO()
    logic.run(make_params(), False, io)
    io.calls = []
    assert logic.run(make_params(), False, io) == {"changed": False, "changed_managed": [], "changed_other": 0}
    assert io.calls == []


def test_check_mode_reports_without_creating_or_writing():
    io = FakeIO()
    result = logic.run(make_params(), True, io)
    assert result["changed_managed"] == [".", "Engineering", "Finance/Reports"]
    assert result["changed_other"] == 1
    assert io.calls == []
    assert list(io.tree) == [BASE]


def test_a_copied_file_inherits_and_an_own_ace_is_kept():
    io = FakeIO()
    logic.run(make_params(), False, io)
    inherited = ((0, ID, MODIFY, ENG), (0, ID, FULL, ADMINS))
    io.tree[f"{BASE}/Engineering/copied.txt"] = [False, fresh()]
    io.tree[f"{BASE}/Engineering/own.txt"] = [False, fresh(stored=True, auto=True, dacl=((0, 0, READ, WRITE),) + inherited + ((0, ID, FULL, ROOT_UID),))]
    result = logic.run(make_params(), False, io)
    assert (result["changed_managed"], result["changed_other"]) == ([], 1)
    # CREATOR OWNER becomes the copying user, who stays the owner.
    assert io.dacl("Engineering/copied.txt") == inherited + ((0, ID, FULL, ROOT_UID),)
    assert io.dacl("Engineering/own.txt")[0] == (0, 0, READ, WRITE)


def test_replace_removes_own_aces_and_parent_passes_the_owner_on():
    io = FakeIO()
    logic.run(make_params(), False, io)
    io.tree[f"{BASE}/Engineering/own.txt"] = [False, fresh(stored=True, dacl=((0, 0, READ, WRITE),))]
    logic.run(make_params(propagate="replace", propagate_owner="parent"), False, io)
    own = io.tree[f"{BASE}/Engineering/own.txt"][1]
    assert own["owner"] == OWNER
    assert own["dacl"] == ((0, ID, MODIFY, ENG), (0, ID, FULL, ADMINS), (0, ID, FULL, OWNER))


def test_none_touches_only_the_way_to_the_managed_folders():
    io = FakeIO({"notes.txt": [False, fresh()], "Other": [True, fresh()]})
    result = logic.run(make_params(propagate="none"), False, io)
    assert result["changed_other"] == 1  # the created intermediate folder Finance
    assert io.tree[f"{BASE}/notes.txt"][1] == fresh()
    assert io.tree[f"{BASE}/Other"][1] == fresh()


def test_folders_default_to_the_owner_and_group_of_the_root():
    io = FakeIO()
    params = make_params(owner=None, group="projects-admins")
    params["folders"]["Engineering"]["owner"] = "projects-owner"
    logic.run(params, False, io)
    assert io.tree[BASE][1]["owner"] == ROOT_UID  # current owner kept
    assert (io.tree[f"{BASE}/Engineering"][1]["owner"], io.tree[f"{BASE}/Engineering"][1]["group"]) == (OWNER, ADMINS)
    assert io.tree[f"{BASE}/Finance/Reports"][1]["group"] == ADMINS


def test_a_file_where_a_folder_is_managed_fails():
    io = FakeIO({"Engineering": [False, fresh()]})
    with pytest.raises(logic.SambaNtaclError, match="is a file"):
        logic.run(make_params(), False, io)
