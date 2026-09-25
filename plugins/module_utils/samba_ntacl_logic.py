# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for the ``samba_ntacl`` module.

The module keeps the NT ACL and the owner of a share's root and of managed
folders authoritative, creates missing folders and passes inheritance (and
optionally ownership) on to the other files and folders. An ACE is the tuple
``(type, flags, access_mask, sid)``; an object's state is a dict with
``stored`` (an NT ACL is stored, not synthesized from the POSIX mode),
``owner``, ``group``, ``protected``, ``auto_inherited`` and ``dacl``. The file
system and the directory are reached through an injected ``io`` object, so this
layer is unit-testable without the bindings.
"""

from __future__ import annotations

import posixpath

#: ACE types (SEC_ACE_TYPE_ACCESS_ALLOWED / _DENIED).
ACE_ALLOW = 0
ACE_DENY = 1
ACE_TYPES = {"allow": ACE_ALLOW, "deny": ACE_DENY}

#: ACE flags (SEC_ACE_FLAG_*).
OBJECT_INHERIT = 0x01
CONTAINER_INHERIT = 0x02
NO_PROPAGATE_INHERIT = 0x04
INHERIT_ONLY = 0x08
INHERITED = 0x10

#: Access masks of the rights, as Windows sets them for these checkboxes.
RIGHTS = {
    "full": 0x001F01FF,
    "modify": 0x001301BF,
    "read_execute": 0x001200A9,
    "read": 0x00120089,
    "write": 0x00100116,
}

#: ACE flags of the "applies to" choices.
APPLIES_TO = {
    "this_folder": 0,
    "this_folder_subfolders_files": CONTAINER_INHERIT | OBJECT_INHERIT,
    "this_folder_subfolders": CONTAINER_INHERIT,
    "this_folder_files": OBJECT_INHERIT,
    "subfolders_files_only": CONTAINER_INHERIT | OBJECT_INHERIT | INHERIT_ONLY,
    "subfolders_only": CONTAINER_INHERIT | INHERIT_ONLY,
    "files_only": OBJECT_INHERIT | INHERIT_ONLY,
}

CREATOR_OWNER = "S-1-3-0"
CREATOR_GROUP = "S-1-3-1"

ROOT = "."


class SambaNtaclError(Exception):
    """User-facing error the module turns into ``fail_json``."""


def canonical(aces):
    """Return explicit ACEs in canonical order: deny before allow, otherwise as given."""
    return tuple(ace for ace in aces if ace[0] == ACE_DENY) + tuple(ace for ace in aces if ace[0] != ACE_DENY)


def explicit_aces(specs, sids):
    """Build the explicit ACEs of an ``aces`` list (trustees resolved via ``sids``)."""
    return canonical([
        (ACE_TYPES[spec["type"]], APPLIES_TO[spec["applies_to"]], RIGHTS[spec["rights"]], sids[spec["trustee"]])
        for spec in specs
    ])


def _inheritable(flags, container):
    if not container:
        return bool(flags & OBJECT_INHERIT)
    if flags & CONTAINER_INHERIT:
        return True
    return bool(flags & OBJECT_INHERIT) and not flags & NO_PROPAGATE_INHERIT


def inherit(parent_dacl, parent_auto_inherited, container, owner, group):
    """Return the ACEs a new child inherits from ``parent_dacl``.

    A port of samba's ``se_create_child_secdesc`` (libcli/security/secdesc.c),
    so the result equals what smbd gives an object created over SMB:
    INHERITED_ACE only when the parent is AUTO_INHERITED, CREATOR OWNER/GROUP
    replaced by the child's owner/group (plus an inherit-only CREATOR ACE on
    containers), duplicates removed.
    """
    inherited = INHERITED if parent_auto_inherited else 0
    result = []
    for ace_type, flags, mask, sid in parent_dacl:
        if not _inheritable(flags, container):
            continue
        if not container:
            new_flags = 0
        else:
            new_flags = flags & ~(INHERIT_ONLY | INHERITED)
            if not new_flags & CONTAINER_INHERIT:
                new_flags |= INHERIT_ONLY
            if new_flags & NO_PROPAGATE_INHERIT:
                new_flags = 0
        creator = None
        trustee = sid
        if sid == CREATOR_OWNER:
            creator, trustee = sid, owner
        elif sid == CREATOR_GROUP:
            creator, trustee = sid, group
        if creator and container and new_flags & CONTAINER_INHERIT:
            result.append((ace_type, inherited, mask, trustee))
            trustee = creator
            new_flags |= INHERIT_ONLY
        elif container and not flags & NO_PROPAGATE_INHERIT:
            trustee = sid
        result.append((ace_type, new_flags | inherited, mask, trustee))
    return tuple(dict.fromkeys(result))


def state(owner, group, protected, dacl):
    """A desired state the module writes (always AUTO_INHERITED, like Windows)."""
    return {"owner": owner, "group": group, "protected": protected, "auto_inherited": True, "dacl": tuple(dacl)}


def other_desired(current, parent, container, owners, propagate, propagate_owner):
    """Return the desired state of an object that is not managed, or None to leave it.

    ``owners`` is the (owner, group) of the nearest managed parent folder.
    ``inherit`` keeps the object's own ACEs (only a stored NT ACL has any) and
    recomputes the inherited part; a protected object keeps its whole DACL.
    ``replace`` leaves only the inherited ACEs and removes the protection.
    """
    owner, group = owners if propagate_owner == "parent" else (current["owner"], current["group"])
    keeps_dacl = propagate == "none" or (propagate == "inherit" and current["stored"] and current["protected"])
    if keeps_dacl:
        if (owner, group) == (current["owner"], current["group"]):
            return None
        return dict(current, owner=owner, group=group)
    explicit = ()
    if propagate == "inherit" and current["stored"]:
        explicit = canonical([ace for ace in current["dacl"] if not ace[1] & INHERITED])
    return state(owner, group, False, explicit + inherit(parent["dacl"], parent["auto_inherited"], container, owner, group))


def same(current, desired):
    """True if the object already has the desired owner, group, flags and DACL."""
    return all(current[key] == desired[key] for key in ("owner", "group", "protected", "auto_inherited", "dacl"))


def normalize_folders(folders):
    """Return the managed folders keyed by their normalized relative path."""
    result = {}
    for key, spec in folders.items():
        rel = posixpath.normpath(key)
        if key.startswith("/") or rel in (ROOT, "..") or rel.startswith("../"):
            raise SambaNtaclError(f"folder '{key}' must be a path below the share root")
        if rel in result:
            raise SambaNtaclError(f"folder '{key}' is listed twice")
        result[rel] = spec
    return result


def trustee_names(params, folders):
    """Every name to resolve: the ACE trustees and the owners and groups."""
    names = {spec["trustee"] for spec in params["aces"]}
    names.update(params[key] for key in ("owner", "group") if params.get(key))
    for spec in folders.values():
        names.update(ace["trustee"] for ace in spec["aces"])
        names.update(spec[key] for key in ("owner", "group") if spec.get(key))
    return sorted(names)


def _parent(rel):
    return posixpath.dirname(rel) or ROOT


class _Run:
    """One top-down pass over the share."""

    def __init__(self, params, check_mode, io, folders, sids, device):
        self.params = params
        self.check_mode = check_mode
        self.io = io
        self.folders = folders
        self.sids = sids
        self.device = device
        needed = set(folders)
        for rel in folders:
            while _parent(rel) != ROOT:
                rel = _parent(rel)
                needed.add(rel)
        self.needed = needed
        self.walk_all = params["propagate"] != "none" or params["propagate_owner"] != "none"
        self.changed_managed = []
        self.changed_other = 0
        self.root_owners = None

    def _sid(self, name):
        return self.sids[name] if name else None

    def _apply(self, rel, path, current, desired, managed):
        if desired is None or (current is not None and current["stored"] and same(current, desired)):
            return
        if not self.check_mode:
            self.io.write(path, desired, current)
        if managed:
            self.changed_managed.append(rel)
        else:
            self.changed_other += 1

    def root(self, path):
        current = self.io.read(path)
        owners = (self._sid(self.params.get("owner")) or current["owner"],
                  self._sid(self.params.get("group")) or current["group"])
        self.root_owners = owners
        desired = state(owners[0], owners[1], True, explicit_aces(self.params["aces"], self.sids))
        self._apply(ROOT, path, current, desired, True)
        self._walk(ROOT, path, desired, owners, exists=True)

    def _managed(self, rel, parent):
        spec = self.folders[rel]
        owner = self._sid(spec.get("owner")) or self.root_owners[0]
        group = self._sid(spec.get("group")) or self.root_owners[1]
        inherited = () if spec["protected"] else inherit(parent["dacl"], parent["auto_inherited"], True, owner, group)
        return state(owner, group, spec["protected"], explicit_aces(spec["aces"], self.sids) + inherited)

    def _walk(self, rel, path, parent, owners, exists):
        entries = dict(self.io.scan(path, self.device)) if exists else {}
        missing = {posixpath.basename(child) for child in self.needed if _parent(child) == rel} - set(entries)
        for name in sorted(set(entries) | missing):
            child = name if rel == ROOT else f"{rel}/{name}"
            child_path = posixpath.join(path, name)
            managed = child in self.folders
            if child in self.needed and not entries.get(name, True):
                raise SambaNtaclError(f"'{child}' is a file, but a folder is managed there")
            if child not in self.needed and not self.walk_all:
                continue
            created = name in missing
            current = None
            if created and not self.check_mode:
                self.io.mkdir(child_path)
            if not created or not self.check_mode:
                current = self.io.read(child_path)
            is_dir = entries.get(name, True)
            if managed:
                desired = self._managed(child, parent)
            elif created:
                desired = state(owners[0], owners[1], False, inherit(parent["dacl"], parent["auto_inherited"], True, *owners))
            else:
                desired = other_desired(current, parent, is_dir, owners, self.params["propagate"], self.params["propagate_owner"])
            self._apply(child, child_path, current, desired, managed)
            if created and not self.check_mode:
                self.io.selinux(child_path)
            if is_dir:
                effective = desired if desired is not None else current
                child_owners = (desired["owner"], desired["group"]) if managed else owners
                self._walk(child, child_path, effective, child_owners, exists=not (created and self.check_mode))


def run(params, check_mode, io):
    """Bring the share root, the managed folders and the other objects to the desired state.

    ``io`` provides ``share_path`` (the share's path from smb.conf; checks the
    VFS stack), ``resolve`` (names to SIDs), ``device``, ``scan`` (folders and
    regular files, no symlinks, same file system), ``read``, ``write``,
    ``mkdir`` and ``selinux``. Check mode reads and compares but neither creates
    nor writes.
    """
    share_path = io.share_path(params["share"])
    root = params.get("path") or share_path
    folders = normalize_folders(params.get("folders") or {})
    sids = io.resolve(trustee_names(params, folders))
    walk = _Run(params, check_mode, io, folders, sids, io.device(root))
    walk.root(root)
    return {
        "changed": bool(walk.changed_managed or walk.changed_other),
        "changed_managed": walk.changed_managed,
        "changed_other": walk.changed_other,
    }
