# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to manage the NT ACLs of a Samba share via the python bindings."""

from __future__ import annotations

DOCUMENTATION = r"""
module: samba_ntacl
short_description: Manage the NT ACLs of a Samba share
version_added: 2.3.0
description:
  - Set the NT ACL, the owner and the group of a share's root and of managed
    folders below it, create missing folders, and pass the inheritance - and
    optionally the ownership - on to all other files and folders of the share.
  - Works through the share's VFS stack with the C(samba) Python bindings
    (C(samba.ntacls), as C(samba-tool ntacl set --service) does), so the ACL
    is stored exactly as smbd stores it for SMB clients.
  - Runs locally on the file server; it has no connection options and is not
    part of the C(jomrr.samba.all) action group. Trustee, owner and group names
    are resolved to SIDs on a domain controller over LSA, with the file
    server's machine account.
  - The module is idempotent and supports check mode; it writes only where the
    ACL, the owner or the group differs.
author:
  - Jonas Mauer (@jomrr)
requirements:
  - Must run locally on the file server (a domain member or a DC), as root,
    with the C(samba) Python bindings (C(python3-samba)) and the Samba server
    installed; the share's VFS modules (C(acl_xattr)) come with the server.
  - The C(vfs objects) of the share must include C(acl_xattr); the module
    fails otherwise.
  - A domain controller reachable for the name lookups, and winbind running
    for the idmap.
options:
  share:
    description:
      - The name of the share in smb.conf. It selects the VFS stack the ACLs
        are read and written through.
    type: str
    required: true
  path:
    description:
      - The root of the share. If omitted, the C(path) of the share in smb.conf.
    type: path
  owner:
    description:
      - The owner of the share root and, unless a folder sets its own, of the
        managed folders; a user or group name.
      - It must map to a uid in the file server's idmap (C(ID_TYPE_UID) or
        C(ID_TYPE_BOTH)). If omitted, the current owner is kept.
    type: str
  group:
    description:
      - The group of the share root and, unless a folder sets its own, of the
        managed folders.
      - It must map to a gid in the file server's idmap (C(ID_TYPE_GID) or
        C(ID_TYPE_BOTH)). If omitted, the current group is kept.
    type: str
  propagate:
    description:
      - What happens to the files and folders that are not managed.
      - C(none) leaves them unchanged.
      - C(inherit) recomputes their inherited ACEs and keeps their own ACEs; an
        object without a stored NT ACL (for example copied over SSH) has none
        of its own. A protected object keeps its whole ACL.
      - C(replace) removes their own ACEs and their protection, so they only
        have the inherited ACEs.
    type: str
    default: inherit
    choices:
      - none
      - inherit
      - replace
  propagate_owner:
    description:
      - What happens to the owner and group of the files and folders that are
        not managed.
      - C(none) leaves them unchanged, for shares where whoever creates an
        object owns it.
      - C(parent) sets the owner and group of the nearest managed parent
        folder, for shares with C(inherit owner).
    type: str
    default: none
    choices:
      - none
      - parent
  aces:
    description:
      - The explicit ACEs of the share root. They are authoritative (ACEs not
        listed are removed) and the root is always protected (it inherits
        nothing).
    type: list
    elements: dict
    required: true
    suboptions:
      trustee:
        description:
          - A user or group name, or a well-known principal such as
            C(CREATOR OWNER), C(Authenticated Users) or C(SYSTEM).
        type: str
        required: true
      rights:
        description:
          - C(full) (0x001F01FF), C(modify) (0x001301BF), C(read_execute)
            (0x001200A9), C(read) (0x00120089) or C(write) (0x00100116).
        type: str
        required: true
        choices:
          - full
          - modify
          - read
          - read_execute
          - write
      type:
        description:
          - Whether the ACE allows or denies the rights.
        type: str
        default: allow
        choices:
          - allow
          - deny
      applies_to:
        description:
          - Which objects the ACE applies to, as the inheritance flags.
        type: str
        default: this_folder_subfolders_files
        choices:
          - files_only
          - subfolders_files_only
          - subfolders_only
          - this_folder
          - this_folder_files
          - this_folder_subfolders
          - this_folder_subfolders_files
  folders:
    description:
      - The managed folders; the key is the path relative to the share root,
        nested paths are allowed. Missing folders, including intermediate ones,
        are created.
      - Each value may set C(protected) (default C(false); C(true) means the
        folder inherits nothing), C(owner) and C(group) (default those of the
        share root) and C(aces), the authoritative explicit ACEs of the folder
        with the same fields as I(aces) (default none). A key without a value
        is a folder with all defaults.
    type: dict
    default: {}
notes:
  - Objects created over SMB inherit the ACEs right away, as the share's
    configuration makes smbd do it (for the owner, for example C(inherit
    owner)); that configuration is not written by this module.
  - Objects copied onto the share over SSH have no NT ACL until the next run;
    C(propagate=inherit) then gives them the inherited ACEs. Their owner stays
    the copying user unless C(propagate_owner=parent).
  - Owner and group are set only by this module; smbd sets the uid and gid
    with them and derives the rwx bits from the DACL. C(chown), C(chmod) of
    the rwx bits and C(setfacl) invalidate the stored NT ACL;
    C(propagate=replace) restores it.
  - smbd refuses the write when the owner, the group or a domain trustee of an
    ACE does not map to a uid or gid in the idmap; the module reports the path
    and the NTSTATUS. With C(idmap_ad) every domain trustee therefore needs a
    uidNumber or gidNumber. Check mode does not detect this.
  - Symlinks are not followed, other file systems below the root are not
    entered, and only folders and regular files are handled. The SACL is not
    managed; it is written back unchanged.
  - Created folders get the default SELinux context of their path, as
    C(restorecon) sets it, when SELinux is enabled.
seealso:
  - module: jomrr.samba.samba_join_member
    description: Join a host to an existing domain as a Samba AD member server.
"""

EXAMPLES = r"""
- name: Set the ACLs of a project share and its department folders
  jomrr.samba.samba_ntacl:
    share: projects
    owner: projects-owner
    group: projects-admins
    aces:
      - trustee: projects-admins
        rights: full
      - trustee: projects-write
        rights: modify
      - trustee: CREATOR OWNER
        rights: full
        applies_to: subfolders_files_only
    folders:
      Engineering:
        aces:
          - trustee: engineering-write
            rights: modify
      Finance/Reports:
        protected: true
        aces:
          - trustee: projects-admins
            rights: full
          - trustee: finance-write
            rights: modify

- name: Reset every other object to the inherited ACEs and the owner of its folder
  jomrr.samba.samba_ntacl:
    share: projects
    propagate: replace
    propagate_owner: parent
    aces:
      - trustee: projects-admins
        rights: full
"""

RETURN = r"""
changed_managed:
  description:
    - The managed paths whose folder was created or whose ACL, owner or group
      was written, C(.) for the share root and the others relative to it; in
      check mode, what would be.
  returned: success
  type: list
  elements: str
  sample:
    - "."
    - Engineering
changed_other:
  description:
    - The number of other files and folders whose ACL, owner or group was
      written, created intermediate folders included; in check mode, what
      would be.
  returned: success
  type: int
  sample: 12
"""

import errno
import importlib
import os
import stat

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.jomrr.samba.plugins.module_utils import samba_ntacl_logic as logic
from ansible_collections.jomrr.samba.plugins.module_utils.samba_conn import fail_without_bindings, run_or_fail

ACE_SPEC = {
    "trustee": {"type": "str", "required": True},
    "rights": {"type": "str", "required": True, "choices": sorted(logic.RIGHTS)},
    "type": {"type": "str", "default": "allow", "choices": sorted(logic.ACE_TYPES)},
    "applies_to": {"type": "str", "default": "this_folder_subfolders_files", "choices": sorted(logic.APPLIES_TO)},
}

FOLDER_SPEC = {
    "protected": {"type": "bool", "default": False},
    "owner": {"type": "str"},
    "group": {"type": "str"},
    "aces": {"type": "list", "elements": "dict", "default": [], "options": ACE_SPEC},
}


class SambaNtaclIO:
    """Share, name lookups and NT ACLs on the local file server.

    All ``samba`` imports are lazy (``importlib.import_module`` inside the
    methods), so importing this module never requires the bindings. ACLs are
    read and written through the share's VFS stack (``service=<share>``) with
    ``samba.ntacls``, names are looked up over LSA on a DC with the machine
    account.
    """

    def __init__(self, module):
        self.module = module
        self.lp = None
        self.share = None
        self.session = None

    def share_path(self, share):
        """Load smb.conf and return the path of ``share``; its VFS stack must store NT ACLs."""
        param = importlib.import_module("samba.param")
        s3param = importlib.import_module("samba.samba3.param")
        self.lp = param.LoadParm()
        self.lp.load_default()
        s3param.get_context().load(self.lp.configfile)
        self.session = importlib.import_module("samba.auth_util").system_session_unix()
        path = self.lp.get("path", share)
        if path is None:
            raise logic.SambaNtaclError(f"share '{share}' is not defined in {self.lp.configfile}")
        if "acl_xattr" not in (self.lp.get("vfs objects", share) or []):
            raise logic.SambaNtaclError(f"the vfs objects of share '{share}' must include acl_xattr")
        self.share = share
        return path

    def resolve(self, names):
        """Return ``{name: sid}``, looked up over LSA on a DC; unknown names fail together."""
        if not names:
            return {}
        samba = importlib.import_module("samba")
        credentials = importlib.import_module("samba.credentials")
        lsa = importlib.import_module("samba.dcerpc.lsa")
        nbt = importlib.import_module("samba.dcerpc.nbt")
        security = importlib.import_module("samba.dcerpc.security")
        ntstatus = importlib.import_module("samba.ntstatus")
        net = importlib.import_module("samba.net")
        creds = credentials.Credentials()
        creds.guess(self.lp)
        creds.set_machine_account(self.lp)
        dc = net.Net(creds, self.lp).finddc(domain=self.lp.get("realm"), flags=nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS)
        conn = lsa.lsarpc(f"ncacn_np:{dc.pdc_dns_name}[seal]", self.lp, creds)
        handle = conn.OpenPolicy2("", lsa.ObjectAttribute(), security.SEC_FLAG_MAXIMUM_ALLOWED)
        sids = {}
        unknown = []
        for name in names:
            try:
                _domains, found, _count = conn.LookupNames3(
                    handle, [lsa.String(name)], lsa.TransSidArray3(), lsa.LSA_LOOKUP_NAMES_ALL, 0,
                    lsa.LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES, lsa.LSA_CLIENT_REVISION_2,
                )
            except samba.NTSTATUSError as err:
                if err.args[0] != ntstatus.NT_STATUS_NONE_MAPPED:
                    raise
                unknown.append(name)
                continue
            entry = found.sids[0]
            if entry.sid_type == lsa.SID_NAME_UNKNOWN:
                unknown.append(name)
                continue
            sids[name] = str(entry.sid)
        if unknown:
            raise logic.SambaNtaclError("cannot resolve to a SID: {}".format(", ".join(unknown)))
        return sids

    def device(self, path):
        """The device of the share root; other file systems below it are not entered."""
        try:
            return os.lstat(path).st_dev
        except FileNotFoundError:
            raise logic.SambaNtaclError(f"the share path '{path}' does not exist")

    def scan(self, path, device):
        """Return ``[(name, is_dir)]`` of the folders and regular files in ``path``.

        Symlinks are not followed and entries on another file system (mount
        points) are left out, as is everything that is neither.
        """
        entries = []
        with os.scandir(path) as found:
            for entry in found:
                info = entry.stat(follow_symlinks=False)
                if info.st_dev != device:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    entries.append((entry.name, True))
                elif stat.S_ISREG(info.st_mode):
                    entries.append((entry.name, False))
        return sorted(entries)

    def read(self, path):
        """Return the object's state as smbd sees it, and whether an NT ACL is stored."""
        samba = importlib.import_module("samba")
        ntacls = importlib.import_module("samba.ntacls")
        security = importlib.import_module("samba.dcerpc.security")
        try:
            sd = ntacls.getntacl(self.lp, path, self.session, direct_db_access=False, service=self.share)
        except samba.NTSTATUSError as err:
            raise logic.SambaNtaclError(
                f"reading the NT ACL of '{path}' through share '{self.share}' failed "
                f"(NTSTATUS 0x{err.args[0]:08X}): {to_native(err.args[1])}"
            )
        try:
            ntacls.getntacl(self.lp, path, self.session, direct_db_access=True)
            stored = True
        except OSError as err:
            if err.errno != errno.ENODATA:
                raise
            stored = False
        aces = sd.dacl.aces if sd.dacl is not None else []
        return {
            "stored": stored,
            "owner": str(sd.owner_sid),
            "group": str(sd.group_sid),
            "protected": bool(sd.type & security.SEC_DESC_DACL_PROTECTED),
            "auto_inherited": bool(sd.type & security.SEC_DESC_DACL_AUTO_INHERITED),
            "dacl": tuple((ace.type, ace.flags, ace.access_mask, str(ace.trustee)) for ace in aces),
            "sacl": sd.sacl,
            "sacl_type": sd.type & (security.SEC_DESC_SACL_PRESENT | security.SEC_DESC_SACL_AUTO_INHERITED | security.SEC_DESC_SACL_PROTECTED),
        }

    def write(self, path, desired, current):
        """Write owner, group and DACL through the share's VFS stack; the SACL goes back unchanged."""
        samba = importlib.import_module("samba")
        ntacls = importlib.import_module("samba.ntacls")
        security = importlib.import_module("samba.dcerpc.security")
        sd = security.descriptor()
        sd.owner_sid = security.dom_sid(desired["owner"])
        sd.group_sid = security.dom_sid(desired["group"])
        sd.dacl = security.acl()
        sd.dacl.revision = security.SECURITY_ACL_REVISION_NT4
        for ace_type, flags, mask, sid in desired["dacl"]:
            ace = security.ace()
            ace.type = ace_type
            ace.flags = flags
            ace.access_mask = mask
            ace.trustee = security.dom_sid(sid)
            sd.dacl_add(ace)
        sd.sacl = current["sacl"]
        sd.type = (
            security.SEC_DESC_SELF_RELATIVE | security.SEC_DESC_DACL_PRESENT | current["sacl_type"]
            | (security.SEC_DESC_DACL_AUTO_INHERITED if desired["auto_inherited"] else 0)
            | (security.SEC_DESC_DACL_PROTECTED if desired["protected"] else 0)
        )
        try:
            # setntacl only renders the descriptor as SDDL with the domain SID;
            # any SID serves for that.
            ntacls.setntacl(self.lp, path, sd, security.SID_BUILTIN, self.session, use_ntvfs=False, service=self.share)
        except samba.NTSTATUSError as err:
            raise logic.SambaNtaclError(
                f"smbd refused the NT ACL of '{path}' (NTSTATUS 0x{err.args[0]:08X}): {to_native(err.args[1])}"
            )

    def mkdir(self, path):
        """Create a folder; its ACL and owner are written right after."""
        os.mkdir(path)

    def selinux(self, path):
        """Give a created folder the default SELinux context of its path, as restorecon does."""
        self.module.set_default_selinux_context(path, False)


def validate_folders(module):
    """Validate each ``folders`` value against the folder spec; return them with defaults."""
    folders = {}
    for key, value in module.params["folders"].items():
        # A key without a value is a folder with all defaults.
        value = {} if value is None else value
        if not isinstance(value, dict):
            module.fail_json(msg=f"folders['{key}'] must be a dictionary")
        result = ArgumentSpecValidator(FOLDER_SPEC).validate(value)
        if result.error_messages:
            module.fail_json(msg="folders['{}']: {}".format(key, "; ".join(result.error_messages)))
        folders[key] = result.validated_parameters
    return folders


def main():
    """Module entry point."""
    argument_spec = {
        "share": {"type": "str", "required": True},
        "path": {"type": "path"},
        "owner": {"type": "str"},
        "group": {"type": "str"},
        "propagate": {"type": "str", "default": "inherit", "choices": ["none", "inherit", "replace"]},
        "propagate_owner": {"type": "str", "default": "none", "choices": ["none", "parent"]},
        "aces": {"type": "list", "elements": "dict", "required": True, "options": ACE_SPEC},
        "folders": {"type": "dict", "default": {}},
    }
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    fail_without_bindings(module)
    params = dict(module.params, folders=validate_folders(module))

    result = run_or_fail(module, "samba_ntacl", (logic.SambaNtaclError,), lambda: logic.run(params, module.check_mode, SambaNtaclIO(module)))

    module.exit_json(**result)


if __name__ == "__main__":
    main()
