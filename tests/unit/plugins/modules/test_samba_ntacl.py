# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the samba_ntacl I/O layer.

The samba bindings are faked via importlib, so these run without them while
exercising the smb.conf lookup, the LSA name resolution, the descriptor
conversion and the directory scan. Importing the module must not require samba."""

from __future__ import annotations

import errno
import os
from types import SimpleNamespace as NS

import pytest
from ansible_collections.jomrr.samba.plugins.module_utils import samba_ntacl_logic as logic
from ansible_collections.jomrr.samba.plugins.modules import samba_ntacl

PROTECTED = 0x1000
AUTO = 0x400
SACL_PRESENT = 0x10
NONE_MAPPED = 0xC0000073
INVALID_OWNER = 0xC000005A


def test_module_imports_without_samba():
    assert hasattr(samba_ntacl, "main")
    assert hasattr(samba_ntacl, "SambaNtaclIO")


class FakeNTSTATUSError(RuntimeError):
    """Stand-in for samba.NTSTATUSError; args are (code, message)."""


SHARES = {
    "projects": {"path": "/srv/samba/shares/projects", "vfs objects": ["acl_xattr"]},
    "plain": {"path": "/srv/plain", "vfs objects": []},
}


class FakeLoadParm:
    configfile = "/etc/samba/smb.conf"

    def load_default(self):
        pass

    def get(self, name, share=None):
        if share is None:
            return {"realm": "SAMDOM.EXAMPLE.COM"}.get(name)
        return SHARES.get(share, {}).get(name)


class FakeAcl:
    def __init__(self):
        self.aces = []
        self.revision = None


class FakeDescriptor:
    def __init__(self):
        self.dacl = None

    def dacl_add(self, ace):
        self.dacl.aces.append(ace)


SECURITY = NS(
    SEC_DESC_DACL_PROTECTED=PROTECTED, SEC_DESC_DACL_AUTO_INHERITED=AUTO, SEC_DESC_SACL_PRESENT=SACL_PRESENT,
    SEC_DESC_SACL_AUTO_INHERITED=0x800, SEC_DESC_SACL_PROTECTED=0x2000, SEC_DESC_SELF_RELATIVE=0x8000,
    SEC_DESC_DACL_PRESENT=0x4, SECURITY_ACL_REVISION_NT4=2, SID_BUILTIN="S-1-5-32", SEC_FLAG_MAXIMUM_ALLOWED=0x02000000,
    descriptor=FakeDescriptor, acl=FakeAcl, ace=NS, dom_sid=str,
)


def patch(monkeypatch, **fakes):
    table = {
        "samba": NS(NTSTATUSError=FakeNTSTATUSError),
        "samba.param": NS(LoadParm=FakeLoadParm),
        "samba.samba3.param": NS(get_context=lambda: NS(load=lambda path: None)),
        "samba.auth_util": NS(system_session_unix=lambda: "SESSION"),
        "samba.dcerpc.security": SECURITY,
    }
    table.update(fakes)
    monkeypatch.setattr(samba_ntacl.importlib, "import_module", lambda name: table[name])


def make_io(monkeypatch, **fakes):
    patch(monkeypatch, **fakes)
    io = samba_ntacl.SambaNtaclIO(module=None)
    io.share_path("projects")
    return io


def test_share_path_reads_smb_conf_and_needs_acl_xattr(monkeypatch):
    io = make_io(monkeypatch)
    assert (io.share_path("projects"), io.share) == ("/srv/samba/shares/projects", "projects")
    with pytest.raises(logic.SambaNtaclError, match="must include acl_xattr"):
        io.share_path("plain")
    with pytest.raises(logic.SambaNtaclError, match="not defined"):
        io.share_path("ghost")


# --- resolve: LSA on a DC with the machine account ---

class FakeLsaConn:
    def __init__(self, table):
        self.table = table

    def OpenPolicy2(self, system_name, attr, access):
        return "HANDLE"

    def LookupNames3(self, handle, names, sids, level, count, options, revision):
        if names[0] not in self.table:
            raise FakeNTSTATUSError(NONE_MAPPED, "none mapped")
        sid, sid_type = self.table[names[0]]
        return (None, NS(sids=[NS(sid=sid, sid_type=sid_type)]), 1)


def lsa_fakes(table, calls):
    creds = NS(guess=lambda lp: calls.append("guess"), set_machine_account=lambda lp: calls.append("machine"))

    def lsarpc(binding, lp, credentials):
        calls.append(binding)
        return FakeLsaConn(table)

    return {
        "samba.credentials": NS(Credentials=lambda: creds),
        "samba.dcerpc.lsa": NS(lsarpc=lsarpc, ObjectAttribute=lambda: None, String=lambda s: s, TransSidArray3=lambda: None,
                               LSA_LOOKUP_NAMES_ALL=1, LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES=0, LSA_CLIENT_REVISION_2=2,
                               SID_NAME_UNKNOWN=8),
        "samba.dcerpc.nbt": NS(NBT_SERVER_LDAP=8, NBT_SERVER_DS=16),
        "samba.ntstatus": NS(NT_STATUS_NONE_MAPPED=NONE_MAPPED),
        "samba.net": NS(Net=lambda creds, lp: NS(finddc=lambda domain, flags: NS(pdc_dns_name="dc1.samdom.example.com"))),
    }


def test_resolve_looks_names_up_on_a_dc_with_the_machine_account(monkeypatch):
    calls = []
    io = make_io(monkeypatch, **lsa_fakes({"projects-admins": ("S-1-5-21-1-2-3-1101", 2), "CREATOR OWNER": ("S-1-3-0", 5)}, calls))
    assert io.resolve(["CREATOR OWNER", "projects-admins"]) == {"CREATOR OWNER": "S-1-3-0", "projects-admins": "S-1-5-21-1-2-3-1101"}
    assert calls == ["guess", "machine", "ncacn_np:dc1.samdom.example.com[seal]"]


def test_resolve_reports_every_unknown_name_and_needs_no_dc_without_names(monkeypatch):
    io = make_io(monkeypatch, **lsa_fakes({"weird": ("S-1-0-0", 8)}, []))
    with pytest.raises(logic.SambaNtaclError, match="cannot resolve to a SID: ghost, weird"):
        io.resolve(["ghost", "weird"])
    # No names, no import of the LSA bindings and no DC contact.
    assert make_io(monkeypatch).resolve([]) == {}


# --- read and write through the share's VFS stack ---

def fake_sd():
    ace = NS(type=0, flags=0x13, access_mask=0x1F01FF, trustee="S-1-5-21-1-2-3-1101")
    return NS(owner_sid="S-1-5-21-1-2-3-1104", group_sid="S-1-22-2-0", type=PROTECTED | AUTO | SACL_PRESENT | 0x4,
              dacl=NS(aces=[ace]), sacl="SACL")


def ntacls_reading(direct_error):
    def getntacl(lp, path, session, direct_db_access=True, service=None):
        if direct_db_access and direct_error is not None:
            raise direct_error
        assert direct_db_access or service == "projects"
        return fake_sd()

    return NS(getntacl=getntacl)


def test_read_returns_the_state_and_whether_an_nt_acl_is_stored(monkeypatch):
    io = make_io(monkeypatch, **{"samba.ntacls": ntacls_reading(None)})
    current = io.read("/srv/samba/shares/projects")
    assert current == {"stored": True, "owner": "S-1-5-21-1-2-3-1104", "group": "S-1-22-2-0", "protected": True,
                       "auto_inherited": True, "dacl": ((0, 0x13, 0x1F01FF, "S-1-5-21-1-2-3-1101"),),
                       "sacl": "SACL", "sacl_type": SACL_PRESENT}
    io = make_io(monkeypatch, **{"samba.ntacls": ntacls_reading(OSError(errno.ENODATA, "No data available"))})
    assert io.read("/srv/samba/shares/projects/copied.txt")["stored"] is False


def test_read_reports_a_failing_vfs_stack_with_path_share_and_ntstatus(monkeypatch):
    def getntacl(*args, **kwargs):
        raise FakeNTSTATUSError(0xC0000034, "The object name is not found.")

    io = make_io(monkeypatch, **{"samba.ntacls": NS(getntacl=getntacl)})
    with pytest.raises(logic.SambaNtaclError, match=r"'/srv/x' through share 'projects' failed \(NTSTATUS 0xC0000034\)"):
        io.read("/srv/x")


def test_write_sends_owner_group_dacl_and_the_unchanged_sacl(monkeypatch):
    sent = {}

    def setntacl(lp, path, sd, domsid, session, use_ntvfs=True, service=None):
        sent.update(path=path, sd=sd, domsid=domsid, use_ntvfs=use_ntvfs, service=service)

    io = make_io(monkeypatch, **{"samba.ntacls": NS(setntacl=setntacl)})
    desired = logic.state("S-1-5-21-1-2-3-1104", "S-1-22-2-0", True,
                          ((1, 0, 0x120089, "S-1-5-21-1-2-3-1102"), (0, 0x3, 0x1F01FF, "S-1-5-21-1-2-3-1101")))
    io.write("/srv/samba/shares/projects", desired, {"sacl": "SACL", "sacl_type": SACL_PRESENT})
    sd = sent["sd"]
    assert (sent["use_ntvfs"], sent["service"], sent["domsid"]) == (False, "projects", "S-1-5-32")
    assert (sd.owner_sid, sd.group_sid, sd.sacl) == ("S-1-5-21-1-2-3-1104", "S-1-22-2-0", "SACL")
    assert sd.type == 0x8000 | 0x4 | SACL_PRESENT | AUTO | PROTECTED
    assert [(a.type, a.flags, a.access_mask, a.trustee) for a in sd.dacl.aces] == list(desired["dacl"])


def test_write_reports_a_refusal_by_smbd_with_path_and_ntstatus(monkeypatch):
    def setntacl(*args, **kwargs):
        raise FakeNTSTATUSError(INVALID_OWNER, "The security ID may not be assigned as the owner")

    io = make_io(monkeypatch, **{"samba.ntacls": NS(setntacl=setntacl)})
    with pytest.raises(logic.SambaNtaclError, match=r"'/srv/x' \(NTSTATUS 0xC000005A\)"):
        io.write("/srv/x", logic.state("S-1-1-0", "S-1-1-0", False, ()), {"sacl": None, "sacl_type": 0})


# --- the scan of a real directory ---

def test_scan_lists_folders_and_files_but_no_symlinks_or_other_file_systems(tmp_path):
    (tmp_path / "b").mkdir()
    (tmp_path / "a.txt").write_text("x")
    os.symlink(tmp_path / "b", tmp_path / "c")
    io = samba_ntacl.SambaNtaclIO(module=None)
    device = io.device(str(tmp_path))
    assert io.scan(str(tmp_path), device) == [("a.txt", False), ("b", True)]
    assert io.scan(str(tmp_path), device + 1) == []
    with pytest.raises(logic.SambaNtaclError, match="does not exist"):
        io.device(str(tmp_path / "ghost"))


# --- the folders option ---

class FailJson(Exception):
    pass


def validate(folders):
    def fail_json(msg):
        raise FailJson(msg)

    return samba_ntacl.validate_folders(NS(params={"folders": folders}, fail_json=fail_json))


def test_folders_get_their_defaults_and_bad_values_fail_by_key():
    folders = validate({"Engineering": {"aces": [{"trustee": "engineering-write", "rights": "modify"}]}, "Archive": None})
    assert folders["Archive"] == {"protected": False, "owner": None, "group": None, "aces": []}
    assert folders["Engineering"]["aces"] == [{"trustee": "engineering-write", "rights": "modify", "type": "allow",
                                              "applies_to": "this_folder_subfolders_files"}]
    with pytest.raises(FailJson, match=r"folders\['Engineering'\]"):
        validate({"Engineering": {"aces": [{"trustee": "x", "rights": "everything"}]}})
    with pytest.raises(FailJson, match="must be a dictionary"):
        validate({"Engineering": "modify"})
