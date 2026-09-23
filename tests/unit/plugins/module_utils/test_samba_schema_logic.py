# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the schema extension planner and the catalog (no samba required).

The reader is faked with canned records, so these exercise the phases, the
add-versus-complete decisions and the never-remove rule without the bindings."""

from __future__ import annotations

import uuid

import pytest
from ansible_collections.jomrr.samba.plugins.module_utils import samba_schema_catalog as catalog
from ansible_collections.jomrr.samba.plugins.module_utils import samba_schema_logic as logic

SCHEMA = "CN=Schema,CN=Configuration,DC=example,DC=com"
CONFIG = "CN=Configuration,DC=example,DC=com"


class FakeIO:
    """Answers reads from ``schema`` (by lDAPDisplayName) and ``rights`` (by rightsGuid)."""

    def __init__(self, schema=None, rights=None, master=True):
        self.schema = schema or {}
        self.rights = rights or {}
        self.master = master
        self.applied = []
        self.reloads = 0

    def schema_dn(self):
        return SCHEMA

    def config_dn(self):
        return CONFIG

    def require_schema_master(self):
        if not self.master:
            raise logic.SambaSchemaError("schema changes must run on the schema master")

    def find_schema(self, name, attrs):
        record = self.schema.get(name.lower())
        return None if record is None else dict(record)

    def find_right(self, rights_guid, attrs):
        record = self.rights.get(rights_guid)
        return None if record is None else dict(record)

    def apply(self, operations):
        self.applied.append([operation["label"] for operation in operations])

    def schema_update_now(self):
        self.reloads += 1


def base_classes():
    """The two structural classes every extension links into."""
    return {
        "user": {"_dn": f"CN=User,{SCHEMA}", "auxiliaryClass": ["posixAccount"], "mayContain": []},
        "computer": {"_dn": f"CN=Computer,{SCHEMA}", "auxiliaryClass": [], "mayContain": ["msDS-Foo"]},
    }


def labels(phases):
    return [operation["label"] for dummy, operations in phases for operation in operations]


# --- catalog sanity ------------------------------------------------------------

def test_catalog_definitions_are_consistent():
    for name, spec in catalog.EXTENSIONS.items():
        attribute_names = [attribute["lDAPDisplayName"] for attribute in spec["attributes"]]
        assert len(set(attribute_names)) == len(attribute_names), name
        for definition in spec["attributes"] + spec["classes"]:
            for prop in catalog.GUID_PROPERTIES:
                if prop in definition:
                    assert str(uuid.UUID(definition[prop])) == definition[prop]
        for definition in spec["classes"]:
            assert set(definition["mayContain"]) <= set(attribute_names), name
        for right in spec["rights"]:
            assert str(uuid.UUID(right["rightsGuid"])) == right["rightsGuid"]


def test_laps_attributes_match_the_microsoft_reference():
    by_name = {attribute["lDAPDisplayName"]: attribute for attribute in catalog.EXTENSIONS["laps"]["attributes"]}
    assert by_name["msLAPS-Password"]["attributeID"] == "1.2.840.113556.1.6.44.1.2"
    assert by_name["msLAPS-Password"]["searchFlags"] == "904"
    assert by_name["msLAPS-PasswordExpirationTime"]["searchFlags"] == "0"
    assert by_name["msLAPS-EncryptedPasswordHistory"]["isSingleValued"] == "FALSE"
    assert by_name["msLAPS-CurrentPasswordVersion"]["rangeLower"] == "16"
    assert by_name["msLAPS-EncryptedPassword"]["attributeSecurityGUID"] == catalog.LAPS_RIGHT_GUID
    assert "attributeSecurityGUID" not in by_name["msLAPS-Password"]


# --- planning ------------------------------------------------------------------

def test_fresh_schema_gets_everything_in_dependency_order():
    phases = logic.plan("sshpublickey", FakeIO(schema=base_classes()))
    assert [name for name, dummy in phases] == ["attributes and rights", "classes", "class links"]
    assert labels(phases) == [
        "add attributeSchema sshPublicKey",
        "add classSchema ldapPublicKey",
        "modify classSchema user (auxiliaryClass)",
    ]
    attribute_add = phases[0][1][0]
    assert attribute_add["dn"] == f"CN=sshPublicKey,{SCHEMA}"
    assert attribute_add["values"]["objectClass"] == ["attributeSchema"]
    assert attribute_add["values"]["schemaIDGUID"] == ["67c03072-1721-4fcd-bf6a-42341060d6fa"]
    class_add = phases[1][1][0]
    # An auxiliary class points its default category at itself.
    assert class_add["values"]["defaultObjectCategory"] == [f"CN=ldapPublicKey,{SCHEMA}"]
    link = phases[2][1][0]
    assert link["add"] == {"auxiliaryClass": ["ldapPublicKey"]}
    assert link["replace"] == {}


def test_laps_plans_rights_and_the_computer_link():
    phases = logic.plan("laps", FakeIO(schema=base_classes()))
    names = labels(phases)
    assert "add attributeSchema msLAPS-Password" in names
    assert "add controlAccessRight ms-LAPS-Encrypted-Password-Attributes" in names
    assert names[-1] == "modify classSchema computer (mayContain)"
    link = phases[2][1][0]
    assert len(link["add"]["mayContain"]) == 7
    right = next(operation for operation in phases[0][1] if "controlAccessRight" in operation["label"])
    assert right["dn"] == f"CN=ms-LAPS-Encrypted-Password-Attributes,CN=Extended-Rights,{CONFIG}"
    assert right["values"]["rightsGuid"] == [catalog.LAPS_RIGHT_GUID]


def complete_sshpublickey():
    schema = base_classes()
    schema["user"]["auxiliaryClass"].append("LDAPPUBLICKEY")
    schema["sshpublickey"] = {
        "_dn": f"CN=sshPublicKey,{SCHEMA}",
        "cn": ["sshPublicKey"], "lDAPDisplayName": ["sshPublicKey"],
        "attributeID": ["1.3.6.1.4.1.24552.500.1.1.1.13"], "attributeSyntax": ["2.5.5.10"], "oMSyntax": ["4"],
        "isSingleValued": ["FALSE"], "searchFlags": ["8"], "description": ["MANDATORY: OpenSSH Public key"],
        "schemaIDGUID": ["67c03072-1721-4fcd-bf6a-42341060d6fa"],
    }
    schema["ldappublickey"] = {
        "_dn": f"CN=ldapPublicKey,{SCHEMA}",
        "cn": ["ldapPublicKey"], "lDAPDisplayName": ["ldapPublicKey"],
        "governsID": ["1.3.6.1.4.1.24552.500.1.1.2.0"], "subClassOf": ["top"], "objectClassCategory": ["3"],
        "mayContain": ["sshPublicKey"], "schemaIDGUID": ["43c5c9fb-eb8d-45a6-933a-06c209c4a4a8"],
        "description": ["MANDATORY: OpenSSH LPK objectclass"],
        "defaultObjectCategory": [f"CN=ldapPublicKey,{SCHEMA}"],
    }
    return schema


def test_complete_extension_plans_nothing():
    # Case differences (LDAPPUBLICKEY) do not count as changes.
    assert labels(logic.plan("sshpublickey", FakeIO(schema=complete_sshpublickey()))) == []


def test_partial_extension_is_completed_never_reduced():
    schema = complete_sshpublickey()
    schema["sshpublickey"]["searchFlags"] = ["0"]
    schema["ldappublickey"]["mayContain"] = ["sshPublicKey", "someOtherAttribute"]
    schema["user"]["auxiliaryClass"] = ["posixAccount"]
    phases = logic.plan("sshpublickey", FakeIO(schema=schema))
    assert labels(phases) == [
        "modify attributeSchema sshPublicKey (searchFlags)",
        "modify classSchema user (auxiliaryClass)",
    ]
    # The differing property is set; the class's extra mayContain value stays.
    assert phases[0][1][0]["replace"] == {"searchFlags": ["8"]}
    assert phases[1][1] == []


def test_missing_linked_class_is_a_clean_error():
    with pytest.raises(logic.SambaSchemaError):
        logic.plan("sshpublickey", FakeIO(schema={}))


# --- run -----------------------------------------------------------------------

def test_run_applies_non_empty_phases_with_a_reload_each():
    io = FakeIO(schema=base_classes())
    result = logic.run({"extension": "sshpublickey"}, False, io)
    assert result["changed"] is True
    assert result["extension"] == "sshpublickey"
    assert len(result["changes"]) == 3
    assert io.applied == [
        ["add attributeSchema sshPublicKey"],
        ["add classSchema ldapPublicKey"],
        ["modify classSchema user (auxiliaryClass)"],
    ]
    assert io.reloads == 3


def test_run_check_mode_plans_without_applying():
    io = FakeIO(schema=base_classes())
    result = logic.run({"extension": "laps"}, True, io)
    assert result["changed"] is True
    assert io.applied == []
    assert io.reloads == 0


def test_run_is_a_noop_when_complete():
    io = FakeIO(schema=complete_sshpublickey())
    result = logic.run({"extension": "sshpublickey"}, False, io)
    assert result["changed"] is False
    assert result["changes"] == []
    assert io.applied == []


def test_run_refuses_a_dc_that_is_not_the_schema_master():
    io = FakeIO(schema=base_classes(), master=False)
    with pytest.raises(logic.SambaSchemaError):
        logic.run({"extension": "laps"}, False, io)
    assert io.applied == []
