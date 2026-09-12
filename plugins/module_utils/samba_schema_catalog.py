# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""The schema extensions samba_schema_extension knows.

Each entry lists what an extension adds: ``attributes`` (attributeSchema
entries), ``classes`` (auxiliary classSchema entries), ``links`` (values added
to an existing class's mayContain or auxiliaryClass) and ``rights``
(controlAccessRight entries below Extended-Rights). Values are the directory's
text form; a GUID is its canonical string, which the I/O stores in the
directory's binary form where the property is binary.

Sources - nothing here is invented:

* ``laps``: Microsoft, "Windows LAPS schema and rights extensions for Windows
  Server Active Directory" (learn.microsoft.com, laps-technical-reference) and
  [MS-ADA2]. Neither publishes fixed schemaIDGUIDs for these attributes, so the
  directory assigns them; the property set's rightsGuid is fixed.
* ``sshpublickey`` and ``ldapcompat``: the Samba wiki's ``sshpubkey.ldif`` and
  ``ldapcompat.ldif`` ("Samba AD schema extensions"), schemaIDGUIDs included.
  The wiki links ``ldapPublicKey`` to no class; this catalog adds it as an
  auxiliary class of ``user`` so accounts (and computers) can carry a key.
"""

from __future__ import annotations

#: Properties stored as a binary GUID.
GUID_PROPERTIES = ("schemaIDGUID", "attributeSecurityGUID")

#: The Windows LAPS property set: the rightsGuid of the extended right and the
#: attributeSecurityGUID of the encrypted-password attributes.
LAPS_RIGHT_GUID = "f3531ec6-6330-4f8e-8d39-7a671fbac605"


def _attribute(cn, name, oid, syntax, om_syntax, single, flags, **extra):
    """An attributeSchema definition in the directory's text form."""
    values = {
        "cn": cn,
        "lDAPDisplayName": name,
        "attributeID": oid,
        "attributeSyntax": syntax,
        "oMSyntax": om_syntax,
        "isSingleValued": "TRUE" if single else "FALSE",
        "searchFlags": str(flags),
    }
    values.update(extra)
    return values


def _laps(suffix, index, syntax, om_syntax, single, flags, **extra):
    """A Windows LAPS attribute (OID 1.2.840.113556.1.6.44.1.<index>)."""
    return _attribute(
        "ms-LAPS-%s" % suffix, "msLAPS-%s" % suffix, "1.2.840.113556.1.6.44.1.%d" % index,
        syntax, om_syntax, single, flags, systemOnly="FALSE", isMemberOfPartialAttributeSet="FALSE",
        **extra
    )


def _aux_class(cn, oid, guid, may_contain, description):
    """An auxiliary classSchema definition (objectClassCategory 3, below top)."""
    return {
        "cn": cn,
        "lDAPDisplayName": cn,
        "governsID": oid,
        "subClassOf": "top",
        "objectClassCategory": "3",
        "mayContain": may_contain,
        "schemaIDGUID": guid,
        "description": description,
    }


_LAPS_ATTRIBUTES = [
    _laps("PasswordExpirationTime", 1, "2.5.5.16", "65", True, 0),
    _laps("Password", 2, "2.5.5.5", "19", True, 904),
    _laps("EncryptedPassword", 3, "2.5.5.10", "4", True, 904, attributeSecurityGUID=LAPS_RIGHT_GUID),
    _laps("EncryptedPasswordHistory", 4, "2.5.5.10", "4", False, 904, attributeSecurityGUID=LAPS_RIGHT_GUID),
    _laps("EncryptedDSRMPassword", 5, "2.5.5.10", "4", True, 904, attributeSecurityGUID=LAPS_RIGHT_GUID),
    _laps("EncryptedDSRMPasswordHistory", 6, "2.5.5.10", "4", False, 904, attributeSecurityGUID=LAPS_RIGHT_GUID),
    _laps(
        "CurrentPasswordVersion", 7, "2.5.5.10", "4", True, 904,
        attributeSecurityGUID=LAPS_RIGHT_GUID, rangeLower="16", rangeUpper="16",
    ),
]

EXTENSIONS = {
    "laps": {
        "attributes": _LAPS_ATTRIBUTES,
        "classes": [],
        "links": [("computer", "mayContain", [attribute["lDAPDisplayName"] for attribute in _LAPS_ATTRIBUTES])],
        "rights": [
            {
                "cn": "ms-LAPS-Encrypted-Password-Attributes",
                "displayName": "ms-LAPS-Encrypted-Password-Attributes",
                "rightsGuid": LAPS_RIGHT_GUID,
                "validAccesses": "48",
            },
        ],
    },
    "sshpublickey": {
        "attributes": [
            _attribute(
                "sshPublicKey", "sshPublicKey", "1.3.6.1.4.1.24552.500.1.1.1.13", "2.5.5.10", "4", False, 8,
                description="MANDATORY: OpenSSH Public key", schemaIDGUID="67c03072-1721-4fcd-bf6a-42341060d6fa",
            ),
        ],
        "classes": [
            _aux_class(
                "ldapPublicKey", "1.3.6.1.4.1.24552.500.1.1.2.0", "43c5c9fb-eb8d-45a6-933a-06c209c4a4a8",
                ["sshPublicKey"], "MANDATORY: OpenSSH LPK objectclass",
            ),
        ],
        "links": [("user", "auxiliaryClass", ["ldapPublicKey"])],
        "rights": [],
    },
    "ldapcompat": {
        "attributes": [
            _attribute(
                "nsUniqueId", "nsUniqueId", "2.16.840.1.113730.3.1.542", "2.5.5.10", "4", True, 9,
                description="MANDATORY: nsUniqueId compatability", schemaIDGUID="7b08323d-9f56-4275-a2d1-3a36871535ce",
            ),
            _attribute(
                "entryUUID", "entryUUID", "1.3.6.1.1.16.4", "2.5.5.10", "4", True, 9,
                description="MANDATORY: entryUUID compatability", schemaIDGUID="8330a79a-be87-49fa-9020-0d95a61375a1",
            ),
        ],
        "classes": [
            _aux_class(
                "ldapCompatPerson", "1.3.6.1.4.1.7165.4.2.3", "3650a6f3-bd15-4e24-9c5c-6fcc6f4dcae1",
                ["nsUniqueId", "entryUUID"], "MANDATORY: Unix LDAP compat person",
            ),
        ],
        "links": [],
        "rights": [],
    },
}
