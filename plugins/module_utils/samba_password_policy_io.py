# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""LDB I/O shared by samba_password_policy and samba_password_settings.

Records are plain dicts (attribute -> list of text values, plus ``_dn``), so
the logic layer stays samba-free. The ``samba``/``ldb`` bindings are imported
lazily (via ``samba_ldb.load_ldb``), so importing this module never requires
them.
"""

from __future__ import annotations

from ansible_collections.jomrr.samba.plugins.module_utils import samba_ldb
from ansible_collections.jomrr.samba.plugins.module_utils import samba_password_policy_logic as logic

#: Attributes read from the domain object.
DOMAIN_ATTRS = list(logic.DOMAIN_ATTRIBUTES.values()) + [logic.DOMAIN_FLAGS]
#: Attributes read from a PSO.
PSO_ATTRS = list(logic.PSO_ATTRIBUTES.values()) + [logic.PSO_PRECEDENCE, logic.PSO_APPLIES_TO]


class PasswordPolicyIO(samba_ldb.SambaObjectIO):
    """Read and write the domain policy and PSOs over the shared LDAP connection."""

    error_cls = logic.SambaPasswordPolicyError
    noun = "password settings object"

    def _read(self, dn, attrs):
        """A record of ``dn`` with ``attrs`` as text values, or None if absent."""
        ldb = samba_ldb.load_ldb()
        try:
            res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=attrs)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                return None
            raise
        message = res[0]
        record = {"_dn": str(message.dn)}
        for attr in attrs:
            element = message.get(attr)
            record[attr] = [str(value) for value in element] if element is not None else []
        return record

    def read_domain(self):
        """The domain object's password policy attributes."""
        return self._read(self.samdb.domain_dn(), DOMAIN_ATTRS)

    def pso_dn(self, name):
        """The DN of PSO ``name`` below the Password Settings Container, name escaped."""
        container = samba_ldb.parse_dn(
            self.samdb, f"{logic.PSO_CONTAINER_RDN},{self.samdb.domain_dn()}"
        )
        return str(samba_ldb.build_child_dn(self.samdb, "CN", name, container))

    def read_pso(self, name):
        """The PSO's record, or None if it does not exist."""
        return self._read(self.pso_dn(name), PSO_ATTRS)

    def add(self, dn, attributes):
        """Add an object with the given values; a concurrent add is a clear error."""
        ldb = samba_ldb.load_ldb()
        message = ldb.Message(ldb.Dn(self.samdb, dn))
        for attr, values in attributes.items():
            message[attr] = ldb.MessageElement(values, ldb.FLAG_MOD_ADD, attr)
        try:
            self.samdb.add(message)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_ENTRY_ALREADY_EXISTS:
                raise logic.SambaPasswordPolicyError(f"'{dn}' already exists (created concurrently?)")
            raise

    def modify(self, dn, changes):
        """Replace the given attribute values in one modify."""
        ldb = samba_ldb.load_ldb()
        message = ldb.Message(ldb.Dn(self.samdb, dn))
        for attr, values in changes.items():
            message[attr] = ldb.MessageElement(values, ldb.FLAG_MOD_REPLACE, attr)
        self._modify(message, dn)

    def resolve_subjects(self, names):
        """Resolve users and global security groups, by sAMAccountName or DN, to DNs.

        A PSO applies to users and global security groups only, so the search
        is restricted to those; the DNs come back sorted and unique. Names that
        do not resolve to exactly one such object are reported together.
        """
        ldb = samba_ldb.load_ldb()
        resolved = set()
        missing = []
        for name in dict.fromkeys(names):
            escaped = ldb.binary_encode(name)
            expression = (
                f"(&(|(sAMAccountName={escaped})(distinguishedName={escaped}))"
                "(|(&(objectClass=user)(!(objectClass=computer)))"
                "(&(objectClass=group)(groupType=-2147483646))))"
            )
            res = self.samdb.search(
                base=self.samdb.domain_dn(),
                scope=ldb.SCOPE_SUBTREE,
                expression=expression,
                attrs=["sAMAccountName"],
            )
            if len(res) != 1:
                missing.append(name)
                continue
            resolved.add(str(res[0].dn))
        if missing:
            raise logic.SambaPasswordPolicyError(
                "not a user or global security group: {}".format(", ".join(missing))
            )
        return sorted(resolved)
