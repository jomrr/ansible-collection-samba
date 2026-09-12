# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared LDB access for the samba object modules.

The lazy ``ldb`` import, the LDB message value helpers, the safe DN construction
and the existence probes live here, plus :class:`SambaObjectIO`, the common
modify/delete/move base of the movable, deletable directory objects (users and
groups). The object-specific attribute mappings stay in ``samba_<object>_io``.

The ``samba``/``ldb`` bindings are imported lazily (via importlib inside a
function), so importing this module never requires them - that keeps the static
sanity phase green, the same constraint as in samba_conn.py.
"""

from __future__ import annotations

import importlib


def load_ldb():
    """Import and return the ``ldb`` module lazily."""
    return importlib.import_module("ldb")


def error_text(exc):
    """Return the message of an ``ldb.LdbError`` (``(code, message)``) or ``str(exc)``.

    ``str()`` of an LdbError is the tuple repr; user-facing messages want the
    text alone.
    """
    args = getattr(exc, "args", ())
    if len(args) == 2 and isinstance(args[0], int):
        return str(args[1]).strip()
    return str(exc).strip()


def first_value(message, attr):
    """Return the first value of an LDB message attribute as ``str`` or ``None``."""
    element = message.get(attr)
    if element is None or len(element) == 0:
        return None
    return str(element[0])


def int_value(message, attr):
    """Return an integer LDB attribute as ``int`` or ``None``.

    LDB stores integers as decimal text; normalising on read keeps the diff an
    int-vs-int comparison, so an unchanged uid/gid never looks like a change.
    """
    raw = first_value(message, attr)
    return int(raw) if raw is not None else None


def parse_dn(samdb, text):
    """Parse a DN string into an ldb.Dn (raises ValueError if malformed)."""
    return load_ldb().Dn(samdb, text)


def build_child_dn(samdb, rdn_attr, name, parent_dn):
    """Build ``<rdn_attr>=<name>,<parent_dn>`` with the name value safely escaped.

    Uses ``ldb.Dn.set_component`` so DN metacharacters in ``name`` cannot inject
    extra DN components.
    """
    ldb = load_ldb()
    dn = ldb.Dn(samdb, "%s=placeholder" % rdn_attr)
    dn.set_component(0, rdn_attr, name)
    dn.add_base(parent_dn)
    return dn


def default_users_dn(samdb):
    """Return the well-known Users container DN (CN=Users,<domaindn>)."""
    dsdb = importlib.import_module("samba.dsdb")
    return samdb.get_wellknown_dn(samdb.get_default_basedn(), dsdb.DS_GUID_USERS_CONTAINER)


def same_parent(samdb, object_dn, parent_dn):
    """True if ``object_dn``'s parent equals ``parent_dn`` (normalized DN compare)."""
    return parse_dn(samdb, object_dn).parent() == parent_dn


def lookup_dn(samdb, dn):
    """Return the directory's own spelling of ``dn``, or None if it does not exist.

    A base-scoped read; the one attribute requested keeps it light (over LDAP an
    empty attribute list means "all").
    """
    ldb = load_ldb()
    try:
        res = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=["distinguishedName"])
    except ldb.LdbError as err:
        if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
            return None
        raise
    return str(res[0].dn) if len(res) else None


def dn_exists(samdb, dn):
    """True if ``dn`` exists in the directory."""
    return lookup_dn(samdb, dn) is not None


def reparent_dn(samdb, object_dn, parent_dn):
    """Return ``object_dn``'s RDN under ``parent_dn`` (move target; RDN preserved)."""
    source = parse_dn(samdb, object_dn)
    return build_child_dn(samdb, source.get_rdn_name(), source.get_rdn_value(), parent_dn)


def rfc2307_provisioned(samdb):
    """True if the domain was provisioned with C(--use-rfc2307).

    The provision step creates the fake-ypserver container
    ``CN=ypServ30,CN=RpcServices,CN=System,<domaindn>`` only with that option,
    so its existence is the reliable, LDAP-queryable indicator. Shared by the
    user and group I/O layers, it is a single base-scoped existence search and is
    only ever called when a POSIX attribute was actually requested.
    """
    dn = parse_dn(samdb, "CN=ypServ30,CN=RpcServices,CN=System,%s" % samdb.domain_dn())
    return dn_exists(samdb, dn)


class SambaObjectIO:
    """Common LDB write operations of the movable, deletable object modules.

    A subclass sets ``error_cls`` (its user-facing error) and ``noun`` (the
    object kind named in messages) and adds the object-specific reads and
    writes. Concurrent-change races (the object vanished, the target exists)
    surface as clear errors or idempotent no-ops, never as tracebacks.
    """

    error_cls = Exception
    noun = "object"

    def __init__(self, samdb):
        self.samdb = samdb
        #: The default Users container, read once per run (a wellKnownObjects
        #: lookup on the DC) and shared by needs_move and parent_exists.
        self._default_container = None

    def rfc2307_provisioned(self):
        """True if the domain was provisioned with C(--use-rfc2307)."""
        return rfc2307_provisioned(self.samdb)

    def _modify(self, message, dn):
        """Apply an LDB modify, mapping a vanished object to a clear error."""
        ldb = load_ldb()
        try:
            self.samdb.modify(message)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                raise self.error_cls("%s '%s' vanished before it could be modified" % (self.noun, dn))
            raise

    def delete(self, dn):
        """Delete the object by DN.

        Returns ``True`` if it was deleted, ``False`` if it was already gone
        (concurrent delete) - an idempotent no-op, not an error.
        """
        ldb = load_ldb()
        try:
            self.samdb.delete(ldb.Dn(self.samdb, dn))
            return True
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                return False
            raise

    def _desired_parent(self, path):
        """Return the desired parent DN (path, or the default Users container).

        The default container is looked up once and reused, so callers must not
        modify it; a path is parsed afresh each time (``container_below_domain``
        modifies that copy).
        """
        if path is None:
            if self._default_container is None:
                self._default_container = default_users_dn(self.samdb)
            return self._default_container
        try:
            return parse_dn(self.samdb, path)
        except ValueError:
            raise self.error_cls("path '%s' is not a valid distinguished name" % path)

    def container_below_domain(self, path):
        """Return ``path`` relative to the domain DN, the form ``newuser``/``newgroup`` take.

        ``None`` for an unset path (samba's default container) and for the domain
        root itself, which the relative form cannot express - the object is then
        created in the default container and moved. A path that is not below the
        domain is an error.
        """
        if path is None:
            return None
        container = self._desired_parent(path)
        base = self.samdb.get_default_basedn()
        if not container.is_child_of(base):
            raise self.error_cls("path '%s' is not below the domain '%s'" % (path, base))
        container.remove_base_components(len(base))
        return str(container) or None

    def parent_exists(self, path):
        """Return True if the desired parent container exists."""
        return dn_exists(self.samdb, self._desired_parent(path))

    def needs_move(self, current_dn, path):
        """Return True if the object's parent differs from the desired location."""
        return not same_parent(self.samdb, current_dn, self._desired_parent(path))

    def move(self, current_dn, path):
        """Move (rename) the object under the desired parent, preserving its RDN."""
        ldb = load_ldb()
        target = reparent_dn(self.samdb, current_dn, self._desired_parent(path))
        try:
            self.samdb.rename(parse_dn(self.samdb, current_dn), target)
        except ldb.LdbError as err:
            if err.args[0] == ldb.ERR_NO_SUCH_OBJECT:
                raise self.error_cls("%s vanished before it could be moved" % self.noun)
            if err.args[0] == ldb.ERR_ENTRY_ALREADY_EXISTS:
                raise self.error_cls("an object already exists at the target location")
            raise
        return str(target)
