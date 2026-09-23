# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure, samba-free logic for samba_password_policy and samba_password_settings.

Imports nothing from ``samba``. Both modules manage the same settings: the
domain's password policy lives as attributes of the domain object
(``minPwdLength`` and friends, the two booleans as bits of ``pwdProperties``),
a fine-grained policy is a ``msDS-PasswordSettings`` object (PSO) with its own
attributes. This layer translates between the module's settings (days,
minutes, booleans) and the directory's encoding (negative 100-nanosecond
ticks, TRUE/FALSE, the flag word), computes the diff and orchestrates the
writes through an injected ``io`` object, so it is unit-testable without the
bindings.

The encoding mirrors samba-tool (verified against samba 4.24.6): ages and
timers are negative ticks; ``maximum_age_days`` 0 means "never expires" and is
stored as NEVER (-2^63) for the domain and for PSOs alike; the domain's lockout
timers at 0 are stored as NEVER as well ("until an administrator unlocks"),
while a PSO stores a plain 0 for them, which is also what samba-tool writes.
"""

from __future__ import annotations


class SambaPasswordPolicyError(Exception):
    """User-facing error the modules turn into ``fail_json``."""


#: Module setting -> attribute of the domain object.
DOMAIN_ATTRIBUTES = {
    "minimum_length": "minPwdLength",
    "history_length": "pwdHistoryLength",
    "minimum_age_days": "minPwdAge",
    "maximum_age_days": "maxPwdAge",
    "lockout_threshold": "lockoutThreshold",
    "lockout_duration_minutes": "lockoutDuration",
    "lockout_window_minutes": "lockOutObservationWindow",
}

#: Module setting -> attribute of a PSO (``msDS-PasswordSettings``).
PSO_ATTRIBUTES = {
    "minimum_length": "msDS-MinimumPasswordLength",
    "history_length": "msDS-PasswordHistoryLength",
    "minimum_age_days": "msDS-MinimumPasswordAge",
    "maximum_age_days": "msDS-MaximumPasswordAge",
    "lockout_threshold": "msDS-LockoutThreshold",
    "lockout_duration_minutes": "msDS-LockoutDuration",
    "lockout_window_minutes": "msDS-LockoutObservationWindow",
    "complexity": "msDS-PasswordComplexityEnabled",
    "reversible_encryption": "msDS-PasswordReversibleEncryptionEnabled",
}

#: Ticks (100 ns) per unit of the interval settings.
TICKS = {
    "minimum_age_days": 24 * 60 * 60 * 10000000,
    "maximum_age_days": 24 * 60 * 60 * 10000000,
    "lockout_duration_minutes": 60 * 10000000,
    "lockout_window_minutes": 60 * 10000000,
}

#: The booleans as bits of the domain's ``pwdProperties``
#: (DOMAIN_PASSWORD_COMPLEX, DOMAIN_PASSWORD_STORE_CLEARTEXT).
FLAG_BITS = {"complexity": 1, "reversible_encryption": 16}

#: The directory's "never" for a relative time.
NEVER = -(1 << 63)

DOMAIN_FLAGS = "pwdProperties"
PSO_OBJECT_CLASS = "msDS-PasswordSettings"
PSO_PRECEDENCE = "msDS-PasswordSettingsPrecedence"
PSO_APPLIES_TO = "msDS-PSOAppliesTo"
PSO_CONTAINER_RDN = "CN=Password Settings Container,CN=System"


def settings_argument_spec():
    """The ``settings`` suboptions, the same for the domain and for a PSO."""
    return {name: {"type": "bool" if name in FLAG_BITS else "int"} for name in PSO_ATTRIBUTES}


def _units(ticks, unit):
    """Ticks -> units; a whole number unless the stored value is not whole."""
    if ticks == NEVER:
        return 0
    whole, remainder = divmod(-ticks, unit)
    return whole if remainder == 0 else whole + remainder / unit


def decode(record, pso=False):
    """Map a policy record (attribute -> list of text values) to the settings dict."""
    attributes = PSO_ATTRIBUTES if pso else DOMAIN_ATTRIBUTES
    settings = {}
    for name, attribute in attributes.items():
        value = record[attribute][0]
        if name in FLAG_BITS:
            settings[name] = value.upper() == "TRUE"
        elif name in TICKS:
            settings[name] = _units(int(value), TICKS[name])
        else:
            settings[name] = int(value)
    if not pso:
        flags = int(record[DOMAIN_FLAGS][0])
        for name, bit in FLAG_BITS.items():
            settings[name] = bool(flags & bit)
    return settings


def merge(current, requested):
    """Overlay the requested settings on the current ones and validate the result."""
    desired = dict(current)
    desired.update({name: value for name, value in requested.items() if value is not None})
    for name, value in desired.items():
        if name not in FLAG_BITS and value < 0:
            raise SambaPasswordPolicyError(f"{name} must not be negative")
    if desired["maximum_age_days"] and desired["minimum_age_days"] >= desired["maximum_age_days"]:
        raise SambaPasswordPolicyError("minimum_age_days must be less than maximum_age_days")
    return desired


def encode(requested, pso=False, flags=0):
    """Encode the requested settings (only those given) as attribute values.

    ``flags`` is the domain's current ``pwdProperties``; only the bits of the
    booleans given are changed, every other bit is kept.
    """
    attributes = PSO_ATTRIBUTES if pso else DOMAIN_ATTRIBUTES
    encoded = {}
    for name, attribute in attributes.items():
        value = requested.get(name)
        if value is None:
            continue
        if name in FLAG_BITS:
            text = "TRUE" if value else "FALSE"
        elif name in TICKS:
            never = value == 0 and (name == "maximum_age_days" or (not pso and name.startswith("lockout_")))
            text = str(NEVER if never else -int(value) * TICKS[name])
        else:
            text = str(value)
        encoded[attribute] = [text]
    if not pso:
        given = [name for name in FLAG_BITS if requested.get(name) is not None]
        for name in given:
            flags = flags | FLAG_BITS[name] if requested[name] else flags & ~FLAG_BITS[name]
        if given:
            encoded[DOMAIN_FLAGS] = [str(flags)]
    return encoded


def inherited_pso_attributes(domain):
    """A new PSO's attributes copied from the domain policy (as samba-tool does)."""
    attributes = {
        PSO_ATTRIBUTES[name]: list(domain[attribute]) for name, attribute in DOMAIN_ATTRIBUTES.items()
    }
    flags = int(domain[DOMAIN_FLAGS][0])
    attributes.update(encode({name: bool(flags & bit) for name, bit in FLAG_BITS.items()}, pso=True))
    # The domain stores "until an administrator unlocks" as NEVER; a PSO stores 0.
    for name in ("lockout_duration_minutes", "lockout_window_minutes"):
        attribute = PSO_ATTRIBUTES[name]
        if attributes[attribute] == [str(NEVER)]:
            attributes[attribute] = ["0"]
    return attributes


def changed_attributes(current, attributes):
    """The attributes whose values differ from ``current`` (all of them for a new object)."""
    if current is None:
        return dict(attributes)
    return {
        name: values for name, values in attributes.items()
        if sorted(current.get(name, [])) != sorted(values)
    }


def run_domain(params, check_mode, io):
    """Reconcile the domain password policy; settings not given stay untouched.

    ``io`` provides ``read_domain`` (the domain object's policy attributes as a
    record, ``_dn`` included) and ``modify(dn, changes)``. Injecting it keeps
    this function testable without the bindings.
    """
    current = io.read_domain()
    desired = merge(decode(current), params["settings"])
    attributes = encode(params["settings"], flags=int(current[DOMAIN_FLAGS][0]))
    changes = changed_attributes(current, attributes)
    if changes and not check_mode:
        io.modify(current["_dn"], changes)
    return {"changed": bool(changes), "dn": current["_dn"], "settings": desired}


def run_pso(params, check_mode, io):
    """Reconcile a fine-grained password settings object (PSO).

    ``io`` provides ``pso_dn(name)``, ``read_pso(name)`` (a record or None),
    ``read_domain``, ``resolve_subjects(names)``, ``add(dn, attributes)``,
    ``modify(dn, changes)`` and ``delete(dn)``. A new PSO inherits every
    setting not given from the domain policy; an existing one keeps its own.
    ``applies_to`` is the exact set of subjects.
    """
    name = params["name"]
    dn = io.pso_dn(name)
    current = io.read_pso(name)

    if params["state"] == "absent":
        if current is None:
            return {"changed": False, "dn": dn, "state": "absent"}
        if check_mode:
            return {"changed": True, "dn": dn, "state": "absent"}
        return {"changed": io.delete(dn), "dn": dn, "state": "absent"}

    baseline = io.read_domain() if current is None else current
    desired = merge(decode(baseline, pso=current is not None), params["settings"])
    attributes = encode(params["settings"], pso=True)
    if current is None:
        attributes = dict(inherited_pso_attributes(baseline), **attributes)
    subjects = io.resolve_subjects(params["applies_to"])
    attributes[PSO_PRECEDENCE] = [str(params["precedence"])]
    attributes[PSO_APPLIES_TO] = subjects
    if current is None:
        attributes["objectClass"] = [PSO_OBJECT_CLASS]
        if not subjects:
            del attributes[PSO_APPLIES_TO]
    changes = changed_attributes(current, attributes)
    if changes and not check_mode:
        if current is None:
            io.add(dn, attributes)
        else:
            io.modify(dn, changes)
    return {
        "changed": bool(changes),
        "dn": dn,
        "state": "present",
        "settings": desired,
        "applies_to": subjects,
        "precedence": params["precedence"],
    }
