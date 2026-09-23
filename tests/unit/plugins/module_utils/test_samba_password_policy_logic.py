# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE)
"""Unit tests for the pure password policy logic (no samba required).

The I/O is faked, so these exercise the tick/flag encoding (verified against
samba-tool), the diff and the domain/PSO orchestration without the bindings."""

from __future__ import annotations

import pytest
from ansible_collections.jomrr.samba.plugins.module_utils import samba_password_policy_logic as logic

DAY = 24 * 60 * 60 * 10000000
MINUTE = 60 * 10000000
NEVER = str(logic.NEVER)
DOMAIN_DN = "DC=example,DC=com"


def domain_record(**over):
    record = {
        "_dn": DOMAIN_DN,
        "minPwdLength": ["7"],
        "pwdHistoryLength": ["24"],
        "minPwdAge": [str(-1 * DAY)],
        "maxPwdAge": [str(-42 * DAY)],
        "lockoutThreshold": ["0"],
        "lockoutDuration": [str(-30 * MINUTE)],
        "lockOutObservationWindow": [str(-30 * MINUTE)],
        "pwdProperties": ["1"],
    }
    record.update(over)
    return record


def pso_record(**over):
    record = {
        "_dn": "CN=admins,CN=Password Settings Container,CN=System,DC=example,DC=com",
        "msDS-MinimumPasswordLength": ["16"],
        "msDS-PasswordHistoryLength": ["24"],
        "msDS-MinimumPasswordAge": [str(-1 * DAY)],
        "msDS-MaximumPasswordAge": [str(-60 * DAY)],
        "msDS-LockoutThreshold": ["5"],
        "msDS-LockoutDuration": [str(-30 * MINUTE)],
        "msDS-LockoutObservationWindow": [str(-30 * MINUTE)],
        "msDS-PasswordComplexityEnabled": ["TRUE"],
        "msDS-PasswordReversibleEncryptionEnabled": ["FALSE"],
        "msDS-PasswordSettingsPrecedence": ["10"],
        "msDS-PSOAppliesTo": ["CN=Domain Admins,CN=Users,DC=example,DC=com"],
    }
    record.update(over)
    return record


def no_settings(**over):
    settings = {name: None for name in logic.PSO_ATTRIBUTES}
    settings.update(over)
    return settings


class FakeIO:
    """Records writes and answers reads from canned records; no samba required."""

    def __init__(self, domain=None, pso=None, subjects=None):
        self.domain = domain_record() if domain is None else domain
        self.pso = pso
        self.subjects = subjects or {}
        self.calls = []

    def read_domain(self):
        return dict(self.domain)

    def pso_dn(self, name):
        return f"CN={name},CN=Password Settings Container,CN=System,{DOMAIN_DN}"

    def read_pso(self, name):
        return None if self.pso is None else dict(self.pso)

    def resolve_subjects(self, names):
        self.calls.append(("resolve_subjects", list(names)))
        return sorted({self.subjects[name] for name in names})

    def add(self, dn, attributes):
        self.calls.append(("add", dn, dict(attributes)))

    def modify(self, dn, changes):
        self.calls.append(("modify", dn, dict(changes)))

    def delete(self, dn):
        self.calls.append(("delete", dn))
        return True


def call_names(fake):
    return [call[0] for call in fake.calls]


# --- decoding -----------------------------------------------------------------

def test_decode_domain_ticks_and_flags():
    settings = logic.decode(domain_record(pwdProperties=["17"]))
    assert settings["minimum_length"] == 7
    assert settings["minimum_age_days"] == 1
    assert settings["maximum_age_days"] == 42
    assert settings["lockout_duration_minutes"] == 30
    assert settings["complexity"] is True
    assert settings["reversible_encryption"] is True


def test_decode_never_reads_as_zero_and_partial_units_as_float():
    settings = logic.decode(domain_record(maxPwdAge=[NEVER], lockoutDuration=[str(-(30 * MINUTE + MINUTE // 2))]))
    assert settings["maximum_age_days"] == 0
    assert settings["lockout_duration_minutes"] == 30.5


def test_decode_pso_booleans():
    settings = logic.decode(pso_record(), pso=True)
    assert settings["complexity"] is True
    assert settings["reversible_encryption"] is False
    assert settings["maximum_age_days"] == 60


# --- encoding -----------------------------------------------------------------

def test_encode_domain_only_given_settings_with_samba_tool_never_rules():
    encoded = logic.encode(
        no_settings(maximum_age_days=0, lockout_duration_minutes=0, minimum_age_days=0, history_length=12), flags=1
    )
    assert encoded == {
        "maxPwdAge": [NEVER],
        "lockoutDuration": [NEVER],
        "minPwdAge": ["0"],
        "pwdHistoryLength": ["12"],
    }


def test_encode_domain_flags_keep_unrelated_bits():
    # 8 (lockout admins) is not ours and must survive; complexity off, reversible on.
    encoded = logic.encode(no_settings(complexity=False, reversible_encryption=True), flags=1 | 8)
    assert encoded == {"pwdProperties": [str(8 | 16)]}


def test_encode_domain_without_booleans_leaves_the_flag_word_alone():
    assert "pwdProperties" not in logic.encode(no_settings(minimum_length=9), flags=1)


def test_encode_pso_stores_plain_zero_for_lockout_timers():
    encoded = logic.encode(no_settings(lockout_duration_minutes=0, maximum_age_days=0, complexity=True), pso=True)
    assert encoded == {
        "msDS-LockoutDuration": ["0"],
        "msDS-MaximumPasswordAge": [NEVER],
        "msDS-PasswordComplexityEnabled": ["TRUE"],
    }


def test_encode_ticks_are_negative_hundred_nanoseconds():
    encoded = logic.encode(no_settings(maximum_age_days=90, lockout_window_minutes=45))
    assert encoded["maxPwdAge"] == [str(-90 * DAY)]
    assert encoded["lockOutObservationWindow"] == [str(-45 * MINUTE)]


# --- merge / validation -------------------------------------------------------

def test_merge_keeps_current_and_validates():
    current = logic.decode(domain_record())
    desired = logic.merge(current, no_settings(minimum_length=12))
    assert desired["minimum_length"] == 12
    assert desired["history_length"] == 24
    with pytest.raises(logic.SambaPasswordPolicyError):
        logic.merge(current, no_settings(minimum_length=-1))
    with pytest.raises(logic.SambaPasswordPolicyError):
        logic.merge(current, no_settings(minimum_age_days=42))
    # max age 0 (never) exempts the age relation.
    assert logic.merge(current, no_settings(maximum_age_days=0, minimum_age_days=42))["maximum_age_days"] == 0


# --- inheritance for a new PSO ------------------------------------------------

def test_inherited_pso_attributes_copy_the_domain():
    attributes = logic.inherited_pso_attributes(domain_record(lockoutDuration=[NEVER], pwdProperties=["17"]))
    assert attributes["msDS-MinimumPasswordLength"] == ["7"]
    assert attributes["msDS-MaximumPasswordAge"] == [str(-42 * DAY)]
    assert attributes["msDS-PasswordComplexityEnabled"] == ["TRUE"]
    assert attributes["msDS-PasswordReversibleEncryptionEnabled"] == ["TRUE"]
    # The domain's NEVER lockout becomes a PSO's 0, as samba-tool writes it.
    assert attributes["msDS-LockoutDuration"] == ["0"]


# --- domain orchestration -----------------------------------------------------

def test_run_domain_noop_when_equal():
    fake = FakeIO()
    result = logic.run_domain({"settings": no_settings(minimum_length=7, complexity=True)}, False, fake)
    assert result["changed"] is False
    assert "modify" not in call_names(fake)
    assert result["settings"]["minimum_length"] == 7


def test_run_domain_writes_only_the_differences():
    fake = FakeIO()
    result = logic.run_domain({"settings": no_settings(minimum_length=12, reversible_encryption=True)}, False, fake)
    assert result["changed"] is True
    assert ("modify", DOMAIN_DN, {"minPwdLength": ["12"], "pwdProperties": ["17"]}) in fake.calls
    assert result["settings"]["minimum_length"] == 12
    assert result["settings"]["history_length"] == 24


def test_run_domain_check_mode_reports_without_writing():
    fake = FakeIO()
    result = logic.run_domain({"settings": no_settings(minimum_length=12)}, True, fake)
    assert result["changed"] is True
    assert "modify" not in call_names(fake)


# --- PSO orchestration --------------------------------------------------------

def pso_params(**over):
    params = {
        "name": "admins",
        "precedence": 10,
        "applies_to": ["Domain Admins"],
        "settings": no_settings(),
        "state": "present",
    }
    params.update(over)
    return params


ADMINS_DN = "CN=Domain Admins,CN=Users,DC=example,DC=com"


def test_run_pso_creates_with_inherited_settings_and_subjects():
    fake = FakeIO(subjects={"Domain Admins": ADMINS_DN})
    result = logic.run_pso(pso_params(settings=no_settings(minimum_length=16)), False, fake)
    assert result["changed"] is True
    added = next(call for call in fake.calls if call[0] == "add")[2]
    assert added["objectClass"] == ["msDS-PasswordSettings"]
    assert added["msDS-PasswordSettingsPrecedence"] == ["10"]
    assert added["msDS-PSOAppliesTo"] == [ADMINS_DN]
    assert added["msDS-MinimumPasswordLength"] == ["16"]
    # Not given -> inherited from the domain policy.
    assert added["msDS-PasswordHistoryLength"] == ["24"]
    assert added["msDS-PasswordComplexityEnabled"] == ["TRUE"]
    assert result["settings"]["minimum_length"] == 16
    assert result["settings"]["history_length"] == 24
    assert result["applies_to"] == [ADMINS_DN]


def test_run_pso_create_without_subjects_omits_the_attribute():
    fake = FakeIO()
    logic.run_pso(pso_params(applies_to=[]), False, fake)
    added = next(call for call in fake.calls if call[0] == "add")[2]
    assert "msDS-PSOAppliesTo" not in added


def test_run_pso_create_check_mode_does_not_write():
    fake = FakeIO(subjects={"Domain Admins": ADMINS_DN})
    result = logic.run_pso(pso_params(), True, fake)
    assert result["changed"] is True
    assert "add" not in call_names(fake)


def test_run_pso_existing_is_idempotent():
    fake = FakeIO(pso=pso_record(), subjects={"Domain Admins": ADMINS_DN})
    result = logic.run_pso(pso_params(settings=no_settings(minimum_length=16, complexity=True)), False, fake)
    assert result["changed"] is False
    assert "modify" not in call_names(fake)
    assert result["settings"]["maximum_age_days"] == 60


def test_run_pso_modifies_only_the_differences():
    fake = FakeIO(pso=pso_record(), subjects={"Domain Admins": ADMINS_DN, "jdoe": "CN=jdoe,CN=Users,DC=example,DC=com"})
    result = logic.run_pso(
        pso_params(precedence=5, applies_to=["jdoe", "Domain Admins"], settings=no_settings(minimum_length=20)),
        False, fake,
    )
    assert result["changed"] is True
    changes = next(call for call in fake.calls if call[0] == "modify")[2]
    assert changes == {
        "msDS-MinimumPasswordLength": ["20"],
        "msDS-PasswordSettingsPrecedence": ["5"],
        "msDS-PSOAppliesTo": ["CN=Domain Admins,CN=Users,DC=example,DC=com", "CN=jdoe,CN=Users,DC=example,DC=com"],
    }
    # Settings not given keep the PSO's own values, not the domain's.
    assert result["settings"]["maximum_age_days"] == 60


def test_run_pso_empty_applies_to_removes_every_assignment():
    fake = FakeIO(pso=pso_record())
    logic.run_pso(pso_params(applies_to=[]), False, fake)
    changes = next(call for call in fake.calls if call[0] == "modify")[2]
    assert changes == {"msDS-PSOAppliesTo": []}


def test_run_pso_absent_deletes_and_is_a_noop_when_missing():
    fake = FakeIO(pso=pso_record())
    result = logic.run_pso(pso_params(state="absent"), False, fake)
    assert result["changed"] is True
    assert "delete" in call_names(fake)
    fake = FakeIO(pso=None)
    result = logic.run_pso(pso_params(state="absent"), False, fake)
    assert result["changed"] is False
    assert "delete" not in call_names(fake)


def test_run_pso_absent_check_mode_does_not_delete():
    fake = FakeIO(pso=pso_record())
    result = logic.run_pso(pso_params(state="absent"), True, fake)
    assert result["changed"] is True
    assert "delete" not in call_names(fake)
