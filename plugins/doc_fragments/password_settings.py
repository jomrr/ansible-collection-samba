# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jonas Mauer
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""The password settings shared by samba_password_policy and samba_password_settings."""

from __future__ import annotations


class ModuleDocFragment(object):
    """The ``settings`` option, the same for the domain policy and for a PSO."""

    DOCUMENTATION = r"""
options:
  settings:
    description:
      - Password and lockout settings to manage.
      - Settings not given are left untouched; a new fine-grained policy copies
        them from the domain policy.
    type: dict
    default: {}
    suboptions:
      minimum_length:
        description: Minimum password length in characters.
        type: int
      history_length:
        description: Number of previous passwords that cannot be reused.
        type: int
      minimum_age_days:
        description: Minimum password age in days; C(0) allows an immediate change.
        type: int
      maximum_age_days:
        description: Maximum password age in days; C(0) means passwords never expire.
        type: int
      lockout_threshold:
        description: Failed sign-ins before the account is locked out; C(0) disables lockout.
        type: int
      lockout_duration_minutes:
        description:
          - Minutes an account stays locked out; C(0) keeps it locked until an
            administrator unlocks it.
        type: int
      lockout_window_minutes:
        description: Minutes after which the failed sign-in counter resets.
        type: int
      complexity:
        description: Require password complexity.
        type: bool
      reversible_encryption:
        description: Store passwords with reversible encryption.
        type: bool
"""
