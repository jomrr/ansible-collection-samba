=============================
jomrr.samba 1.0 Release Notes
=============================

.. contents:: Topics

v1.0.2
======

Bugfixes
--------

- Changelog generation - enable changelog_nice_yaml in changelogs/config.yaml so the generated changelogs/changelog.yaml is indented the way yamllint and ansible-lint expect (and carries a --- header). This removes the yaml[indentation] findings a consumer saw when linting the installed collection, without excluding the file from linting. Changelog content is unchanged (formatting only).
- Changelog hygiene - wrap the over-long single-line changelog fragment entries as folded block scalars so each line stays within the 160-character limit, and stop shipping the transient changelogs/fragments directory in the release artifact (it is build-only input, consumed at release time). Fixes yaml[line-length] findings a consumer saw when linting the installed collection. No changelog text changed.

v1.0.1
======

Bugfixes
--------

- Documentation rendering - replace the C(M()) module-reference markup macro with C(C()) (and structured C(seealso) entries) in samba_provision, samba_dns_record_info, samba_dns_zone_info and samba_join_sssd. The macro is valid markup and renders locally, but the Galaxy/Automation Hub documentation renderer could not parse it and fell back to the raw JSON dump for those four modules. The collection itself was unaffected (import, install and functionality were always fine); only the rendered doc pages were.

v1.0.0
======

Minor Changes
-------------

- New module samba_join_dc to join a host to an existing domain as an additional Samba AD domain controller (state=present only; runs locally on the joining host; binary idempotency with a three-way discriminator that refuses to overwrite a DC of a different domain).
- New module samba_join_member to join a host to an existing domain as a Samba AD member server (state=present only; runs locally on the joining host; binary idempotency via net ads testjoin; requires a pre-configured smb.conf with server role = member server).
- New module samba_join_sssd to join a host to an existing domain via adcli, writing a Kerberos keytab for SSSD (state=present only; runs locally on the joining host; binary idempotency via adcli testjoin; the join password is fed to adcli on stdin, never on the command line).
- New module samba_provision to provision the first Samba AD domain controller of a new domain (state=present only; runs locally on the future DC; binary idempotency, never re-provisions an existing domain).

v0.1.0
======

Minor Changes
-------------

- New module samba_dns_record to manage DNS records (A, AAAA, CNAME, PTR, MX, TXT, SRV, NS) in a Samba AD DC.
- New module samba_dns_record_info to query DNS records from a Samba AD DC.
- New module samba_dns_zone to manage DNS zones (forward and reverse, all samba-tool supported types) in a Samba AD DC.
- New module samba_dns_zone_info to query DNS zones from a Samba AD DC.
- New module samba_group to manage groups (scope, category, members) in a Samba AD DC.
- New module samba_group_info to query groups from a Samba AD DC.
- New module samba_ou to manage organizational units in a Samba AD DC.
- New module samba_ou_info to query organizational units from a Samba AD DC.
- samba_user - add update_password (on_create/always) to control password updates on existing users.
- samba_user - new module to manage users (create, modify, remove, enable/disable) in a Samba AD DC via the native Python bindings.
- samba_user and samba_group - add RFC2307/POSIX attributes (uidNumber, gidNumber, unixHomeDirectory, loginShell, gecos); samba_user_info and samba_group_info return them.
- samba_user and samba_group - add path parameter to place objects in an OU, with idempotent move on change.
- samba_user_info - new module to query users from a Samba AD DC.
