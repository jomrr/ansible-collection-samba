=============================
jomrr.samba 0.1 Release Notes
=============================

.. contents:: Topics

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
