=============================
jomrr.samba 2.3 Release Notes
=============================

.. contents:: Topics

v2.3.1
======

Bugfixes
--------

- samba_provision - set the sysvol NT ACLs as C(samba-tool domain provision) does; samba's C(provision()) skips them by default. A DC provisioned with an earlier version of this module needs a one-time C(samba-tool ntacl sysvolreset).

v2.3.0
======

Minor Changes
-------------

- New module samba_ntacl to set the NT ACL, owner and group of a share root and of managed folders (created if missing) through the share's VFS stack on the file server, and to pass inheritance and optionally ownership on to the other files and folders (C(propagate), C(propagate_owner)).

New Modules
-----------

- samba_ntacl - Manage the NT ACLs of a Samba share

v2.2.0
======

Minor Changes
-------------

- New module samba_computer to keep an existing computer account in a container or OU (a move, idempotent, with check mode); the default is the domain's Computers container, domain controller accounts are never matched, and accounts are never created or deleted.
- New module samba_computer_info to query computer accounts, the same accounts samba_computer manages (domain controllers and managed service accounts excluded).
- samba_join_member - new option C(computer_ou) to create the machine account in a given OU, as samba_join_sssd offers; an existing account is not moved.

Bugfixes
--------

- Documentation rendering - replace the remaining C(M()) module-reference markup macros with C(C()) (the modules are already in C(seealso)) in samba_group and samba_group_info. As in 1.0.1, the Galaxy/Automation Hub documentation renderer cannot parse the macro; only the rendered doc pages were affected.
- samba_join_member - C(domain.workgroup) after a join is the NetBIOS workgroup from smb.conf, as documented and as a run without a join returns; it was the DNS domain name the join binding reports.

New Modules
-----------

- samba_computer - Keep a computer account in a container of a Samba AD DC
- samba_computer_info - Query computer accounts from a Samba AD DC

v2.1.0
======

Minor Changes
-------------

- samba_dns_zone - C(aging), C(norefresh_interval) and C(refresh_interval) manage a zone's record aging like C(samba-tool dns zoneoptions).
- samba_dns_zone - a refused zone property write names the property and the zone.
- samba_dns_zone_info - each zone reports its C(aging), C(norefresh_interval) and C(refresh_interval).

v2.0.0
======

Minor Changes
-------------

- New module samba_password_policy to manage the domain password policy (length, history, ages, lockout, complexity, reversible encryption) in a Samba AD DC; settings not given stay untouched, unrelated C(pwdProperties) bits are preserved.
- New module samba_password_settings to manage fine-grained password settings objects (PSOs) and the exact set of users and global security groups they apply to; a new PSO inherits the settings not given from the domain policy, as C(samba-tool domain passwordsettings pso create) does.
- New module samba_schema_extension to add a known schema extension to a Samba AD domain on the schema master, from a catalog of published definitions - C(laps) (the Windows LAPS attributes, property set and their place on the computer class), C(sshpublickey) (OpenSSH public keys on user accounts) and C(ldapcompat) (entryUUID/nsUniqueId) - completing a partly present extension and never removing schema.
- samba_group - C(members) accepts distinguished names as well as sAMAccountNames, so the member DNs C(samba_group_info) returns can be fed back unchanged (the read mirror the DNS modules already offer). A DN is checked to exist and taken in the directory's own spelling.
- samba_group - members are resolved with one LDAP search per batch of names instead of one search per member, and unknown members are reported together in one error.
- samba_join_member, samba_join_sssd - new option C(force) to re-join a host that already has a machine account, re-establishing the machine password respectively the keytab (always a change; requires C(bind_password)).
- samba_join_sssd - new option C(keytab) (default C(/etc/krb5.keytab)) names the host keytab C(adcli) writes (C(--host-keytab)) and the module reads the join state from; previously the path was fixed.
- samba_user, samba_group - a new object is added in a single operation. samba's own C(newuser)/C(newgroup) take the container (C(path)), the names, e-mail, description and the POSIX attributes (C(gid_number) for groups), so a create no longer adds, renames and modifies in turn. As with C(samba-tool user create), a user created with C(given_name) and/or C(surname) but no C(display_name) gets a display name derived from the names; check mode and the diff predict it.
- samba_user, samba_group - the default container is looked up once per run instead of on every location check, and the move decision is evaluated once instead of twice.

Breaking Changes / Porting Guide
--------------------------------

- samba_group - C(scope) and C(category) no longer default to C(global) and C(security). When omitted, a new group is still created as a global security group, but the type of an existing group is left unchanged; when only one of the two is given, the other part is kept from the stored type. Previously every task reconciled the defaults, so updating for example the description of the built-in domain-local C(DnsAdmins) group tried to convert it to a global group and failed. Playbooks that relied on the defaults to enforce a type must set C(scope) and C(category) explicitly.
- samba_join_dc, samba_join_member - the join now requires Kerberos by default and fails rather than falling back to NTLM, the same stance as the object modules. Previously the policy came from smb.conf (usually C(desired)), so a join could silently authenticate with NTLM. The new option C(use_kerberos) restores that fallback with C(desired) for hosts whose Kerberos client setup is not complete at join time.
- samba_user - C(enabled) no longer defaults to C(true). When omitted, a new account is created enabled and the state of an existing account is left unchanged, like every other unset attribute. Previously any task that omitted C(enabled) enabled a disabled account again; playbooks that relied on that implicit re-enable must now set C(enabled=true) explicitly.

Bugfixes
--------

- all object and info modules (shared connection) - a failed connection now reports its cause instead of one generic message. The bind user and realm are named (they are not secrets; the password never appears). When the DC was reached but no Kerberos ticket could be obtained, the KDC's reason is given (wrong password, unreachable KDC, clock skew); when the ticket was fine, the LDAP bind error is given so a DC that refuses sealing can be told apart; when the DC was not reached at all, the transport error is given.
- all object and info modules (shared connection) - when C(realm) is omitted it is derived only from a fully qualified C(server) name. A bare host name or an IP address now fails before any connection with a message asking for C(realm), instead of guessing a realm such as C(DC1) or C(0.2.10) and failing later with a cryptic Kerberos error.
- samba_dns_record - C(state=absent) deleted the record by rewriting the whole dnsRecord attribute from a snapshot, so a record added on the same name between the read and the write was lost. Now only the exact stored value is deleted; when it was the last live record the node is tombstoned in the same modify (the state samba itself leaves behind for its garbage collection). A value that vanished meanwhile is re-read and treated as already absent.
- samba_dns_record - C(ttl) is now reconciled. A record with the same identity but a different TTL was reported unchanged and the requested TTL never applied; it is now updated in place (old value deleted and new one added in one modify) and reported as a change, with the TTL shown in the diff and in the returned record.
- samba_dns_record - every record change now raises the zone's SOA serial (and stamps the record with it), as C(samba-tool dns) does. Before, the serial never moved and records carried a fixed serial of 1, so secondaries (zone transfers) and BIND9_DLZ notifications never saw the changes. The serial is swapped by deleting the exact old SOA value and adding the new one in a single modify, so a concurrently rewritten SOA is re-read instead of overwritten; idempotent runs do not touch it.
- samba_dns_record - re-adding a record at a name whose last record had been removed left the dnsNode tombstoned (dNSTombstoned=TRUE), so the DNS server never answered the name while the module reported it present. The node is now revived (records replaced, flag cleared) and the read path treats tombstoned nodes as absent, matching samba_dns_record_info and the DNS server.
- samba_join_dc, samba_provision - what samba's join and provision print while they run inside the module process is captured instead of reaching the module's stdout, where Ansible expects only the JSON result and merely tolerates other lines. The lines are returned as C(output), and the last of them are quoted in the error when the operation fails.
- samba_join_member, samba_join_sssd - whether the host is joined is now decided locally (the machine account in the local Samba secrets store, respectively a machine principal for the realm in the keytab) instead of by C(net ads testjoin) / C(adcli testjoin). Those probes need a reachable DC found by DNS discovery, a working KDC and a sane clock, so any such failure looked like "not joined" and triggered an unintended re-join with a new machine password or keytab, and a plain DC outage produced a misleading "joining failed" and a wrong C(changed) in check mode. The C(net) binary is no longer required by samba_join_member.
- samba_ou - deleting an OU the directory protects (systemFlags) or the bind user may not delete is reported cleanly, with the directory's reason, instead of as a raw ldb error.
- samba_ou_info - an invalid C(path) is rejected with a clear message instead of a traceback; the value is parsed as a distinguished name before it is used as the search base.
- samba_provision, samba_join_dc - a local Samba database that exists but cannot be opened for lack of privileges is reported as a permission problem instead of as a partially provisioned or corrupt host, and the local domain's DNS name is taken from samba's own C(domain_dns_name()) instead of being derived from the DN by hand.
- samba_user - the lookup matched any object with objectClass user, so a username naming a computer account (for example DC1$) would have been managed or, with state=absent, deleted. The module now matches user accounts only (objectCategory person), consistent with samba_user_info; computer accounts are never touched.
- samba_user - with C(update_password=always), a user removed between the read and the password write ended in a traceback, because samba's C(setpassword) raises a plain exception for a missing user that the module's error-code handler never saw. The password is now written by DN (the same C(unicodePwd) encoding samba uses), so a vanished user and a password rejected by the domain policy are both reported as clear errors.
- samba_user, samba_group - creating an object is now all-or-nothing. LDAP offers no transactions, so when a step after the initial add failed (a failed move under C(path), an attribute, enabled-state, gidNumber or member write) a half-created object stayed behind. The module now removes the object it just created and fails with the cause. A create that samba's own create helper rejects (for example a password refused by the domain policy) is reported cleanly instead of as a traceback. Changes to an existing object remain separate operations that a re-run completes.
- samba_user, samba_group, samba_ou - an empty string for a string attribute (for example C(description="")) crashed with an ldb "empty attribute" error, and there was no way to remove an attribute that had been set. An empty string now removes the attribute; an attribute that is already absent compares equal to it, so the run is idempotent. Removing is a no-op when creating an object. The POSIX integer attributes of samba_user cannot be removed this way.
- samba_user, samba_group, samba_ou - check mode now validates the target location (C(path) parses, the parent container exists) before it reports anything, so a dry run fails exactly where the real run would instead of claiming a change for a create or move the real run then refuses.
- samba_user, samba_user_info, samba_group, samba_group_info, samba_ou, samba_ou_info, samba_dns_record, samba_dns_record_info, samba_dns_zone, samba_dns_zone_info - the documentation no longer claims the module must run on the DC. These modules reach the DC over the network (GSSAPI sign+seal LDAP, plus the C(dnsserver) RPC for zones) and run on any host that has the C(samba) Python bindings and can reach the DC; the DC itself is merely the simplest place. The wording was left over from the credential-free local connection model the collection abandoned.

New Modules
-----------

- samba_password_policy - Manage the domain password policy of a Samba AD DC
- samba_password_settings - Manage fine\-grained password settings objects (PSOs) in a Samba AD DC
- samba_schema_extension - Extend the schema of a Samba AD domain with a known extension

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
