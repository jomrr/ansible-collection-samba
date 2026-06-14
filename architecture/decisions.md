# Architecture Decisions

Architecture decisions for the `jomrr.samba` collection.

---

## Container Runtime

### Context

The collection is developed on Fedora with rootless Podman; Docker is not used.
There are two test worlds: `ansible-test` (sanity/units) against the official
test container image, and Molecule (integration) against the stock upstream
distribution images.

### Decision

`ansible-test` runs against Podman with Python target 3.12. On this host
`docker` is real Moby, so the Podman engine is selected explicitly via
`ANSIBLE_TEST_PREFER_PODMAN=1`:

```bash
ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test sanity --docker --python 3.12
ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test units  --docker --python 3.12
```

Molecule uses the rootless `podman` driver against the stock distribution
images (`debian:stable`, `fedora:latest`, `opensuse/tumbleweed:latest`,
`ubuntu:latest`), referenced rather than built or modified.

The DC containers do NOT run systemd. systemd-as-PID1 in a container consumes
~12 inotify instances each (`fs.inotify.max_user_instances` defaults to 128),
so a four-distro matrix alongside other containers exhausts the budget and the
later DCs fail to boot. Instead each container's PID1 is a trivial keep-alive
and Samba is started as a plain daemon (`samba --daemon`) from `prepare.yml`.
The modules only need a local `SamDB` connection, so no network service is
required for them. The DC runs `--privileged` (acceptable for a throwaway test
fixture) so Samba can write native `security.NTACL` xattrs.

### Known friction (rootless Podman) and how it is handled

- **idmap xid range**: Samba's default s4 idmap range (3,000,000-4,000,000)
  lies outside the rootless subordinate-id map (~65536 ids); the sysvol chown
  during the DC self-join then hits an unmappable xid and Samba panics.
  `prepare.yml` rewrites `/usr/share/samba/setup/idmap_init.ldif` to a low
  range (10000-60000) before provisioning.
- **tmpfs state**: `/var/lib/samba` is a per-run tmpfs in the container's own
  mount namespace, where native `security.NTACL` xattrs are writable and each
  run gets a clean domain.
- **python bootstrap**: the stock base images ship no python3; `prepare.yml`
  installs it via `raw` (the podman connection has no shell wrapper, so the
  command runs through an explicit `/bin/sh -c`) before gathering facts.
- **distro deltas** (handled via `os_family` vars, not per-distro task forks):
  the AD DC daemon and provision data are split into separate packages on
  Debian/Ubuntu (`samba-ad-dc`, `samba-ad-provision`, `samba-dsdb-modules`,
  `samba-vfs-modules`); openSUSE needs `samba-tool`, `samba-python3` and
  `python3xx-cryptography` explicitly; readiness is gated on a local
  `samba-tool user list` (one samba-tool build rejects an explicit
  `127.0.0.1`).
- **openSUSE MIT KDC**: openSUSE builds samba against the MIT Kerberos KDC, so
  the `samba` AD DC daemon execs `/usr/sbin/krb5kdc`; without `krb5-server` that
  child fails and `samba_terminate` takes the whole daemon down. The local LDB
  still answers (so the `user list` gate passes), which is why a second readiness
  gate queries the DNS RPC (`samba-tool dns`) - it surfaces this and any other
  failed daemon child fast. `krb5-server` and `samba-winbind` are therefore in
  the openSUSE package set. The other distros use the in-tree Heimdal KDC.

### Consequences

- The first gate before any module code is that the empty skeleton passes
  `ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test sanity --docker --python 3.12`.
- Runtime quirks are documented here as they appear, not hardcoded elsewhere,
  because they change with Podman/distro versions.

---

## Samba Backend and Import Encapsulation

### Context

The modules talk to a Samba AD DC to manage users, groups, OUs, and DNS. Two
approaches exist: the native Python bindings (`samba.samdb.SamDB`,
`samba.dcerpc`) or a subprocess wrapper around `samba-tool`.

### Decision

Native Python bindings.

### Rationale

- Clean current/desired-state diffing via LDB searches instead of parsing CLI
  output. This is the basis for correct idempotency and check mode.
- No subprocess overhead, no fragile output parsing, no `changed_when`
  acrobatics around `command:`.
- Because the DC runs in the same Molecule container (see DC topology), the
  python3-samba version always matches the DC version, eliminating the classic
  bindings risk of a version mismatch.

### Trade-off

- `import samba` does not exist in the ansible-test sanity container. This
  creates the central tension with the "no ignore list" rule.

### Follow-on decision (import encapsulation)

`plugins/module_utils/samba_conn.py` never imports `samba` at module level.

- Existence check via `importlib.util.find_spec("samba")` — binds no symbol, so
  no unused-import / F401.
- Real imports via `importlib.import_module(...)` inside the function that needs
  them — ordinary function calls, so no `import-outside-toplevel`.
- If the binding is missing at runtime: `fail_json` with `missing_required_lib`.

This keeps the sanity phase green without touching a lint rule or adding an
ignore entry. The pattern is mandatory for every code path that touches
`samba`.

---

## DC Test Topology

### Context

The integration/idempotency tests need a running Samba AD DC. Options: provision
the DC inside the Molecule container, or run a separate DC as a sidecar / pod
member.

### Decision

The Samba AD DC runs inside the Molecule container itself, provisioned per
scenario and started as a plain `samba --daemon` (see Container Runtime for why
not systemd).

### Rationale

- Follows directly from the Samba backend decision: the DC and python3-samba are
  the same installation in the same container, so there is no version mismatch
  between bindings and DC.
- Simpler topology for idempotency verification: no network setup between the
  test runner and a separate DC; the modules talk to the local `SamDB`.

### Open provisioning points (solved in prepare.yml, not worked around)

- `samba-tool domain provision` needs a correct FQDN/hostname (set in
  `/etc/hosts`, written with `unsafe_writes` because it is a bind-mount).
- `/etc/krb5.conf` is the one Samba generates under the private dir.
- `--use-rfc2307` is passed.
- The DNS backend is `SAMBA_INTERNAL`, consistent for later DNS module tests.
- The idmap range and tmpfs/native-ACL points from Container Runtime apply.

### Consequences

- Molecule `prepare.yml` provisions the DC, then seeds the objects that
  `converge.yml` will modify / disable / delete / purge (so those transitions
  are real changes once and no-ops on the idempotence run).
- `converge.yml` exercises all four modules against the local DC and must be
  idempotent.
- The idempotence step (a second converge run yielding `changed: false`) is the
  check that the unit mocks cannot make; `verify.yml` then asserts the resulting
  state through the `*_info` modules.

---

## Connection Model

Every module connects to the DC with explicit caller credentials
(`server`/`username`/`password`/`realm`) over LDAP using SASL/GSSAPI with signing
and sealing on port 389 — the GSSAPI layer encrypts the traffic, so no LDAPS or
StartTLS is involved. Kerberos is required (`MUST_USE_KERBEROS`, so the bind
fails rather than downgrading to NTLM), sealing is forced
(`client ldap sasl wrapping = seal`, so it fails rather than downgrading to an
unencrypted bind), and the ticket obtained from username/password is held in an
in-memory credential cache (`MEMORY:`) that never touches disk and dies with the
process. Zone create/delete additionally use the `dnsserver` RPC, authenticated
and sealed with the same credentials. The earlier credential-free local paths
(`system_session` against `sam.ldb`, and machine-account RPC) are abandoned: the
deliberate trade-off is that every call now needs reachable LDAP and valid
credentials, in exchange for the DC authorizing each operation against the
authenticated principal (least privilege and an audit trail) instead of an
implicit local-root bypass.

---

## samba_provision (setup module)

### Context

A new module, `samba_provision`, performs the first-time provisioning of a Samba
AD DC. This is fundamentally different from the object modules (`samba_user`,
`samba_group`, `samba_ou`, `samba_dns_*`): it creates the domain itself, before
any DC exists to connect to. Per the decision policy in CLAUDE.md, the
`samba.provision` bindings API was verified (against samba 4.23.8) and this
decision proposed to the maintainer before any module code is written.

### Decision

`samba_provision` is a *setup* module, not an object module, and deliberately
departs from several collection conventions:

- **No connection doc_fragment, not in the `jomrr.samba.all` action group.**
  There is no DC to connect to during provisioning, so the GSSAPI `ldap://`
  connection layer (`server`/`bind_username`/`bind_password`/`realm`) does not
  apply. The module acts on the local machine that is becoming the DC.
- **Local-only, mandatory.** Unlike the object modules (fully remote-capable
  over `ldap://`), `samba_provision` must run on the future DC itself
  (`hosts: <dc>` / `delegate_to`). It calls `samba.provision.provision()`
  locally and opens the local `sam.ldb` directly.
- **`state` present only.** No `absent` — destroying a domain is intentionally
  not offered. Only provisioning; joining an existing domain is a future
  separate module, not this one.
- **Binary, non-incremental idempotency.** Idempotency is "is a DC already
  provisioned here, yes/no", not the read-diff-write of the object modules. An
  already-provisioned domain is never re-provisioned and never reconciled
  against the module's parameters: `present` means only "ensure a DC exists
  here", not "ensure a DC with exactly these parameters". A parameter mismatch
  against an existing domain is neither an error nor a change.
- **`samba.provision` bindings, lazy-imported.** Consistent with the Samba
  Backend decision (native bindings, not a `samba-tool` subprocess).
  `samba.provision` (and `samba.auth`, `samba.param`, `samba.functional_level`,
  `samba.dsdb`) are absent in the sanity container, so every import is lazy
  (`find_spec` / `import_module` inside a function), the same mandatory pattern
  as `samba_conn`.

### Verified API (samba 4.23.8)

- `provision(logger, session_info, ...)` — `logger` and `session_info` are the
  only positional requireds (48 parameters total); everything else is keyword
  with sane defaults. `samba-tool domain provision` itself calls this with
  `logger=get_logger(...)`, `session_info=samba.auth.system_session()` and
  `lp=sambaopts.get_loadparm()`.
- Module option -> `provision()` parameter mapping:
  - `realm` -> `realm`; `domain` (NetBIOS) -> `domain`; `hostname` ->
    `hostname`.
  - `dns_backend` -> `dns_backend`, one of `SAMBA_INTERNAL` / `BIND9_DLZ` /
    `BIND9_FLATFILE` / `NONE`.
  - server role -> `serverrole="dc"` (samba canonicalizes via
    `sanitize_server_role` to `"active directory domain controller"`).
  - function level -> `dom_for_fun_level`, mapped from a friendly string via
    `samba.functional_level.string_to_level`; valid keys are `2000`, `2003`,
    `2008`, `2008_R2`, `2012`, `2012_R2`, `2016`; samba's own default when
    unset is `DS_DOMAIN_FUNCTION_2008_R2`.
  - admin password -> `adminpass` (secret -> `no_log`); samba enforces password
    quality, so a weak password fails provisioning with a clear error.
  - `use_rfc2307` -> `use_rfc2307` (bool).
- Not exposed (internal/dangerous; left at samba defaults): the `*dn` overrides
  (`rootdn`/`domaindn`/`schemadn`/...), the secret/guid internals
  (`krbtgtpass`/`machinepass`/`*guid`), `targetdir`/`smbconf` paths,
  `backend_store`, `base_schema`, `adprep_level`, `next_rid`, etc.
- Return: a `ProvisionResult` with `server_role`, `paths`, `domaindn`,
  `domainsid`, `names` (`hostname`/`domain`/`dnsdomain`), and `samdb`/`lp`. The
  module returns the non-secret subset (e.g. `domaindn`, `domainsid`,
  `dnsdomain`, server role); `adminpass`/`adminpass_generated` are never
  returned.
- Idempotency open: the local `sam.ldb` path is `lp.private_path("sam.ldb")`
  (`/var/lib/samba/private/sam.ldb` by default, smb.conf-respecting, not
  hardcoded). "Provisioned" = the file exists AND opens as
  `SamDB(url=<path>, session_info=system_session(), lp=lp)` and answers a query;
  file absent = not provisioned; file present but unopenable = a clear
  `fail_json` ("present but broken"), never a silent re-provision. This local
  `system_session` open is the one place the collection still uses the
  credential-free local LDB path that the object modules abandoned (see
  Connection Model) — justified because provisioning is inherently pre-DC and
  local, with no DC to authenticate against yet.

### Open design points (settled in Phase 2)

- **check_mode**: provisioning cannot be dry-run by samba. `check_mode` reads
  the idempotency state only (provisioned yes/no) and returns `changed`
  accordingly, without provisioning. `supports_check_mode=True` with that
  read-only behaviour.
- **no_log**: `adminpass` is a secret (rule 8) -> `no_log` on the option; never
  in return, diff or error.
- **Non-idempotency boundary**: an existing domain is never re-provisioned or
  diffed; a parameter mismatch is a no-op, not a failure (`present` = "a DC
  exists here").
- **Race/TOCTOU (rule 9)**: the window between the "not provisioned" check and
  `provision()` is negligible — provisioning is a one-time setup step, not a
  concurrent path. `provision()` into a non-empty private dir fails on its own,
  which is surfaced as a clear `fail_json` rather than a traceback.

### Status

Proposed to the maintainer in this phase (verification only). No module code is
written until this decision is accepted; Phase 2 implements on this finding.

---

## Join module family (samba_join_dc / samba_join_member / samba_join_sssd)

### Context

Three setup modules join a host to an existing domain, all run locally on the
joining host like `samba_provision`. The mechanism was verified against samba
4.23.8 / adcli 0.9.2 before any code; this records the decisions.

### The cut: by mechanism, not by purpose

The family is split by **join mechanism and the artifact it writes**, not by the
host's intended purpose:

- `samba_join_dc` — `samba.join.join_DC` bindings, full DC replication.
- `samba_join_member` — `samba.net_s3.join_member` bindings, writes
  `secrets.tdb` (the Samba-native, winbind-backed path).
- `samba_join_sssd` — `adcli join` (CLI), writes a Kerberos **keytab** (the
  SSSD-native path).

**There is no `samba_join_client` and no `backend` switch.** The earlier plan
(a `samba_join_client` with `backend: winbind | sssd`) is replaced by this
honester cut. Rationale: at the *join layer* a winbind "client" enrolment is
**identical** to `samba_join_member` (both are `net_s3.join_member` →
`secrets.tdb`); "client vs. member" is a **role-level** distinction (how the host
is configured and used), not a module-level one. The only real fork is the
artifact: `secrets.tdb` (winbind) vs a keytab (SSSD). So the two artifacts *are*
the two modules — `samba_join_member` and `samba_join_sssd` — and a `backend`
parameter would have been a false abstraction over what are really two different
tools writing two different files.

### Decision

- **Strict module boundary.** Each module performs only the join act plus its
  idempotency detection, and stops there. NOT in the module: smb.conf/sssd.conf
  templating, enabling/starting daemons (winbind/sssd), or wiring the
  nsswitch/PAM/authselect stack. Those are orchestration and belong in the
  (later) role. Rationale (best practice + the Samba Backend decision): the
  module owns only the stateful operation a `command` models badly; templating,
  daemons and the host stack are orchestration the role owns. This boundary is
  also forced by the mechanism: the Samba member join binding needs a configured
  smb.conf (realm, workgroup, `server role = member server`) to already exist, so
  the role configures smb.conf first and the module then performs the join
  against it.
- **Local-only, not in the `jomrr.samba.all` action group, `state` present
  only**, binary idempotency - same shape as `samba_provision`. No `absent`
  (un-joining is not offered in this family).

### Verified mechanism (samba 4.23.8 / adcli 0.9.2) and the bindings-vs-CLI finding

The expectation that the member join is CLI-only is **largely refuted** -
bindings exist for it; only the SSSD/adcli path is genuinely CLI-only:

- **samba_join_dc - bindings.** `samba.join.join_DC(logger, server, creds, lp,
  site, netbios_name, dns_backend, machinepass, ...)` (class `DCJoinContext`,
  `do_join()`/`join_finalise()`). This is the binding behind `samba-tool domain
  join <realm> DC`, analogous to `provision()`. Consistent with the Samba
  Backend decision; lazy-imported.
  - **Verified mechanism quirk (`netbios_name` is effectively required).**
    Although `netbios_name` looks optional in the signature, `DCJoinContext`
    runs its entire SPN/DN setup only inside `if netbios_name:`; passing `None`
    or an empty value leaves `ctx.SPNs` unset, so `do_join()` later crashes with
    `'DCJoinContext' object has no attribute 'SPNs'`. `samba-tool` always derives
    one. Consequence: the module derives the NetBIOS name from loadparm/the
    hostname (`lp.get("netbios name")`, the same default `samba-tool` uses) when
    the caller omits it, and never passes `None` to `join_DC()`. Surfaced only by
    the live multi-host Molecule join — mocked units, which stub `join_DC`, could
    not see it.
- **samba_join_member (winbind) - bindings.** The standard AD member join is
  `samba.net_s3.Net(creds, s3_lp, server).join_member(dnshostname, createupn,
  createcomputer, osName, osVer, osServicePack, machinepass)` - the source3
  `net ads join` code path, which writes the machine secret to `secrets.tdb`
  (what winbind reads). It is a real binding, not a subprocess. It does require a
  configured smb.conf (the s3 LoadParm is loaded from it), which the role
  provides per the boundary above. Lazy-imported.
  A winbind-backed *client* enrolment uses this very same operation (net_s3
  `join_member` -> `secrets.tdb`), which is exactly why it is **not** a separate
  module: see "the cut" above.
- **samba_join_sssd - CLI only: the documented exception to the bindings rule.** There is no
  Python binding for `adcli` (it is a separate C tool from the realmd project;
  `import adcli` does not exist). `adcli join` is the low-level pure-join
  component: it creates the machine account and writes a Kerberos **keytab**
  (default `/etc/krb5.keytab`, which SSSD reads), WITHOUT touching
  sssd.conf/nsswitch/PAM - exactly the module boundary, unlike `realm join` which
  does the whole stack. Verified flags (adcli 0.9.2): `adcli join --domain=<realm>
  --login-user=<user> --stdin-password` with optional `--domain-controller`
  (DC discovery via DNS SRV otherwise), `--host-fqdn`, `--domain-ou`. This is the
  **one deliberate subprocess/CLI in the collection and a justified exception to
  the bindings-only rule**: no binding exists, and `adcli` is the
  correct boundary-respecting tool. The CLI call is wrapped and made safe (see
  Security), localised to this single module.

### Idempotency discriminators (binary, per module)

- **samba_join_dc:** a local `sam.ldb` exists AND its domain (realm / domain SID)
  matches the join target. No `sam.ldb` -> not joined. A `sam.ldb` whose domain
  differs from the target -> this host is already a DC of a *different* domain ->
  clear error, never re-join. (This dissolves the provision-vs-join ambiguity:
  the module ensures "this host is a DC of the target domain"; an existing
  matching DC is the no-op. **Empirically confirmed** by the live multi-host
  Molecule test: the local DC's domain identity is reliably readable and
  comparable to the target — the replication proof (a `repltest` user seeded on
  the existing DC and found in the joiner's replica) passed on all four joiner
  distros, the second run was an idempotent no-op, and the foreign-domain refusal
  fired live.)
- **samba_join_member:** `net ads testjoin`
  (`rc == 0` = the machine account is valid against the domain) is the robust
  discriminator; `secrets.tdb` presence is the weaker fallback. (`testjoin` has
  no clean binding, so the idempotency *check* uses the `net` CLI even though the
  join itself uses the binding.)
- **samba_join_sssd:** `adcli testjoin --domain=<realm>` (`rc == 0` = joined;
  it validates the existing keytab and needs no credentials).

### Open design points

- **check_mode:** joining cannot be dry-run; check_mode reads the join state
  only (the discriminators above) and reports `changed` without joining.
  `supports_check_mode=True` for all three.
- **Security (rule 8):** the domain-admin join password is `no_log` and never
  appears in return, diff, error or log. Credential passing, verified:
  - bindings (join_DC, net_s3 join_member): via `samba.credentials.Credentials`
    (`set_password`), never on a command line.
  - `adcli join`: `--login-user=Administrator --stdin-password`, the password fed
    on **stdin**, never as an argv (which would show in `ps`).
  - `net` (for `testjoin` and any net call): credentials via the `PASSWD`
    environment variable, never `-U user%password` on the command line.
- **Race/TOCTOU (rule 9):** the window between the state check and the join is
  negligible (one-time setup, not a concurrent path); a join failure is turned
  into a clear `fail_json`, not a raw traceback.
- **Imports/subprocess:** the binding paths are lazy-imported (`samba.join`,
  `samba.net_s3`, `samba.credentials`, `samba.param`) like `samba_conn`; the
  adcli/net paths are subprocesses whose only safety concern is credential
  handling (above), not the sanity-container import constraint.
- **Lesson for the binding-based join modules (optional-vs-required parameters).**
  The `netbios_name` finding above generalises: a Samba join binding can declare
  a parameter optional in its signature yet trip over `None` internally (here the
  whole SPN/DN setup is gated on it). For `net_s3.join_member` and the adcli path,
  verify per-parameter whether "optional" really means optional or whether the
  binding expects the value `samba-tool` always supplies (e.g. `dnshostname`,
  `machinepass`), and derive a sane default in the module rather than forward
  `None`. This class of bug is caught only by a live join, not by mocked units
  that stub the binding — so each join module needs its own live Molecule pass.

### Status

Implemented. All three modules (`samba_join_dc`, `samba_join_member`,
`samba_join_sssd`) exist with unit tests; `samba_join_dc` and
`samba_join_member` additionally have live multi-host Molecule scenarios green on
four distros, and `samba_join_sssd`'s scenario is the next phase. The notable
revisions to the initial expectation are settled: member/winbind join has a
binding (net_s3), the CLI exception is limited to the SSSD/adcli path, and -
correcting the earlier "`backend` matters at the module level" finding - the
family is cut by mechanism into `samba_join_member` (net_s3 → secrets.tdb) and
`samba_join_sssd` (adcli → keytab) with **no** `samba_join_client`/`backend`
switch (see "the cut" above).
