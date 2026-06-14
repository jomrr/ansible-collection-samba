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
any DC exists to connect to. Per the ADR policy in CLAUDE.md, the
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
