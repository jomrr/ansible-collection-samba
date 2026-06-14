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
