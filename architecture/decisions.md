# Architecture Decisions

Architecture decisions for the `jomrr.samba` collection.

---

## Container Runtime

### Context

The collection is developed on Fedora 43 with rootless Podman; Docker is not
used. There are two test worlds: `ansible-test` (sanity/units) against the
official test container image, and Molecule (integration) against prebuilt,
systemd-enabled multi-distro images.

### Decision

`ansible-test` runs against Podman with Python target 3.12. On this host
`docker` is real Moby, so the Podman engine is selected explicitly via
`ANSIBLE_TEST_PREFER_PODMAN=1`:

```bash
ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test sanity --docker --python 3.12
ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test units  --docker --python 3.12
```

Molecule uses the rootless `podman` driver against the prebuilt images, which
are referenced rather than built or modified here.

### Known friction (rootless + cgroups v2)

- `ansible-test` sets `--privileged` for some targets; under rootless this can
  collide with user namespaces. Observe it rather than dropping tests.
- systemd inside a container needs working cgroup delegation. The prebuilt
  Molecule images already provide this.

### Consequences

- The first gate before any module code is that the empty skeleton passes
  `ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test sanity --docker --python 3.12`.
- Runtime quirks are documented here as they appear, not hardcoded elsewhere,
  because they change with Podman/Fedora versions.

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
scenario. The systemd-enabled images provide the prerequisites.

### Rationale

- Follows directly from the Samba backend decision: the DC and python3-samba are
  the same installation in the same container, so there is no version mismatch
  between bindings and DC.
- systemd present in the image, so `samba` starts cleanly as a service.
- Simpler topology for idempotency verification: no network setup between the
  test runner and a separate DC.

### Open provisioning points (to be solved in prepare.yml, not worked around)

- `samba-tool domain provision` needs a correct FQDN/hostname.
- `/etc/krb5.conf` must match the provisioned realm.
- Possibly `--use-rfc2307` depending on test needs.
- The DNS backend choice (internal SAMBA_INTERNAL) must match the DNS module
  tests.

### Consequences

- Molecule `prepare.yml` provisions the DC before converge.
- `converge.yml` runs the modules against localhost / the local DC.
- `verify.yml` checks idempotency (a second converge run yields changed: false).
