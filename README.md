# Ansible Collection: `jomrr.samba`

Modules for the full lifecycle of a Samba Active Directory domain, through the
native `samba` Python bindings (`samba.samdb.SamDB`, `samba.join`,
`samba.net_s3`, `samba.dcerpc`):

- **Object management** on a running DC — users, groups, organizational units,
  and the Samba internal DNS.
- **Domain lifecycle** — provisioning a new domain controller and joining a host
  to an existing domain (as a DC, a Samba member server, or an SSSD client).

Every module is idempotent and supports check mode: the object modules diff the
current against the desired state, while the lifecycle modules use a binary
"is it already provisioned/joined?" check. A second run with the same parameters
reports `changed: false`.

## Modules

### Object and info modules

These manage objects on a **running** DC over the network and share the GSSAPI
connection options through the `jomrr.samba.all` action group (see Connection
setup).

| Module | Purpose | idempotent | check_mode |
|--------|---------|------------|------------|
| `samba_user` | Create, modify and remove users (incl. RFC2307/POSIX attributes) | yes | yes |
| `samba_user_info` | Query users | n/a (read) | n/a |
| `samba_group` | Create, modify and remove groups (scope, category, members, gid) | yes | yes |
| `samba_group_info` | Query groups | n/a (read) | n/a |
| `samba_ou` | Create, modify and remove organizational units | yes | yes |
| `samba_ou_info` | Query organizational units | n/a (read) | n/a |
| `samba_dns_record` | Manage DNS records (A, AAAA, CNAME, PTR, NS, MX, SRV, TXT) | yes | yes |
| `samba_dns_record_info` | Query DNS records | n/a (read) | n/a |
| `samba_dns_zone` | Create and remove AD-integrated DNS zones (forward/reverse) | yes | yes |
| `samba_dns_zone_info` | Query DNS zones | n/a (read) | n/a |

### Domain lifecycle modules

These run **locally on the target machine** that is becoming/joining a DC, take
no GSSAPI connection options, and are **not** in the `jomrr.samba.all` action
group (see Execution topology → Lifecycle modules run locally). Only
`state: present` is supported — there is no tear-down/leave. Idempotency is
binary.

| Module | Purpose | idempotent | check_mode |
|--------|---------|------------|------------|
| `samba_provision` | Provision a brand-new Samba AD domain controller | yes (binary) | yes |
| `samba_join_dc` | Join an existing domain as an additional DC | yes (binary) | yes |
| `samba_join_member` | Join an existing domain as a Samba member server (winbind) | yes (binary) | yes |
| `samba_join_sssd` | Join an existing domain for SSSD (writes a Kerberos keytab) | yes (binary) | yes |

The three join modules are split **by join mechanism and the artifact each
writes**, not by the host's intended purpose:

- `samba_join_dc` — `samba.join`, full DC replication.
- `samba_join_member` — `samba.net_s3`, writes the machine secret to
  `secrets.tdb` (the winbind path).
- `samba_join_sssd` — `adcli`, writes a Kerberos keytab (the SSSD path).

Each module performs **only the join act** and its idempotency detection. It
does not template `smb.conf`/`sssd.conf`, configure idmap/nsswitch/PAM, or
enable/start the winbind or SSSD daemon — that is the caller's responsibility.
In particular `samba_join_member` requires a pre-configured `smb.conf`
(`realm`, `workgroup`, `server role = member server`) to join against.

All modules use the native Python bindings, with **one deliberate exception**:
`samba_join_sssd` shells out to `adcli` (there is no Python binding for it),
feeding the join password on stdin, never on the command line.

## Requirements

- **`python3-samba` on the executing host.** The modules use the native Samba
  Python bindings (`samba.samdb.SamDB` is the bindings class, not a generic LDAP
  client), so the host that *runs* the module must have `python3-samba`
  installed. Which host that is depends on the execution topology (see below):
  for the object/info modules the DC itself (preferred) or the Ansible
  controller (remote DC); for the lifecycle modules always the target machine
  being provisioned/joined. Without the bindings the module fails with
  `missing_required_lib`.
- **`adcli` for `samba_join_sssd` only.** That module drives the `adcli` command
  line tool (the one module that is not pure bindings), so the target host must
  have `adcli` installed; it fails cleanly if `adcli` is not on `PATH`. The other
  lifecycle modules need only `python3-samba`.
- **Kerberos / GSSAPI:** the executing host must be able to obtain a Kerberos
  ticket for the DC's realm — working DNS/SRV resolution to the DC, a matching
  `krb5.conf`, and synchronised clocks (clock skew breaks Kerberos).
- **ansible-core:** `>= 2.19.0` (see `meta/runtime.yml`).
- **RFC2307/POSIX attributes** (`uid_number`, `gid_number`,
  `unix_home_directory`, `login_shell`, `gecos` on `samba_user`; `gid_number`
  on `samba_group`) require a domain provisioned with `--use-rfc2307`. Setting
  any of them on a domain without RFC2307 fails before any change is made; not
  setting them leaves such domains entirely unaffected.

## Execution topology

The **object and info modules** reach the DC over the network — a GSSAPI
sign+seal `ldap://` connection, and for `samba_dns_zone` additionally a
`dnsserver` RPC — and have no DC-local dependency. Two topologies are supported.
(The lifecycle modules are different — see *Lifecycle modules run locally* at the
end of this section.)

### Preferred — run on the DC (loopback)

Run the module on the domain controller itself and point `server` at that same
DC, so the connection goes over loopback:

```yaml
- name: Manage the DC from the DC itself
  hosts: dc1.example.com          # the domain controller
  module_defaults:
    group/jomrr.samba.all:
      server: dc1.example.com     # the same DC, reached over loopback
      bind_username: Administrator
      bind_password: "{{ vault_dc_admin_password }}"
      realm: EXAMPLE.COM
  tasks: []                       # your jomrr.samba.* tasks here
```

This is the topology the integration tests cover end to end across all supported
distributions: the sealed LDAP connection and the DNS-zone RPC both run over
loopback, with no firewall and no RPC endpoint-mapper detour — the fewest moving
parts and the highest chance of success. `python3-samba` is already present on a
DC.

### Also supported — run from the controller against a remote DC

Run the module on the Ansible controller (`hosts: localhost`) and point `server`
at the remote DC's FQDN:

```yaml
- name: Manage a remote DC from the controller
  hosts: localhost
  module_defaults:
    group/jomrr.samba.all:
      server: dc1.example.com     # a remote DC, reached over the network
      bind_username: Administrator
      bind_password: "{{ vault_dc_admin_password }}"
      realm: EXAMPLE.COM
  tasks: []                       # your jomrr.samba.* tasks here
```

Every operation runs over network paths (`ldap://` or the TCP RPC), so the code
fully supports this. It adds requirements on the controller:

- **`python3-samba` must be installed on the controller** — it is the host that
  runs the module. A controller version close to the DC's Samba version is
  advisable for the DNS-zone RPC IDL; plain LDAP is more version-tolerant.
- **Kerberos must resolve from the controller to the DC** (DNS/SRV records, a
  correct `krb5.conf`) and clocks must be in sync.
- **DNS-zone management needs more than port 389.** `samba_dns_zone` uses the
  `dnsserver` RPC over `ncacn_ip_tcp`, which needs the RPC endpoint mapper plus
  dynamically assigned ports reachable through any firewall between controller
  and DC. The other modules (users, groups, OUs, DNS records) use only the
  single sealed LDAP port 389. If a firewall sits between controller and DC,
  this RPC is the part to open for zone management.

The connection options below are the same in both topologies; only `hosts` and
the `server` value differ.

### Lifecycle modules run locally

`samba_provision` and the join modules (`samba_join_dc`, `samba_join_member`,
`samba_join_sssd`) act on the **local machine** that is becoming/joining a DC, so
they always run *on that host* (`hosts:` the target, or `delegate_to` it). They
have no GSSAPI sealed-LDAP session and are not in the `jomrr.samba.all` action
group. The options they share with the object modules by name (`server`,
`bind_username`, `bind_password`, `realm`) mean something different here: the
existing DC to join against and the admin credentials to authorize the join —
not a connection to manage objects on. `samba_provision` takes no `server`/bind
options at all (there is no DC yet); it provisions the domain locally.

## Connection setup

Every **object and info module** connects to the DC with **explicit caller
credentials** over LDAP using SASL/GSSAPI with signing and sealing on port 389
(the GSSAPI layer encrypts the traffic; there is no LDAPS or StartTLS). Kerberos
is required and the ticket is held in an in-memory credential cache that never
touches disk. (The lifecycle modules do not use this connection layer; see
Execution topology.)

Each of these modules therefore takes these connection options:

| Option | Required | Description |
|--------|----------|-------------|
| `server` | yes | DNS host name of the DC, e.g. `dc1.example.com` |
| `bind_username` | yes | Account to bind as, e.g. `Administrator` |
| `bind_password` | yes | Its password — **keep it in Ansible Vault or a secret store** |
| `realm` | no | Kerberos realm, e.g. `EXAMPLE.COM`; derived from `server` if omitted |

> **Security:** `bind_password` is marked `no_log`, but that only scrubs it from
> module output — it does not protect a plain-text value at rest. Always supply
> it through Ansible Vault or an external secret store, never in plain text in a
> playbook, inventory or variable file. Bind with an account that has exactly
> the privileges it needs; the DC authorizes every operation against that
> principal.

These modules share these options through the `jomrr.samba.all` action group, so
you can set them once with `module_defaults` instead of repeating them on every
task (the lifecycle modules are not in the group):

```yaml
- name: Manage the Samba AD DC
  hosts: dc1.example.com           # run on the DC (preferred; see Execution topology)
  module_defaults:
    group/jomrr.samba.all:
      server: dc1.example.com      # the same DC, over loopback
      bind_username: Administrator
      bind_password: "{{ vault_dc_admin_password }}"   # from Ansible Vault
      realm: EXAMPLE.COM
  tasks:
    - name: Ensure a user exists with POSIX attributes
      jomrr.samba.samba_user:
        username: jdoe
        given_name: Jane
        surname: Doe
        display_name: Jane Doe
        email: jane.doe@example.com
        password: "{{ vault_jdoe_password }}"
        uid_number: 10001
        gid_number: 10000
        unix_home_directory: /home/jdoe
        login_shell: /bin/bash
        state: present

    - name: Ensure a group exists with that user as a member
      jomrr.samba.samba_group:
        name: engineers
        scope: global
        category: security
        members:
          - jdoe
        state: present
```

## Usage examples

Create a forward DNS zone and a record in it:

```yaml
- name: DNS zone and record
  hosts: dc1.example.com           # run on the DC (preferred; see Execution topology)
  module_defaults:
    group/jomrr.samba.all:
      server: dc1.example.com      # the same DC, over loopback
      bind_username: Administrator
      bind_password: "{{ vault_dc_admin_password }}"
      realm: EXAMPLE.COM
  tasks:
    - name: Ensure the zone exists
      jomrr.samba.samba_dns_zone:
        name: example.com
        state: present

    - name: Ensure a host record exists
      jomrr.samba.samba_dns_record:
        zone: example.com
        name: www
        type: A
        value: 192.0.2.10
        state: present
```

Query state back through an `*_info` module (read-only, `changed: false`):

```yaml
    - name: Look up a user
      jomrr.samba.samba_user_info:
        username: jdoe
      register: jdoe_info

    - name: List all DNS zones
      jomrr.samba.samba_dns_zone_info:
      register: zones
```

The `*_info` modules return the same field names the managing modules accept as
input, so their output can be fed straight back as write input.

### Domain lifecycle

The lifecycle modules run **on the target host** and do not use the action group.
Provision a new domain controller:

```yaml
- name: Provision a new Samba AD domain controller
  hosts: dc1.example.com           # runs locally on the host becoming the DC
  tasks:
    - name: Ensure the domain is provisioned
      jomrr.samba.samba_provision:
        realm: EXAMPLE.COM
        domain: EXAMPLE
        admin_password: "{{ vault_dc_admin_password }}"   # from Ansible Vault
        dns_backend: SAMBA_INTERNAL
        use_rfc2307: true
        state: present
```

Join an existing domain as a Samba member server (your playbook configures
`smb.conf` with `server role = member server` first; the module performs only
the join):

```yaml
- name: Join the host as a member server
  hosts: member1.example.com       # runs locally on the joining host
  tasks:
    - name: Ensure the host is a domain member
      jomrr.samba.samba_join_member:
        realm: EXAMPLE.COM
        server: dc1.example.com     # the existing DC to join against
        bind_username: Administrator
        bind_password: "{{ vault_dc_admin_password }}"    # from Ansible Vault
        state: present
```

`samba_join_dc` and `samba_join_sssd` follow the same shape (run on the joining
host; `server`/`bind_*` identify the DC and the join credentials).

## Architecture

See `architecture/decisions.md` in the source repository for the design
decisions behind the collection:

- Samba backend (native Python bindings) and lazy-import encapsulation
- Connection model (explicit GSSAPI credentials, sign + seal, in-memory ccache)
- Domain lifecycle (provision and the join family): split by join mechanism and
  artifact, bindings everywhere with one deliberate `adcli` CLI exception (sssd)
- Container runtime (rootless Podman) and DC test topology

## Tests

```bash
ansible-lint
ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test sanity --docker --python 3.12
ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test units  --docker --python 3.12
molecule test                       # the default (object-module) scenario
```

Integration runs against rootless Podman across Debian, Fedora, openSUSE and
Ubuntu. There are five Molecule scenarios; select one with `-s`:

- `default` — the object/info modules against a single provisioned DC
- `provision` — `samba_provision`
- `join_dc` — `samba_join_dc` (multi-host: DC + joining DC pairs)
- `join_member` — `samba_join_member` (multi-host; proves RFC2307 uid resolution
  via winbind)
- `join_sssd` — `samba_join_sssd` (multi-host; proves RFC2307 uid resolution via
  SSSD)

```bash
molecule test -s join_member
```

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).
