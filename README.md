# Ansible Collection: `jomrr.samba`

Modules for managing a Samba Active Directory Domain Controller through the
native `samba` Python bindings (`samba.samdb.SamDB`, `samba.dcerpc`): users,
groups, organizational units, and the Samba internal DNS. The modules diff the
current against the desired state, so they are idempotent and support check
mode.

## Modules

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

## Requirements

- **Controller / target host:** the modules run on a Samba AD DC host that has
  the `samba` Python bindings (`python3-samba`) installed; they talk to the
  directory through those bindings.
- **ansible-core:** `>= 2.19.0` (see `meta/runtime.yml`).
- **RFC2307/POSIX attributes** (`uid_number`, `gid_number`,
  `unix_home_directory`, `login_shell`, `gecos` on `samba_user`; `gid_number`
  on `samba_group`) require a domain provisioned with `--use-rfc2307`. Setting
  any of them on a domain without RFC2307 fails before any change is made; not
  setting them leaves such domains entirely unaffected.

## Connection setup

Every module connects to the DC with **explicit caller credentials** over LDAP
using SASL/GSSAPI with signing and sealing on port 389 (the GSSAPI layer
encrypts the traffic; there is no LDAPS or StartTLS). Kerberos is required and
the ticket is held in an in-memory credential cache that never touches disk.

Each module therefore takes these connection options:

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

All modules share these options through the `jomrr.samba.all` action group, so
you can set them once with `module_defaults` instead of repeating them on every
task:

```yaml
- name: Manage the Samba AD DC
  hosts: dc
  module_defaults:
    group/jomrr.samba.all:
      server: dc1.example.com
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
  hosts: dc
  module_defaults:
    group/jomrr.samba.all:
      server: dc1.example.com
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

## Architecture

See `architecture/decisions.md` in the source repository for the design
decisions behind the collection:

- Samba backend (native Python bindings) and lazy-import encapsulation
- Connection model (explicit GSSAPI credentials, sign + seal, in-memory ccache)
- Container runtime (rootless Podman) and DC test topology

## Tests

```bash
ansible-lint
ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test sanity --docker --python 3.12
ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test units  --docker --python 3.12
molecule test
```

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).
