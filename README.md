# Ansible Collection: `jomrr.samba`

Modules for managing a Samba AD DC through the native Python bindings:
users, groups, OUs, and the Samba internal DNS.

## Modules

| Module | Purpose | idempotent | check_mode |
|--------|---------|------------|------------|
| `samba_user` | Manage users | yes | yes |
| `samba_user_info` | Query users | n/a (read) | n/a |
| `samba_group` | Manage groups | yes | yes |
| `samba_group_info` | Query groups | n/a (read) | n/a |
| `samba_ou` | Manage OUs | yes | yes |
| `samba_ou_info` | Query OUs | n/a (read) | n/a |
| `samba_dns_record` | Manage DNS records | yes | yes |
| `samba_dns_record_info` | Query DNS records | n/a (read) | n/a |

## Architecture

See `architecture/decisions.md`:

- Container runtime (rootless Podman, Fedora 43)
- Samba backend (Python bindings) and import encapsulation
- DC topology (DC inside the Molecule container)

## Tests

```bash
ansible-lint
ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test sanity --docker --python 3.12
ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test units  --docker --python 3.12
molecule test
```
