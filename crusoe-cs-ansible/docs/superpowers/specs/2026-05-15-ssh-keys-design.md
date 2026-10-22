# SSH Authorized Keys Management — Design Spec

**Date:** 2026-05-15

## Goal

A playbook to deploy and remove SSH authorized keys for the Ansible remote user across target hosts. Keys are defined in a version-controlled file and can be applied or removed in bulk or per-user.

## File Structure

```
roles/ssh_keys/
  files/
    authorized_keys.yml     # list of {username, pub_key} dicts
  tasks/
    main.yml                # deploy/remove logic using ansible.posix.authorized_key
playbooks/ssh_keys.yml      # entry point with usage documentation at the top
```

## Key Definitions File

`roles/ssh_keys/files/authorized_keys.yml` holds the full list of managed keys:

```yaml
ssh_authorized_keys:
  - username: alice
    pub_key: "ssh-ed25519 AAAA... alice@host"
  - username: bob
    pub_key: "ssh-ed25519 AAAA... bob@host"
```

`username` is a human-readable label used to filter at run time. It does not need to match a Linux username — it identifies the key owner within the file.

## Playbook Variables

| Variable       | Required | Default      | Description                                      |
|----------------|----------|--------------|--------------------------------------------------|
| `target_hosts` | yes      | —            | Host or group pattern (Ansible inventory target) |
| `state`        | no       | `present`    | `present` to add keys, `absent` to remove        |
| `ssh_users`    | no       | all entries  | List of usernames to act on; omit to act on all  |

## Role Task Logic

1. Load `authorized_keys.yml` from the role's `files/` directory using `lookup('file', ...)` + `from_yaml`.
2. Filter the list: if `ssh_users` is defined, keep only entries whose `username` is in that list. Otherwise use all entries.
3. Loop over the filtered list and call `ansible.posix.authorized_key` with:
   - `user: "{{ ansible_user }}"` — the remote user Ansible connects as
   - `key: "{{ item.pub_key }}"`
   - `state: "{{ state }}"`

## Playbook Usage Comment

The top of `playbooks/ssh_keys.yml` documents all variables and example invocations:

```
# Usage: ansible-playbook playbooks/ssh_keys.yml -e target_hosts=<group>
#
# Variables:
#   target_hosts  (required) — inventory host or group
#   state         (optional, default: present) — present | absent
#   ssh_users     (optional) — list of usernames to act on; omit for all
#
# Examples:
#   Add all keys:
#     ansible-playbook playbooks/ssh_keys.yml -e target_hosts=gpu-nodes
#
#   Add only alice's key:
#     ansible-playbook playbooks/ssh_keys.yml -e target_hosts=gpu-nodes \
#       -e '{"ssh_users":["alice"]}'
#
#   Remove bob's key:
#     ansible-playbook playbooks/ssh_keys.yml -e target_hosts=gpu-nodes \
#       -e '{"ssh_users":["bob"],"state":"absent"}'
```

## Dependencies

`ansible.posix` collection must be added to `requirements.yml`:

```yaml
collections:
  - name: ansible.posix
```

## Out of Scope

- Managing keys for users other than `ansible_user`
- Fetching keys from external sources (GitLab, GitHub, LDAP)
- Exclusive key management (replacing all keys, not just adding/removing specific ones)
