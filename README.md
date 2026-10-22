# crusoe-cs

Tooling from the Crusoe Cloud Support team for operating and
maintaining Crusoe Cloud infrastructure.

Crusoe Cloud Support Portal → <https://support.crusoecloud.com/>

## ⚠️ DISCLAIMER

This repository is a community resource and is not officially supported,
endorsed, or maintained by Crusoe. While we make reasonable, best-effort
attempts to maintain and update tooling and dependencies, this repository
is provided "AS IS" without warranties of any kind. You use this software
entirely at your own risk.

## Repository layout

| Path | What it is |
|---|---|
| [`crusoe-cs-ansible/`](crusoe-cs-ansible/) | Ansible playbooks, roles, dynamic inventory, and Helm charts for Crusoe Cloud k8s node operations — see its [README](crusoe-cs-ansible/README.md) for setup and usage |

## Conventions

- Component subdirectories are self-contained: each carries its own
  README, tooling, and lint gates. The monorepo root stays thin.
- Commit style: conventional prefixes (`feat:`, `fix:`, `test:`,
  `chore:`, `docs:`).
- CI runs per component (see each component's config) plus monorepo
  root checks as they are introduced.
