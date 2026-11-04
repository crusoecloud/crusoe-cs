"""The docker-target harness: build, run, exec, playbook — the
scenario substrate for the container-based e2e scenarios.

The live-found rules preserved here:
  - the memory fact cache (the container host is always "target", so
    the jsonfile cache would serve the PREVIOUS scenario's OS facts —
    Ubuntu facts on a Rocky container → apt task on a dnf host)
  - the systemd boot wait (degraded is fine in a container)
  - the target matrix: capabilities per target, scenario selection
"""

from __future__ import annotations

import subprocess
import time

from .runner import CommandError, run

CONTAINER = "target"


def _find_ansible(repo_root: str) -> str:
    """The project venv's ansible-playbook (community.docker lives
    there — the PATH one lacks it). Same resolution as the shell
    era's find_ansible_venv."""
    import os

    candidates = [
        f"{repo_root}/.venv/bin/ansible-playbook",
        os.path.expanduser("~/git/crusoe-cs-ansible/.venv/bin/ansible-playbook"),
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return "ansible-playbook"  # PATH fallback (CI installs it)


# The target matrix (design spec §6): scenario bodies are
# platform-neutral; targets declare capabilities and scenarios
# select/skip per capability. docker-ubuntu/docker-rocky: full host
# userspace, systemd (boot-unit: yes). docker-alpine: cos-like — no
# systemd (boot-unit: no → interval-only persistence). Future targets
# (kind, GKE) slot in here via the same capability contract.
TARGET_SPECS: dict[str, dict[str, bool]] = {
    "docker-ubuntu": {"boot-unit": True, "cloud-init": True},
    "docker-rocky": {"boot-unit": True, "cloud-init": False},
    "docker-alpine": {"boot-unit": False},
    "gke-cos": {"boot-unit": False, "host-userspace": False, "netns-mounts": False},
}

_DOCKERFILES = {
    ("ubuntu",): "Dockerfile.debian",
    ("debian",): "Dockerfile.debian",
    ("rockylinux",): "Dockerfile.redhat",
    ("almalinux",): "Dockerfile.redhat",
    ("alpine",): "Dockerfile.alpine",
}


def image_to_target(image: str) -> str:
    family = image.split(":")[0]
    if family in ("ubuntu", "debian"):
        return "docker-ubuntu"
    if family in ("rockylinux", "almalinux"):
        return "docker-rocky"
    if family == "alpine":
        return "docker-alpine"
    if image == "gke-cos":
        return "gke-cos"
    return "docker-ubuntu"


def target_capability(target: str, capability: str) -> bool:
    return TARGET_SPECS.get(target, {}).get(capability, False)


class DockerTarget:
    """One privileged container playing the host role.

    --privileged: nft needs NET_ADMIN; systemd needs the extra caps.
    The container keeps its own network namespace, so the rules never
    reach the docker host. Named "target" to match the inventory
    host — the community.docker connection plugin resolves the
    container by inventory hostname.
    """

    def __init__(self, e2e_dir: str, repo_root: str) -> None:
        self.e2e_dir = e2e_dir
        self.repo_root = repo_root
        self.tag: str | None = None

    # --- lifecycle -----------------------------------------------------
    def build(self, image: str) -> str:
        """Build the target image; returns the tag."""
        family = image.split(":")[0]
        dockerfile = next(
            (df for fams, df in _DOCKERFILES.items() if family in fams), None
        )
        if dockerfile is None:
            raise CommandError(
                f"unsupported image: {image} "
                "(ubuntu:*|debian:*|rockylinux:*|almalinux:*|alpine:*)"
            )
        tag = f"cve98432-e2e-{image.replace(':', '-').replace('/', '-')}"
        run(
            [
                "docker",
                "build",
                "-q",
                "-t",
                tag,
                "--build-arg",
                f"BASE={image}",
                "-f",
                f"{self.e2e_dir}/images/{dockerfile}",
                f"{self.e2e_dir}/images",
            ]
        )
        self.tag = tag
        return tag

    def start(self, image: str, *, systemd: bool = True) -> None:
        """Run the container. systemd=True boots /lib/systemd/systemd
        and waits for is-system-running (degraded is fine); False
        runs `sleep infinity` (the pod-native shape — no systemd
        needed, the pod-native path never touches the host's
        userspace)."""
        run(["docker", "rm", "-f", CONTAINER], check=False)
        cmd = [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--privileged",
            "--cgroupns=private",
            "--tmpfs",
            "/run",
        ]
        if systemd:
            cmd += [
                "--tmpfs",
                "/run/lock",
                "--name",
                CONTAINER,
                image,
                "/lib/systemd/systemd",
            ]
        else:
            cmd += ["--name", CONTAINER, image, "sleep", "infinity"]
        run(cmd)
        if systemd:
            self._wait_systemd()

    def _wait_systemd(self, attempts: int = 30) -> None:
        for _ in range(attempts):
            st = run(
                ["docker", "exec", CONTAINER, "systemctl", "is-system-running"],
                check=False,
            ).stdout.strip()
            if st in ("running", "degraded"):
                return
            time.sleep(1)
        raise CommandError("systemd did not finish booting")

    def stop(self) -> None:
        run(["docker", "rm", "-f", CONTAINER], check=False)

    # --- exec / copy ------------------------------------------------------
    def exec(
        self, *cmd: str, check: bool = True, env: dict[str, str] | None = None
    ) -> str:
        env_flags = [
            f for kv in (env or {}).items() for f in ("-e", f"{kv[0]}={kv[1]}")
        ]
        return run(["docker", "exec", *env_flags, CONTAINER, *cmd], check=check).stdout

    def exec_ok(self, *cmd: str, env: dict[str, str] | None = None) -> bool:
        env_flags = [
            f for kv in (env or {}).items() for f in ("-e", f"{kv[0]}={kv[1]}")
        ]
        return (
            run(["docker", "exec", *env_flags, CONTAINER, *cmd], check=False).returncode
            == 0
        )

    def exec_rc(self, *cmd: str, env: dict[str, str] | None = None) -> int:
        """The exit code (stdout discarded) — for the probe contract:
        rc 1 = PASS, rc 0 = not working, rc 2 = collateral, rc 3 =
        crash. Only rc 1 is a pass; the caller asserts on the exact
        code, never a blanket 'non-zero'."""
        env_flags = [
            f for kv in (env or {}).items() for f in ("-e", f"{kv[0]}={kv[1]}")
        ]
        return run(
            ["docker", "exec", *env_flags, CONTAINER, *cmd], check=False
        ).returncode

    def exec_python(
        self, code: str, check: bool = True, env: dict[str, str] | None = None
    ) -> str:
        """Run python code in the container (stdin — no quoting)."""
        env_flags = [
            flag for kv in (env or {}).items() for flag in ("-e", f"{kv[0]}={kv[1]}")
        ]
        proc = subprocess.run(
            ["docker", "exec", "-i", *env_flags, CONTAINER, "python3", "-"],
            input=code,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if check and proc.returncode != 0:
            raise CommandError(f"python exec failed: {proc.stderr.strip()}")
        return proc.stdout

    def copy_in(self, local: str, remote: str) -> None:
        run(["docker", "cp", local, f"{CONTAINER}:{remote}"])

    def restart(self) -> None:
        """docker restart re-executes PID1; the container survives —
        the boot-cycle shape."""
        run(["docker", "restart", CONTAINER])

    # --- ansible ------------------------------------------------------------
    def write_inventory(self) -> None:
        """The docker-connection inventory (the container host is
        always "target")."""
        path = f"{self.e2e_dir}/inventory.tmp"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(
                "[target]\n"
                "target ansible_connection=community.docker.docker "
                "ansible_user=root ansible_python_interpreter=/usr/bin/python3 "
                "ansible_remote_tmp=/tmp/ansible home=/root "
                f"ansible_docker_container={CONTAINER}\n"
            )

    def run_playbook(self, playbook: str, *extra: str, wrapper: bool = False) -> str:
        """Run a playbook against the container. The memory fact
        cache is mandatory: the container host is always "target",
        so the jsonfile cache would serve the PREVIOUS scenario's OS
        facts (Ubuntu facts on a Rocky container → apt task on a dnf
        host). The interpreter is the project venv's
        ansible-playbook (community.docker lives there — the PATH
        one lacks it)."""
        import os

        self.write_inventory()
        argv = [
            _find_ansible(self.repo_root),
            "-i",
            f"{self.e2e_dir}/inventory.tmp",
            playbook,
            "-e",
            "target_hosts=target",
            *extra,
        ]
        env = dict(
            os.environ,
            ANSIBLE_CACHE_PLUGIN="memory",
            ANSIBLE_CONFIG=f"{self.repo_root}/ansible.cfg",
        )
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            cwd=self.repo_root,
            env=env,
            timeout=600,
        )
        if proc.returncode != 0:
            raise CommandError(f"playbook failed: {proc.stderr.strip()[-500:]}")
        return proc.stdout
