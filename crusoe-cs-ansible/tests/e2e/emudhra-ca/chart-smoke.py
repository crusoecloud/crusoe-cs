#!/usr/bin/env python3
"""E2E smoke for the crusoe-distrust-emudhra-ca chart on a REAL Crusoe cluster.

Proves the full image-mechanism path end-to-end: build the image from the
working tree (never a stale local tag), push it to CCR (the cluster's
native registry), helm-install the chart into a dedicated namespace, and
assert real remediation on the cluster's nodes — then prove idempotency
by re-running one pod, and prove the journald callback landed events in
the node's journal.

⚠️ REAL-FLEET ACTION: this remediates the target nodes' trust stores
(idempotent, advisory-mandated) and creates a CCR repo + token. That is
the point — but it is not a dry run.

Usage: tests/e2e/emudhra-ca/chart-smoke.py [--keep]
    --keep  skip teardown (leave the release installed for inspection)

No hardcoding: every environment-specific value flows from an env var
with a discovery-based default — the script never carries literal
registry URLs, repo names, project IDs, namespaces, or secret names.

Env contract (all optional):
    EMUDHRA_SMOKE_KUBE_CONTEXT  kube context (default: current context;
                                must be backed by a crusoe-client-admin-*
                                user credential)
    EMUDHRA_SMOKE_CCR_LOCATION  CCR location (default: discovered from
                                the cluster record via the crusoe CLI)
    EMUDHRA_SMOKE_CCR_REPO      CCR repo name (default: crusoe-distrust-emudhra-ca)
    EMUDHRA_SMOKE_CCR_PROJECT   CCR project id (default: discovered from
                                `crusoe registry repositories list`)
    EMUDHRA_SMOKE_NAMESPACE     install namespace (default:
                                crusoe-distrust-emudhra-ca-smoke)
    EMUDHRA_SMOKE_RELEASE       helm release name (default:
                                crusoe-distrust-emudhra-ca-smoke)
    EMUDHRA_SMOKE_PULL_SECRET   pull secret (default: crusoe-registry-pull
                                if present in the namespace, else created)
    EMUDHRA_SMOKE_IMAGE_TAG     image tag (default: smoke-<git-sha>, never
                                latest — traceable to the commit)

Requires: kubectl, docker, helm, crusoe CLI.

CCR auth: username = Crusoe account email (crusoe whoami), password = a
fresh token from `crusoe registry tokens create` (contains `$` — piped
via --password-stdin, never echoed).

SAFETY: never touches the crusoe-node-remediation namespace, its
DaemonSet, or its secret. Installs ONLY into the dedicated smoke
namespace; teardown = helm uninstall + namespace delete. Exit 0 = pass,
non-zero = fail; teardown runs on any exit unless --keep.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CHARTS_DIR = os.path.join(REPO_ROOT, "charts")
IMAGES_DIR = os.path.join(REPO_ROOT, "images")


def chart_name() -> str:
    """Discover the chart: the one under charts/ whose Chart.yaml
    description mentions the emudhra remediation. Renaming the chart
    must not require editing this script; EMUDHRA_SMOKE_CHART overrides.
    """
    override = os.environ.get("EMUDHRA_SMOKE_CHART", "")
    if override:
        return override
    for entry in sorted(os.listdir(CHARTS_DIR)):
        chart_yaml = os.path.join(CHARTS_DIR, entry, "Chart.yaml")
        if not os.path.isfile(chart_yaml):
            continue
        with open(chart_yaml) as f:
            content = f.read()
        if "emudhra" in content:
            m = re.search(r"^name:\s*(\S+)", content, re.M)
            if m:
                return m.group(1)
    die("could not discover the emudhra chart under charts/ — "
        "set EMUDHRA_SMOKE_CHART")

KEEP = "--keep" in sys.argv

log_prefix = "[chart-smoke]"


def log(msg: str) -> None:
    print(f"{log_prefix} {msg}")


def die(msg: str) -> None:
    print(f"{log_prefix} FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def run(cmd: list[str], *, check: bool = True, input_text: str | None = None,
        env: dict | None = None, quiet: bool = False) -> subprocess.CompletedProcess:
    """Run a command; optionally raise on failure. Never uses a shell."""
    return subprocess.run(
        cmd, check=check, input=input_text, env=env,
        capture_output=True, text=True,
    )


def out(cmd: list[str], **kwargs) -> str:
    """Run a command and return stdout (raises on failure)."""
    return run(cmd, **kwargs).stdout.strip()


# ---------------------------------------------------------------------------
# 0. Resolve values (env var wins, discovery-based default otherwise)
# ---------------------------------------------------------------------------

def require_tool(name: str) -> None:
    if run(["which", name], check=False).returncode != 0:
        die(f"{name} not found")


def current_kube_context() -> str:
    return out(["kubectl", "config", "current-context"])


def context_user(context: str) -> str:
    """The credential behind a kube context (crusoe-client-admin-* check)."""
    cfg = json.loads(out(["kubectl", "config", "view", "-o", "json"]))
    for ctx in cfg.get("contexts", []):
        if ctx.get("name") == context:
            return (ctx.get("context") or {}).get("user", "")
    return ""


def discover_ccr_location(cluster: str) -> str:
    """The cluster record carries the authoritative location field."""
    listing = json.loads(out(["crusoe", "kubernetes", "clusters", "list", "--format", "json"]))
    for c in listing:
        if c["name"] == cluster:
            return c["location"]
    die(f"could not discover the CCR location for cluster '{cluster}' — "
        "set EMUDHRA_SMOKE_CCR_LOCATION")


def resolve_ccr_repo(repo_name: str, location: str, project_env: str) -> tuple[str, str]:
    """Find or create the CCR repo; return (repo_url, full_project_id).

    The repo url embeds the project-8: <repo-name>.<project8>.
    """
    listing = json.loads(out(["crusoe", "registry", "repositories", "list", "--format", "json"]))
    repo_url = next((r["url"] for r in listing if r["name"] == repo_name), "")
    if not repo_url:
        log(f"CCR repo {repo_name} absent — creating ({location}, standard)")
        created = json.loads(out([
            "crusoe", "registry", "repositories", "create",
            "--name", repo_name, "--location", location,
            "--mode", "standard", "--format", "json",
        ]))
        repo_url = created["url"]
        if not repo_url:
            die("could not read repo url from create output")
    m = re.search(r"\.([a-f0-9]{8})$", repo_url)
    if not m:
        die(f"could not parse project-8 from repo url '{repo_url}'")
    project8 = m.group(1)
    if project_env:
        return repo_url, project_env
    projects = json.loads(out(["crusoe", "projects", "list", "--format", "json"]))
    full = next((p["id"] for p in projects if p["id"].startswith(project8)), "")
    if not full:
        die(f"could not discover the full project id for prefix {project8} — "
            "set EMUDHRA_SMOKE_CCR_PROJECT")
    return repo_url, full


def main() -> None:
    for tool in ("kubectl", "helm", "docker", "crusoe"):
        require_tool(tool)

    current = current_kube_context()
    kube_context = os.environ.get("EMUDHRA_SMOKE_KUBE_CONTEXT", current)
    if kube_context != current:
        die(f"kube context {kube_context} is not the current context ({current}) — "
            f"kubectl config use-context {kube_context} first")
    user = context_user(kube_context)
    if not user.startswith("crusoe-client-admin-"):
        die(f"kube context '{kube_context}' (user '{user or '<none>'}') is not backed "
            "by a crusoe-client-admin-* credential — refusing to run against an "
            "unknown cluster")

    ccr_location = os.environ.get("EMUDHRA_SMOKE_CCR_LOCATION", "") \
        or discover_ccr_location(kube_context)
    chart = chart_name()
    chart_dir = os.path.join(CHARTS_DIR, chart)
    dockerfile = os.path.join(IMAGES_DIR, chart, "Dockerfile")

    ccr_repo = os.environ.get("EMUDHRA_SMOKE_CCR_REPO", chart)
    ns = os.environ.get("EMUDHRA_SMOKE_NAMESPACE", f"{chart}-smoke")
    release = os.environ.get("EMUDHRA_SMOKE_RELEASE", f"{chart}-smoke")
    # Pull secret: env override wins; otherwise reuse the well-known
    # crusoe-registry-pull secret if it already exists in the namespace,
    # else create one named after the release (created below from the
    # fresh CCR token).
    pull_secret = os.environ.get("EMUDHRA_SMOKE_PULL_SECRET", "")
    image_tag = os.environ.get(
        "EMUDHRA_SMOKE_IMAGE_TAG",
        "smoke-" + out(["git", "-C", REPO_ROOT, "rev-parse", "--short", "HEAD"]),
    )
    if image_tag == "latest":
        die("refusing to push :latest — the tag must trace to a commit")

    ccr_registry = f"registry.{ccr_location}.ccr.crusoecloudcompute.com"

    log("resolved values (override any via EMUDHRA_SMOKE_*):")
    log(f"  kube context:  {kube_context}")
    log(f"  CCR location:  {ccr_location}")
    log(f"  CCR repo:      {ccr_repo}")
    log(f"  CCR project:   <discovered below>")
    log(f"  namespace:     {ns}")
    log(f"  release:       {release}")
    log(f"  pull secret:   {pull_secret or '<discovered below>'}")
    log(f"  image tag:     {image_tag}")

    repo_url, _project = resolve_ccr_repo(
        ccr_repo, ccr_location, os.environ.get("EMUDHRA_SMOKE_CCR_PROJECT", ""))
    image = f"{repo_url}/{chart}:{image_tag}"
    log(f"CCR repo url: {repo_url}")
    log(f"image: {image}")

    # ------------------------------------------------------------------
    # 1. Build the image from the working tree (never a stale local tag).
    #    Nodes are amd64; build that platform explicitly.
    # ------------------------------------------------------------------
    log(f"building image from working tree: {image} (linux/amd64)")
    run(["docker", "buildx", "build", "--platform", "linux/amd64", "--load",
         "-f", dockerfile, "-t", image, REPO_ROOT],
        check=True)
    log("build OK")

    # ------------------------------------------------------------------
    # 2. Push to CCR (fresh token, --password-stdin, never echoed)
    # ------------------------------------------------------------------
    whoami = out(["crusoe", "whoami"])
    m = re.search(r"\(([^)]+@[^)]+)\)", whoami)
    ccr_user = m.group(1) if m else None
    if not ccr_user:
        die("could not determine Crusoe account email (crusoe whoami)")

    token_key_id = ""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".token", delete=False) as tf:
        token_file = tf.name
    os.chmod(token_file, 0o600)
    try:
        created = json.loads(out([
            "crusoe", "registry", "tokens", "create",
            "--alias", f"{chart}-chart-smoke", "--format", "json",
        ]))
        token_key_id = created.get("key_id", "")
        with open(token_file, "w") as f:
            f.write(created["token"])
        if not os.path.getsize(token_file):
            die("crusoe registry tokens create produced no token")

        run(["docker", "login", ccr_registry, "--username", ccr_user,
             "--password-stdin"], check=True, input_text=open(token_file).read())
        log(f"docker login OK (user: {ccr_user})")

        log(f"pushing {image}")
        run(["docker", "push", image], check=True)
        log("push OK")
        run(["docker", "logout", ccr_registry], check=False)

        # --------------------------------------------------------------
        # 3. Namespace + pull secret + helm install
        # --------------------------------------------------------------
        if run(["kubectl", "get", "namespace", ns], check=False).returncode != 0:
            run(["kubectl", "create", "namespace", ns], check=True)
        if not pull_secret:
            # Discovery: reuse the well-known crusoe-registry-pull secret
            # if it exists in this namespace, else create one named after
            # the release from the fresh CCR token.
            if run(["kubectl", "get", "secret", "crusoe-registry-pull", "-n", ns],
                   check=False).returncode == 0:
                pull_secret = "crusoe-registry-pull"
            else:
                pull_secret = f"{release}-pull"
        if run(["kubectl", "get", "secret", pull_secret, "-n", ns],
               check=False).returncode != 0:
            log(f"creating pull secret {pull_secret} in {ns}")
            run(["kubectl", "create", "secret", "docker-registry", pull_secret,
                 "-n", ns,
                 "--docker-server", ccr_registry,
                 "--docker-username", ccr_user,
                 "--docker-password", open(token_file).read()],
                check=True)

        log(f"helm install {release} into {ns} (image: {image})")
        run(["helm", "install", release, chart_dir, "-n", ns,
             "--set", f"image.full={image}",
             "--set", f"imagePullSecrets[0].name={pull_secret}"],
            check=True)

        # --------------------------------------------------------------
        # 4. Wait event-driven for all pods to be Ready, then for each
        #    playbook to FINISH (Ready only means the container started).
        # --------------------------------------------------------------
        node_count = len(out(["kubectl", "get", "nodes", "-o", "name"]).splitlines())
        log(f"waiting for {node_count} pods Ready (event-driven, 600s timeout)")
        run(["kubectl", "wait", "--for=condition=Ready", "pod",
             "-l", f"app={release}", "-n", ns, "--timeout=600s"],
            check=True)
        ready = len(out(["kubectl", "get", "pods", "-l", f"app={release}", "-n", ns,
                         "--field-selector", "status.phase=Running",
                         "-o", "name"]).splitlines())
        if ready != node_count:
            die(f"expected {node_count} Running pods, found {ready}")
        log(f"all {ready} pods Running")

        def wait_for_recap(pod: str, max_attempts: int = 120) -> bool:
            """Poll for PLAY RECAP (bounded; no fixed long sleeps)."""
            for _ in range(max_attempts):
                logs = run(["kubectl", "logs", "-n", ns, pod],
                           check=False).stdout
                if "PLAY RECAP" in logs:
                    return True
                phase = out(["kubectl", "get", "pod", pod, "-n", ns,
                             "-o", "jsonpath={.status.phase}"]) if run(
                    ["kubectl", "get", "pod", pod, "-n", ns],
                    check=False).returncode == 0 else "Gone"
                if phase != "Running":
                    return False
                time.sleep(5)
            return False

        all_pods = out(["kubectl", "get", "pods", "-l", f"app={release}", "-n", ns,
                        "-o", "name"]).splitlines()
        all_pods = [p.removeprefix("pod/") for p in all_pods]
        for pod in all_pods:
            if not wait_for_recap(pod):
                logs = run(["kubectl", "logs", "-n", ns, pod, "--tail=40"],
                           check=False).stdout
                prev = run(["kubectl", "logs", "-n", ns, pod, "--previous",
                            "--tail=40"], check=False).stdout
                print(logs, file=sys.stderr)
                print(prev, file=sys.stderr)
                die(f"{pod}: playbook never finished (no PLAY RECAP within the wait window)")
            log(f"{pod}: playbook finished (recap present)")

        # --------------------------------------------------------------
        # 5. Assert remediation evidence in the first run's logs
        # --------------------------------------------------------------
        def assert_pod_recap(pod: str, label: str) -> None:
            """State-tolerant: the fleet may be freshly affected (changed>=1,
            affected=True) or already remediated by an earlier run
            (changed=0, affected=False). Either way failed=0 is mandatory."""
            logs = run(["kubectl", "logs", "-n", ns, pod], check=False).stdout
            if "failed=0" not in logs:
                print(logs[-1500:], file=sys.stderr)
                die(f"{label}: {pod} recap missing failed=0")
            changed = re.findall(r"changed=(\d+)", logs)
            if not changed:
                print(logs[-1500:], file=sys.stderr)
                die(f"{label}: {pod} recap missing changed=N")
            n_changed = int(changed[-1])
            if n_changed >= 1 and "affected=True" in logs:
                log(f"{label}: {pod} remediated (changed={n_changed}, failed=0, affected=True)")
            elif n_changed == 0 and "affected=False" in logs:
                log(f"{label}: {pod} already clean (changed=0, failed=0, affected=False)")
            else:
                print(logs[-1500:], file=sys.stderr)
                die(f"{label}: {pod} inconsistent recap (changed={n_changed}, "
                    "expected changed>=1+affected=True or changed=0+affected=False)")

        first_pod = all_pods[0]
        assert_pod_recap(first_pod, "first-run")

        for pod in all_pods:
            logs = run(["kubectl", "logs", "-n", ns, pod], check=False).stdout
            if "failed=0" not in logs:
                log(f"WARN: {pod} missing failed=0")
        log("all pods report failed=0")

        # --------------------------------------------------------------
        # 6. Journald callback: task events must have landed in the node's
        #    journal (the Watch Agent forwards them to the console). Read
        #    the journal ON the node via a privileged debug pod — the same
        #    hostPath the chart itself uses.
        # --------------------------------------------------------------
        def assert_node_journal(node: str) -> None:
            # The identifier is whatever the chart sets — read it from the
            # rendered template instead of duplicating the literal here.
            rendered = run(["helm", "template", release, chart_dir, "-n", ns],
                           check=True).stdout
            m = re.search(r"value:\s*(\S+)", rendered[rendered.index("ANSIBLE_JOURNALD_IDENTIFIER"):])
            identifier = m.group(1) if m else chart
            script = (f"grep -c 'SYSLOG_IDENTIFIER={identifier}' "
                      "/host/var/log/journal/*/*.journal 2>/dev/null "
                      "| awk -F: '{s+=$NF} END {print s+0}'")
            p = run(["kubectl", "debug", f"node/{node}", "--image=busybox", "--",
                     "sh", "-c", script], check=False)
            # kubectl debug is ASYNC: it creates the pod and returns before
            # the command runs. Parse the debug pod's name, wait for it to
            # complete, then read its logs.
            m = re.search(r"Creating debugging pod (\S+)", p.stdout or "")
            if not m:
                die(f"journald: could not create a debug pod on {node}: "
                    f"{(p.stderr or p.stdout or '')[-300:]}")
            debug_pod = m.group(1)
            run(["kubectl", "wait", "--for=condition=Ready", f"pod/{debug_pod}",
                 "--timeout=120s"], check=True)
            # The container may complete between Ready and the log read;
            # poll briefly for non-empty logs (bounded, event-ish).
            logs = ""
            for _ in range(12):  # ~12s worst case
                logs = run(["kubectl", "logs", debug_pod], check=False).stdout
                if logs.strip():
                    break
                time.sleep(1)
            count = 0
            for line in reversed(logs.strip().splitlines()):
                if line.isdigit():
                    count = int(line)
                    break
            run(["kubectl", "delete", "pod", debug_pod, "--wait=false"],
                check=False)
            if count < 1:
                die(f"journald: node {node} journal has no {identifier} events "
                    f"(callback did not write? logs={logs[-300:]})")
            log(f"journald: node {node} journal has {count} {identifier} events")

        def assert_forwarder_healthy(node: str) -> None:
            """The Watch Agent (Vector) is the hop from the node journal to
            the Managed Logs console. There is no public query API for the
            console (the ingest endpoint is write-only), so assert the
            forwarder is alive and not dropping: the crusoe_ingest sink
            must have no dropped/fatal events in its recent logs.
            Transient connection-reset WARNs are normal (Vector retries
            from its disk buffer)."""
            agent_pod = out([
                "kubectl", "get", "pods", "-n", "crusoe-system",
                "-l", "app.kubernetes.io/name=crusoe-watch-agent",
                "--field-selector", f"spec.nodeName={node}",
                "-o", "jsonpath={.items[0].metadata.name}",
            ])
            if not agent_pod:
                # Label may differ across versions; fall back to prefix.
                agent_pod = out([
                    "kubectl", "get", "pods", "-n", "crusoe-system", "-o", "name",
                    "--field-selector", f"spec.nodeName={node}",
                ]).splitlines()
                agent_pod = next(
                    (p.removeprefix("pod/") for p in agent_pod
                     if "watch-agent" in p), "")
            if not agent_pod:
                die(f"forwarder: no crusoe-watch-agent pod found on {node}")
            logs = run(["kubectl", "logs", "-n", "crusoe-system", agent_pod,
                        "--since=1h"], check=False).stdout
            bad = [ln for ln in logs.splitlines()
                   if "crusoe_ingest" in ln
                   and any(w in ln.lower() for w in ("dropped", "fatal", "gave up"))]
            if bad:
                print("\n".join(bad[-5:]), file=sys.stderr)
                die(f"forwarder: {agent_pod} on {node} is dropping "
                    f"crusoe_ingest events ({len(bad)} recent occurrences)")
            log(f"forwarder: {agent_pod} on {node} healthy "
                "(no dropped crusoe_ingest events in the last hour)")

        journal_node = out(["kubectl", "get", "pod", first_pod, "-n", ns,
                            "-o", "jsonpath={.spec.nodeName}"])
        assert_node_journal(journal_node)
        assert_forwarder_healthy(journal_node)


        # --------------------------------------------------------------
        # 7. Idempotency: delete one pod, wait for replacement, changed=0
        # --------------------------------------------------------------
        log(f"idempotency: deleting {first_pod} and waiting for replacement")
        node_of_first = out(["kubectl", "get", "pod", first_pod, "-n", ns,
                             "-o", "jsonpath={.spec.nodeName}"])
        run(["kubectl", "delete", "pod", first_pod, "-n", ns, "--wait=true"],
            check=True)
        run(["kubectl", "wait", "--for=condition=Ready", "pod",
             "-l", f"app={release}", "-n", ns,
             "--field-selector", f"spec.nodeName={node_of_first}",
             "--timeout=600s"], check=True)
        repl = out(["kubectl", "get", "pods", "-l", f"app={release}", "-n", ns,
                    "--field-selector", f"spec.nodeName={node_of_first}",
                    "-o", "name"]).splitlines()
        repl = [p.removeprefix("pod/") for p in repl]
        if not repl:
            die(f"no replacement pod found on {node_of_first}")
        replacement = repl[0]
        if replacement == first_pod:
            die("replacement pod is the same pod (delete did not work?)")
        if not wait_for_recap(replacement):
            die(f"replacement pod {replacement}: playbook never finished")

        repl_logs = run(["kubectl", "logs", "-n", ns, replacement],
                        check=False).stdout
        if "failed=0" not in repl_logs:
            print(repl_logs[-1500:], file=sys.stderr)
            die(f"idempotency: {replacement} recap missing failed=0")
        repl_changed = re.findall(r"changed=(\d+)", repl_logs)
        if repl_changed and int(repl_changed[-1]) != 0:
            print(repl_logs[-1500:], file=sys.stderr)
            die(f"idempotency: {repl_changed[-1]} changes on re-run (expected 0)")
        if "affected=False" not in repl_logs:
            print(repl_logs[-1500:], file=sys.stderr)
            die(f"idempotency: {replacement} missing affected=False on re-run")
        log(f"idempotency: {replacement} re-run changed=0, affected=False, failed=0")

        log(f"PASS: {ready}/{node_count} nodes parked; first run remediated "
            "(changed>=1, affected=True); re-run idempotent (changed=0); "
            "journald events present on the node")
    finally:
        # The token file held a live credential — always unlink it.
        try:
            os.unlink(token_file)
        except OSError:
            pass
        # With --keep the release stays installed and its pull secret
        # references this token — deleting it would break future pulls
        # on nodes with a cold image cache (the VM-replacement lesson).
        if token_key_id and not KEEP:
            run(["crusoe", "registry", "tokens", "delete", token_key_id],
                check=False, capture_output=True)
            log(f"smoke token {token_key_id} deleted")
        elif token_key_id and KEEP:
            log(f"--keep: smoke token {token_key_id} left in place "
                "(the pull secret references it)")
        if KEEP:
            log(f"--keep: leaving {ns} installed for inspection")
        else:
            log(f"teardown: helm uninstall {release} + namespace {ns}")
            run(["helm", "uninstall", release, "-n", ns], check=False)
            run(["kubectl", "delete", "namespace", ns, "--wait=true"],
                check=False)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        tail = (e.stderr or e.stdout or "")[-1500:]
        print(f"{log_prefix} FAIL: command failed "
              f"({' '.join(e.cmd)}): {tail}", file=sys.stderr)
        sys.exit(1)
