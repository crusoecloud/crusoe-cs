#!/usr/bin/env python3
"""Generic mitigation entrypoint for the crusoe-mitigator DaemonSet.

The chart renders the enabled mitigations into the MITIGATIONS env var,
one per line:  <name>|<wrapper-playbook>|<flat -e vars>|<interval-seconds>

interval 0 (or absent) = ONCE per pod start. Re-runs happen when the pod
restarts (node reboot, pod deletion, chart upgrade) — the park model.
interval > 0 = SCHEDULED: the entrypoint keeps the pod alive and re-runs
the mitigation every interval, for mitigations that must hold
continuously or can be undone mid-life (a package upgrade reinstalls a
vulnerable file, another tool flushes the nft ruleset). Scheduled roles
MUST be idempotent — a compliant host's re-run is zero-change.

Runs EVERY enabled mitigation (one failure does not block the others)
and reports each to stdout and the host journal. Failure handling is
per-mitigation: a ONCE-only failure exits non-zero immediately (the
CrashLoop backoff is the retry cadence); a SCHEDULED failure rides to
the next run and only CrashLoops after
MITIGATION_MAX_CONSECUTIVE_FAILURES (default 3) consecutive failures
— a transient failure in one mitigation must not kill the pod and with
it every other mitigation's schedule.

Parks (sleep) when all once-only mitigations succeed and nothing is
scheduled. On SIGTERM (pod deletion) it drains: the in-flight playbook
finishes, no new run starts, exit 0 — bounded by the pod's
terminationGracePeriodSeconds, after which kubelet SIGKILLs.

Wrapper playbooks live at /opt/ansible (baked into the image) and run
the role over the chroot connection to the host VM mounted at /host.

Environment:
  MITIGATIONS          the chart-rendered mitigation list (see above)
  MITIGATION_MAX_CONSECUTIVE_FAILURES
                       scheduled mitigations CrashLoop after this many
                       consecutive failures (default 3)
  ANSIBLE_WORKDIR      playbook directory (default /opt/ansible; tests
                       override)
  ANSIBLE_JOURNALD_IDENTIFIER  set by the chart to enable journald
                       logging via the callback plugin's writer
  NODE_NAME            node name (logs)
"""

import logging
import os
import signal
import subprocess
import sys
import threading
import time

WORKDIR = os.environ.get("ANSIBLE_WORKDIR", "/opt/ansible")
MITIGATIONS_ENV = os.environ.get("MITIGATIONS", "")
NODE_NAME = os.environ.get("NODE_NAME", "unknown")
try:
    MAX_CONSECUTIVE_FAILURES = int(
        os.environ.get("MITIGATION_MAX_CONSECUTIVE_FAILURES", "3")
    )
except ValueError:
    MAX_CONSECUTIVE_FAILURES = 3

# Event-driven mode flips: watch the node's mode label; a change
# forces the scheduled mitigations due immediately (no pod delete, no
# interval wait). All three env pieces come from the chart (auto
# mode); any missing piece disables the watcher (tests, SSH path).
MODE_WATCH = os.environ.get("NODE_MODE_WATCH", "") == "1"
NODE_MODE_LABEL = os.environ.get("NODE_MODE_LABEL", "")
# The k8s API the in-cluster config resolves to (empty = in-cluster).
K8S_API = os.environ.get("K8S_API", "")

# INFO+ to stdout with the [crusoe-mitigator] prefix and UTC timestamps
# (scheduled re-runs need inline stamps to correlate sweeps). stderr is
# deliberately NOT mirrored: kubectl merges a container's stdout and
# stderr into one stream, so a WARNING+ mirror would print every failure
# line twice in kubectl logs. The journal (JournalHandler below) is the
# second channel; stdout is the primary.
_STDOUT = logging.StreamHandler(sys.stdout)
_STDOUT.setFormatter(
    logging.Formatter(
        "%(asctime)s [crusoe-mitigator] %(message)s", "%Y-%m-%dT%H:%M:%SZ"
    )
)
_STDOUT.converter = time.gmtime


class JournalHandler(logging.Handler):
    """logging.Handler that writes records to the host's journald.

    One log call fans out to stdout/stderr AND the journal — no paired
    journal_event calls. Uses the repo's shared JournalWriter (native
    protocol over the datagram socket; availability probed once and
    cached, writes never raise). No-op when the chart has not set
    ANSIBLE_JOURNALD_IDENTIFIER (journaldLogging: false).

    Python level -> journald priority: ERROR+ -> err, WARNING ->
    warning, INFO -> info, DEBUG -> debug. The record's message goes
    bare (the pod log line owns the prefix/timestamp); NODE_NAME and
    the status ride as structured fields.
    """

    PRIORITIES = {
        logging.DEBUG: "debug",
        logging.INFO: "info",
        logging.WARNING: "warning",
        logging.ERROR: "err",
        logging.CRITICAL: "err",
    }

    def __init__(self, identifier, node_name):
        super().__init__()
        self._identifier = identifier
        self._node_name = node_name
        self._writer = None
        if identifier:
            sys.path.insert(0, "/opt/ansible/plugins")
            try:
                from module_utils.journald import JournalWriter

                # JOURNAL_SOCKET override: tests point at a fake socket.
                self._writer = JournalWriter(
                    os.environ.get(
                        "JOURNAL_SOCKET",
                        "/run/systemd/journal/socket",
                    )
                )
            except ImportError:
                pass

    def emit(self, record):
        if self._writer is None:
            return
        try:
            priority = self.PRIORITIES.get(record.levelno, "info")
            self._writer.write(
                self._identifier,
                priority,
                record.getMessage(),
                {
                    "ANSIBLE_STATUS": "POD_" + priority.upper(),
                    "POD_NODE": self._node_name,
                },
            )
        except Exception:
            # Logging must never break the caller; journald is the
            # secondary channel (stdout is primary).
            self.handleError(record)


log = logging.getLogger("crusoe-mitigator")
log.setLevel(logging.INFO)
log.addHandler(_STDOUT)
log.addHandler(
    JournalHandler(
        os.environ.get("ANSIBLE_JOURNALD_IDENTIFIER", ""),
        NODE_NAME,
    )
)


def parse_mitigations(raw):
    """Parse the MITIGATIONS list into (name, playbook, argv, interval).

    Skips blank lines; names must be unique (they key the schedule).
    """
    parsed = []
    seen = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 2:
            log.warning("skipping malformed line: %r", line)
            continue
        name, playbook = parts[0], parts[1]
        vars_argv = parts[2].split() if len(parts) > 2 else []
        interval = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
        if name in seen:
            log.warning("duplicate mitigation %r, keeping first", name)
            continue
        seen.add(name)
        parsed.append((name, playbook, vars_argv, interval))
    return parsed


def run_mitigation(name, playbook, vars_argv):
    """Run one wrapper playbook; report and return the exit code."""
    log.info("%s: running %s (%s)", NODE_NAME, name, playbook)
    argv = [
        "ansible-playbook",
        "-i",
        "inventory",
        playbook,
        *vars_argv,
    ]
    env = dict(os.environ, ANSIBLE_ROLES_PATH="/opt/ansible/roles")
    result = subprocess.run(argv, cwd=WORKDIR, env=env)
    if result.returncode == 0:
        log.info("%s: %s succeeded", NODE_NAME, name)
    else:
        log.error("%s: %s FAILED (rc=%s)", NODE_NAME, name, result.returncode)
    return result.returncode


def failure_is_fatal(interval, consecutive):
    """Whether a failure should CrashLoop the pod now.

    Once-only (interval 0): always — the CrashLoop backoff is the
    retry cadence. Scheduled: only after MAX_CONSECUTIVE_FAILURES
    consecutive failures — a transient failure must not kill the
    pod (and with it every other mitigation's schedule).
    """
    if interval <= 0:
        return True
    return consecutive >= MAX_CONSECUTIVE_FAILURES


def watch_event_mode(event, label):
    """The mode a k8s watch event implies, or None when the event
    carries no label state (BOOKMARK/DELETED/ERROR — treating those
    as changes would fire the re-run on every heartbeat).

    A single-resource watch (?watch=true on a named object) streams
    the CURRENT object as the first line — NO type field (found live:
    the watcher baselined on nothing and swallowed every change).
    That typeless object IS the baseline: return its label state so
    the first-line handling sets it."""
    if "type" not in event:
        # The initial object of a single-resource watch stream.
        labels = event.get("metadata", {}).get("labels", {})
        return labels.get(label, "")
    if event.get("type") not in ("ADDED", "MODIFIED"):
        return None
    labels = event.get("object", {}).get("metadata", {}).get("labels", {})
    return labels.get(label, "")


class _StopLoop(Exception):
    """Test-only: unwind main() at a chosen point."""


class NodeModeWatcher(threading.Thread):
    """Watches the node's mode label via the k8s watch API; a change
    sets the mode event so the scheduler re-runs the scheduled
    mitigations immediately. The watch stream reconnects on any
    error with a bounded backoff — a dropped connection must not
    kill the watcher (the interval re-run remains the floor)."""

    def __init__(self, node_name, label, on_change):
        super().__init__(daemon=True)
        self._node = node_name
        self._label = label
        self._on_change = on_change
        self._last_mode = None
        # Only the very first event ever baselines; reconnect ADDED
        # events carry the CURRENT label and must be compared (a change
        # during a connection gap would otherwise be silently swallowed
        # by the re-baseline — found live).
        self._ever_connected = False

    def start(self):
        super().start()

    def run(self):
        import json
        import ssl
        import urllib.request

        backoff = 1
        while True:
            try:
                # In-cluster config: the service account token + the
                # cluster CA the kubelet injects (urllib does not read
                # the CA bundle on its own — without it the watch
                # fails certificate verification).
                sa_dir = "/var/run/secrets/kubernetes.io/serviceaccount"
                token_path = f"{sa_dir}/token"
                ca_path = f"{sa_dir}/ca.crt"
                with open(token_path, encoding="utf-8") as fh:
                    token = fh.read().strip()
                ctx = ssl.create_default_context(cafile=ca_path)
                api = K8S_API or (
                    "https://"
                    + os.environ["KUBERNETES_SERVICE_HOST"]
                    + ":"
                    + os.environ["KUBERNETES_SERVICE_PORT"]
                )
                url = f"{api}/api/v1/nodes/{self._node}?watch=true&timeoutSeconds=300"
                req = urllib.request.Request(url)
                req.add_header("Authorization", f"Bearer {token}")
                with urllib.request.urlopen(req, timeout=310, context=ctx) as resp:
                    backoff = 1
                    for line in resp:
                        if not line.strip():
                            continue
                        event = json.loads(line)
                        mode = watch_event_mode(event, self._label)
                        if mode is None:
                            continue
                        if not self._ever_connected:
                            # The very first event ever (the stream's
                            # initial object) is the baseline; every
                            # later event — including a reconnect's
                            # fresh ADDED carrying the CURRENT label —
                            # is COMPARED, so a change during a
                            # connection gap still fires.
                            self._last_mode = mode
                            self._ever_connected = True
                            continue
                        if mode != self._last_mode:
                            self._last_mode = mode
                            log.info(
                                "%s: node mode label changed to %r — "
                                "forcing an immediate re-run",
                                NODE_NAME,
                                mode,
                            )
                            self._on_change()
            except Exception as exc:  # noqa: BLE001 — the watcher must survive
                log.warning(
                    "node mode watch failed (%s); reconnecting in %ss",
                    exc,
                    backoff,
                )
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)


def start_mode_watcher(_unused=None):
    """Start the watcher when fully configured; returns whether it
    started. The mode event is module state the scheduler waits on."""
    if not (MODE_WATCH and NODE_MODE_LABEL and NODE_NAME != "unknown"):
        return False
    NodeModeWatcher(NODE_NAME, NODE_MODE_LABEL, _mode_event.set).start()
    return True


# The mode-change event: set by the watcher, waited on by the
# scheduler's sleep (event-driven wake; the interval remains the
# floor for missed events).
_mode_event = threading.Event()


def _fire_soon():
    """Test hook: fire the mode event from the fake watcher."""
    _mode_event.set()


def sleep_slices(seconds, should_wake):
    """Sleep `seconds` in <=1s slices, returning early once
    should_wake() is true. PEP 475 restarts time.sleep after a signal
    handler runs, so one long sleep would not notice the drain flag
    until it completed — well past the pod's grace period."""
    deadline = time.monotonic() + seconds
    while True:
        if should_wake():
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(1.0, remaining))


def main():
    mitigations = parse_mitigations(MITIGATIONS_ENV)
    if not mitigations:
        log.error("no mitigations enabled — check the chart's mitigations list")
        return 1

    log.info("%s: starting", NODE_NAME)

    # Event-driven mode flips: the watcher (when configured) sets the
    # mode event on a label change; the scheduler treats it as "all
    # scheduled mitigations due NOW".
    start_mode_watcher()

    # name -> monotonic time of last successful run.
    last_run = {}
    # name -> consecutive-failure count (scheduled mitigations only).
    consecutive_failures = {}
    scheduled = [m for m in mitigations if m[3] > 0]
    draining = False

    def request_drain(signum, frame):
        nonlocal draining
        draining = True
        log.info(
            "%s: SIGTERM — draining; in-flight run finishes, no new run starts",
            NODE_NAME,
        )

    signal.signal(signal.SIGTERM, request_drain)

    while True:
        now = time.monotonic()
        failures = []
        for name, playbook, vars_argv, interval in mitigations:
            if draining:
                break
            last = last_run.get(name)
            due = last is None or (interval > 0 and now - last >= interval)
            # A mode-change event forces every scheduled mitigation
            # due immediately — the label flip converges in seconds.
            if _mode_event.is_set() and interval > 0:
                due = True
            if not due:
                continue
            if run_mitigation(name, playbook, vars_argv) == 0:
                last_run[name] = time.monotonic()
                consecutive_failures[name] = 0
            else:
                consecutive_failures[name] = consecutive_failures.get(name, 0) + 1
                failures.append(name)
        # Clear the mode event ONLY when a scheduled mitigation consumed
        # it this pass — a config with no scheduled mitigations (all
        # once-only) leaves the event set; the next scheduled entry
        # added by a chart upgrade picks it up instead of losing the
        # flip (the bot review's #1: the unconditional clear swallowed
        # mode events in once-only-only configs).
        if scheduled:
            _mode_event.clear()

        if draining:
            log.info("%s: drained; exiting 0", NODE_NAME)
            return 0

        for name in failures:
            interval = next(m[3] for m in mitigations if m[0] == name)
            if failure_is_fatal(interval, consecutive_failures[name]):
                log.error(
                    "%s: %s FAILED %d consecutive times; exiting to CrashLoop",
                    NODE_NAME,
                    name,
                    consecutive_failures[name],
                )
                return 1
            log.warning(
                "%s: %s failed (%d consecutive; CrashLoop at %d) — "
                "retrying at next scheduled run",
                NODE_NAME,
                name,
                consecutive_failures[name],
                MAX_CONSECUTIVE_FAILURES,
            )

        if not scheduled:
            log.info("%s: all mitigations succeeded; parking", NODE_NAME)
            # Park until SIGTERM (the drain flag ends the sliced sleep).
            sleep_slices(10**9, lambda: draining)
            log.info("%s: drained; exiting 0", NODE_NAME)
            return 0

        # Sleep until the earliest next due time among scheduled runs,
        # waking early on a mode-change event (event-driven flips).
        now = time.monotonic()
        next_due = min(
            last_run.get(name, now) + interval for name, _, _, interval in scheduled
        )
        delay = max(0.0, next_due - now)
        sleep_slices(delay, lambda: draining or _mode_event.is_set())


if __name__ == "__main__":
    sys.exit(main())
