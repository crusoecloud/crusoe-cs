#!/bin/bash
# Host-side instrumentation for capturing the NFS mount failure path
# Run on a CMK worker VM that reproduces the issue.
# NFS_HOSTNAME (default: nfs.crusoecloudcompute.com) can be set in the
# environment to target a different NFS endpoint.
# This sets up traces, prints a prompt, then waits for you to trigger your repro
# via your normal CSI-driven workload (pod deploy, DaemonSet scale-up, etc.)
set -uo pipefail

NFS_HOSTNAME="${NFS_HOSTNAME:-nfs.crusoecloudcompute.com}"
EVIDENCE_DIR="/tmp/csi-nfs-trace-$(date +%Y%m%dT%H%M%SZ)"
mkdir -p "$EVIDENCE_DIR"
echo ">>> Evidence will be collected in $EVIDENCE_DIR"

# =========================================================================
# 1. Wrap /sbin/key.dns_resolver with strace
# =========================================================================
echo ">>> Installing strace wrapper for /sbin/key.dns_resolver"
sudo cp /sbin/key.dns_resolver /sbin/key.dns_resolver.real
sudo tee /sbin/key.dns_resolver >/dev/null <<EOF
#!/bin/bash
exec strace -f -tt -s 512 \
  -o "$EVIDENCE_DIR/key.dns_resolver.\$\$.strace" \
  -e 'trace=network,openat,read,write,connect,sendto,recvmsg,recvfrom,exit,exit_group' \
  /sbin/key.dns_resolver.real "\$@"
EOF
sudo chmod +x /sbin/key.dns_resolver

# Cleanup trap — restores original binary even on Ctrl-C / SIGTERM
trap '
  echo ""
  echo ">>> Restoring /sbin/key.dns_resolver"
  sudo mv -f /sbin/key.dns_resolver.real /sbin/key.dns_resolver 2>/dev/null
  sudo kill $TCPDUMP_PID $BPF_PID 2>/dev/null
' EXIT INT TERM

# =========================================================================
# 2. Start tcpdump on port 53
# =========================================================================
echo ">>> Starting tcpdump on port 53"
sudo tcpdump -i any -n -s 0 -w "$EVIDENCE_DIR/dns.pcap" \
  '(port 53) or (host 8.8.8.8) or (host 8.8.4.4)' 2>/dev/null &
TCPDUMP_PID=$!

# =========================================================================
# 3. Start bpftrace tracking upcall execve calls
# =========================================================================
echo ">>> Starting bpftrace tracking upcall handlers"
sudo bpftrace -e '
  tracepoint:syscalls:sys_enter_execve
  {
    printf("[%d.%06d] PID=%d PPID=%d cmd=%s\n",
           nsecs / 1000000000, (nsecs % 1000000000)/1000,
           pid, curtask->real_parent->pid,
           str(args->filename));
  }
' 2>&1 | grep --line-buffered -E "request-key|key\.dns_resolver|mount\.nfs|/bin/mount" \
  > "$EVIDENCE_DIR/upcall-execve.log" &
BPF_PID=$!

# =========================================================================
# 4. Snapshot baseline state
# =========================================================================
echo ">>> Capturing baseline state"
sudo cat /proc/keys > "$EVIDENCE_DIR/proc-keys-before.txt"
{
  echo "=== /etc/resolv.conf ==="
  cat /etc/resolv.conf
  echo
  echo "=== resolvectl status ==="
  sudo resolvectl status
  echo
  echo "=== getent hosts $NFS_HOSTNAME ==="
  getent hosts "$NFS_HOSTNAME"
  echo
  echo "=== dig A ==="
  dig A "$NFS_HOSTNAME" +short
  echo "=== dig AAAA ==="
  dig AAAA "$NFS_HOSTNAME" +short
  echo "=== hostname / uname ==="
  hostname; uname -a
} > "$EVIDENCE_DIR/resolver-state-before.txt" 2>&1

sleep 2

# =========================================================================
# 5. Wait for the user to trigger their CSI-driven repro
# =========================================================================
cat <<MSG

==========================================================================
Instrumentation is now LIVE on this VM ($(hostname)).
Capturing:
  - strace of every /sbin/key.dns_resolver invocation
  - tcpdump of all DNS traffic (port 53 + 8.8.8.8/8.8.4.4)
  - bpftrace of relevant execve calls (kubelet → mount → upcall handlers)

Now trigger your normal CSI-driven repro from your test cluster:
  - kubectl rollout restart your test DaemonSet/Deployment, OR
  - scale up/down test pods, OR
  - kubectl delete pods to force re-mount

Waiting for "Required key not available" in kubelet journal (Ctrl-C to abort)...
==========================================================================
MSG

FLAG_FILE="$EVIDENCE_DIR/.detected"

# Background watcher — writes flag file on first match
(
  sudo journalctl -u kubelet -f -n 0 --output=cat 2>/dev/null \
    | grep --line-buffered -i "required key not available" \
    | while read -r MATCH_LINE; do
        printf "\n>>> Auto-detected failure: %s\n" "$MATCH_LINE"
        printf ">>> Capturing for 30 more seconds...\n"
        sleep 30
        touch "$FLAG_FILE"
        break
      done
) &
WATCHER_PID=$!

MAX_WAIT=600
WAIT_START=$SECONDS
echo "(or press Enter to stop capturing manually; auto-timeout in ${MAX_WAIT}s)"
# Poll every second for the flag file; exit on manual Enter or timeout
while [[ ! -f "$FLAG_FILE" ]]; do
  if (( SECONDS - WAIT_START >= MAX_WAIT )); then
    echo ">>> Timed out after ${MAX_WAIT}s without detecting failure — stopping capture" >&2
    break
  fi
  IFS= read -r -t 1 -s 2>/dev/null
  rc=$?
  if [[ $rc -eq 0 ]]; then
    echo ">>> Stopping on manual request"
    break
  elif [[ $rc -le 128 ]]; then
    # EOF on non-interactive stdin — sleep to avoid busy loop
    sleep 1
  fi
  # rc > 128: read timed out after 1s — no extra sleep needed
done
kill "$WATCHER_PID" 2>/dev/null

# =========================================================================
# 6. Snapshot final state and capture CSI/kubelet logs
# =========================================================================
echo ">>> Capturing final state"

sudo cat /proc/keys > "$EVIDENCE_DIR/proc-keys-after.txt"

{
  echo "=== /etc/resolv.conf ==="
  cat /etc/resolv.conf
  echo
  echo "=== resolvectl status ==="
  sudo resolvectl status
  echo
  echo "=== getent hosts ==="
  getent hosts "$NFS_HOSTNAME"
} > "$EVIDENCE_DIR/resolver-state-after.txt" 2>&1

# CSI driver pod logs from THIS node (best-effort)
echo ">>> Trying to capture CSI driver logs from this node"
if command -v kubectl >/dev/null 2>&1; then
  THIS_NODE=$(hostname)
  CSI_POD=$(kubectl -n crusoe-system get pods -o wide --field-selector spec.nodeName=$THIS_NODE \
              -l app=crusoe-csi-driver-fs --no-headers 2>/dev/null | awk '{print $1}' | head -1)
  if [[ -n "$CSI_POD" ]]; then
    kubectl -n crusoe-system logs "$CSI_POD" -c crusoe-csi-driver --since=20m \
      > "$EVIDENCE_DIR/csi-node-driver.log" 2>&1
    echo ">>> Captured CSI logs from pod $CSI_POD"
  else
    echo "(no CSI pod found on this node — capture manually if needed)"
  fi
else
  echo "(kubectl not available on this VM — capture CSI driver logs from your kubeconfig context manually)"
fi

# Kubelet journal for the trigger window
echo ">>> Capturing kubelet journal"
sudo journalctl -u kubelet --since "20 min ago" --no-pager \
  > "$EVIDENCE_DIR/kubelet.log" 2>&1

# =========================================================================
# 7. Bundle and summarize
# =========================================================================
sudo kill $TCPDUMP_PID $BPF_PID 2>/dev/null
sleep 1

echo
echo "=========================================="
TRACE_COUNT=$(ls "$EVIDENCE_DIR"/key.dns_resolver.*.strace 2>/dev/null | wc -l)
echo "key.dns_resolver invocations captured: $TRACE_COUNT"
echo "  (0 = kernel never spawned the upcall — would mean a totally different failure mode)"
echo
ENOKEY_HITS=$(grep -c -i "required key not available\|enokey" "$EVIDENCE_DIR/kubelet.log" 2>/dev/null || echo 0)
echo "ENOKEY occurrences in kubelet log: $ENOKEY_HITS"
echo
sudo chown -R "$(id -un):$(id -gn)" "$EVIDENCE_DIR"
tar czf "$EVIDENCE_DIR.tar.gz" -C "$(dirname "$EVIDENCE_DIR")" "$(basename "$EVIDENCE_DIR")"
echo "Bundle: $EVIDENCE_DIR.tar.gz"
echo "=========================================="
