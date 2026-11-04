# Ansible image for crusoe-cs-ansible: the controller AND the
# crusoe-distrust-emudhra-ca DaemonSet payload in one.
#
# Controller: runs playbooks against a LOCAL target (connection: local,
# or the chroot connection plugin against a mounted rootfs) — no dynamic
# inventory, no ssh transport, no crusoe CLI, no helm/kubectl. Ships
# ansible-core + the kubernetes client + the collections from
# requirements.yml (community.general provides the chroot plugin).
# Published to ghcr.io/crusoecloud/crusoe-cs/ansible.
#
# DaemonSet payload: the emudhra_ca role + wrapper playbook + one-host
# inventory are baked at /opt/ansible (see the COPY below); the
# crusoe-distrust-emudhra-ca chart runs them over chroot against the
# host VM. The pod's securityContext (privileged, runAsUser 0)
# overrides this image's non-root USER — chroot requires root.
#
# Trust-store gate: the eMudhra compromise advisory (see
# roles/emudhra_ca/vars/main.yml) means a controller that TRUSTS the
# distrusted roots would silently accept chains signed by them. The build
# fails unless the final image's system bundle AND python certifi are free
# of the pinned fingerprints, and a live TLS check proves the system store
# actually rejects the advisory's canary sites while normal HTTPS works.
# Base pinned by digest (never a floating tag — a rebuild could
# silently change the toolchain under the trust gate). Override with
# --build-arg BASE=<digest-pinned ref> if you must, deliberately.
ARG BASE=python:3.14-alpine@sha256:601e99e090cb08c2784a42395487709500bc39930307fe72f3f11a8f3c430762
FROM ${BASE}

# Toolchain: bash (scripts assume it), curl (trust-gate HTTPS checks),
# openssl (trust-gate fingerprint scan), ca-certificates (TLS).
# nftables + util-linux: pod-native delivery — the mitigator pod runs
# the image's own nft via netlink against the shared host netns (no
# chroot into host userspace; works on minimal hosts like COS) and the
# reconciler's nsenter comes from util-linux.
# Version-pinned (the security report flags unpinned apk adds):
# reproducible builds, no surprise upstream changes.
RUN apk add --no-cache \
      bash~5 \
      ca-certificates=20261020-r0 \
      curl~8 \
      openssl~3 \
      nftables~1 \
      util-linux~2

# Python dependencies — installed from uv.lock: the repo's single
# source of truth for Python versions. `uv sync --frozen` installs
# exactly the locked runtime deps (no dev group, no floating
# resolution) into /opt/venv. Bump a version in pyproject.toml,
# `uv lock`, and the image follows — the lock COPY invalidates this
# layer and the trust gate downstream re-runs against the new pins.
# uv is COPY'd from its distro image (single static binary, no pip
# install at build time; digest-pinned for reproducibility — the
# INDEX digest, so each build platform pulls its own arch's binary).
COPY --from=ghcr.io/astral-sh/uv@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490 /uv /uvx /usr/local/bin/
COPY pyproject.toml uv.lock /tmp/deps/
# UV_COMPILE_BYTECODE=1: uv sync skips bytecode compilation by
# default — the image runs as USER runner, which cannot write
# __pycache__ under /opt/venv, so every ansible/kubernetes import
# would recompile in memory on EVERY start (kubernetes's generated
# client tree is thousands of modules; measured 0.82s per import
# without bytecode). Compile at build time instead (uv's Docker
# guide recommendation).
RUN UV_COMPILE_BYTECODE=1 uv venv /opt/venv \
    && UV_COMPILE_BYTECODE=1 UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --no-dev --project /tmp/deps \
    && rm -rf /tmp/deps
ENV PATH="/opt/venv/bin:${PATH}"

# Ansible collections — same pins as requirements.yml.
COPY requirements.yml /tmp/requirements.yml
# --no-cache: ansible-galaxy's shared response cache corrupts under
# concurrent runs ("Missing expected 'results' in ansible-galaxy
# cache" — hit twice in CI when one multi-arch build ran the layer
# per platform in parallel). The per-arch build jobs no longer share
# a builder, but the flag stays: it's the upstream-recommended
# workaround and the layer is cached by BuildKit anyway.
RUN ansible-galaxy collection install --no-cache -r /tmp/requirements.yml \
      -p /usr/share/ansible/collections \
    && rm /tmp/requirements.yml

# Non-root runtime user for controller use; playbooks run against
# local/chroot targets. The DaemonSet pod overrides this via its
# securityContext (chroot requires root).
RUN addgroup -S runner && adduser -S -G runner runner
USER runner

ENV HOME=/home/runner \
    ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections \
    LANG=C.UTF-8

# ---------------------------------------------------------------------------
# Trust-store gate (build-time, fails the build):
#   1. No distrusted eMudhra root (pinned SHA-256 fingerprints from
#      roles/emudhra_ca/vars/main.yml) in the system CA bundle or in any
#      python certifi bundle.
#   2. Functional: HTTPS to a well-known host verifies, and the advisory's
#      canary sites (chained to the distrusted roots) FAIL verification.
# ---------------------------------------------------------------------------
RUN set -eu; \
    bad_fps="86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B \
             D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4 \
             7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D \
             F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5"; \
    scan_bundle() { \
      bundle="$1"; \
      [ -f "$bundle" ] || return 0; \
      d="$(mktemp -d)"; \
      awk -v d="$d" '/BEGIN CERTIFICATE/{f=sprintf("%s/c.%d.pem",d,++i)} f{print > f} /END CERTIFICATE/{close(f); f=""}' "$bundle"; \
      for pem in "$d"/*.pem; do \
        [ -f "$pem" ] || continue; \
        fp="$(openssl x509 -in "$pem" -noout -fingerprint -sha256 2>/dev/null | tr -d ':' | awk -F= '{print toupper($2)}')"; \
        for bad in $bad_fps; do \
          [ "$fp" = "$bad" ] && { echo "DISTRUSTED ROOT IN $bundle: $bad" >&2; exit 1; }; \
        done; \
      done; \
      rm -rf "$d"; \
    }; \
    scan_bundle /etc/ssl/certs/ca-certificates.crt; \
    for pem in /usr/lib/python3*/site-packages/certifi/cacert.pem \
               /usr/local/lib/python3*/site-packages/certifi/cacert.pem \
               /opt/venv/lib/python3*/site-packages/certifi/cacert.pem; do \
      scan_bundle "$pem"; \
    done; \
    echo "trust-store scan: clean"; \
    curl -fsS --max-time 30 -o /dev/null https://pypi.org/simple/ \
      || { echo "HTTPS to pypi.org failed: system trust store broken" >&2; exit 1; }; \
    for site in dv-g3b-emudhra.we-have-a-problem.com \
                dv-g3b-aaa-emudhra.we-have-a-problem.com; do \
      rc=0; \
      curl -fsS -o /dev/null --max-time 20 "https://${site}/" 2>/dev/null || rc=$?; \
      if [ "$rc" -eq 0 ]; then \
        echo "CANARY SITE VERIFIED — distrusted root still trusted: ${site}" >&2; \
        exit 1; \
      elif [ "$rc" -ne 60 ]; then \
        echo "CANARY CHECK INCONCLUSIVE (curl rc=${rc}) — network error, not TLS rejection: ${site}" >&2; \
        exit 1; \
      fi; \
    done; \
    echo "TLS canary check: distrusted chains rejected"

# Smoke: ansible and the collections must exist and run.
RUN set -eu; \
    ansible --version | head -1; \
    ansible-galaxy collection list | grep -q kubernetes.core

# Bake the DaemonSet payload GENERICALLY: every role, every playbook,
# every wrapper — the image is a point-in-time snapshot of the repo's
# remediation catalog. WHICH remedations run is pure chart config
# (values.yaml's mitigations list names playbooks by path); adding a
# remediation to the repo needs NO Dockerfile edit, only a rebuild.
# These COPYs sit AFTER the trust gate + smoke layers so they don't
# invalidate them: the gate reads only the trust store (apk
# ca-certificates + pip certifi), which the payload COPYs don't touch
# — a role/playbook edit re-caches everything above this line.
COPY roles/ /opt/ansible/roles/
COPY playbooks/ /opt/ansible/playbooks/
COPY images/ansible/*.yml images/ansible/inventory /opt/ansible/
# Executable payloads: any role file under files/sbin/ lands in PATH
# (sidecar commands like the pod-netns reconciler reference these
# paths). The explicit COPY keeps the mode without a build-arg dance.
COPY --chmod=0755 roles/cve_2026_98432/files/cve-2026-98432-netns-reconcile.py /usr/local/sbin/cve-2026-98432-netns-reconcile.py
# Generic mitigation entrypoint for the crusoe-mitigator chart: parses
# the chart-rendered MITIGATIONS list, runs each playbook, parks or
# CrashLoops. Baked at the path the chart's command expects.
COPY --chmod=0755 images/ansible/mitigate.py /usr/local/sbin/mitigate.py
# Generic textfile metrics file-server (chart metrics-server sidecar):
# serves every *.prom in the chart hostPath on :19698 for vmagent /
# managed-collection scraping.
COPY --chmod=0755 images/ansible/serve-metrics.py /usr/local/sbin/serve-metrics.py
COPY plugins/ /opt/ansible/plugins/

WORKDIR /work
# The security report flags the missing HEALTHCHECK. The entrypoint
# parks (sleep) after the mitigations run; the healthcheck proves the
# supervisor is alive (a hung entrypoint fails it).
HEALTHCHECK --interval=60s --timeout=10s --start-period=90s \
  CMD pgrep -f mitigate.py >/dev/null || exit 1
ENTRYPOINT ["ansible-playbook"]
