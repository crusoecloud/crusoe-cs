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
RUN apk add --no-cache \
      bash \
      ca-certificates \
      curl \
      openssl

# Python dependencies: ansible-core (not the full `ansible` package — that
# bundles ~100 collections and ~700MB; the component's collections are
# installed explicitly below) + the kubernetes client.
RUN pip install --no-cache-dir "ansible-core>=2.17" "kubernetes"

# Ansible collections — same pins as requirements.yml.
COPY requirements.yml /tmp/requirements.yml
RUN ansible-galaxy collection install -r /tmp/requirements.yml \
      -p /usr/share/ansible/collections \
    && rm /tmp/requirements.yml

# Bake the DaemonSet payload: role + wrapper + inventory + the
# callback plugins (journald logging) at /opt/ansible.
COPY roles/emudhra_ca/ /opt/ansible/roles/emudhra_ca/
COPY images/ansible/wrapper.yml images/ansible/inventory /opt/ansible/
COPY plugins/ /opt/ansible/plugins/

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
               /usr/local/lib/python3*/site-packages/certifi/cacert.pem; do \
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

WORKDIR /work
ENTRYPOINT ["ansible-playbook"]
