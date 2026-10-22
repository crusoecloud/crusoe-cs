#!/usr/bin/env bash
# eMudhra SCA e2e harness — drives playbooks against Docker containers.
#
# Usage: tests/e2e/emudhra-ca/run.sh <scenario> [--images <csv>]
#   Scenarios: smoke | vars | detect | remediate | fallback | wrapper | clean | mixed | unsupported | extended | all
#   Default images: ubuntu:22.04,ubuntu:24.04,rockylinux:9,debian:12,almalinux:9
#
#   Rocky 8 is NOT in the default matrix: its repos ship no dnf bindings for
#   any Python new enough for ansible-core 2.20 modules (verified against
#   Rocky 8's actual repos), so the package module cannot run there. The
#   role's logic is family-generic and proven on EL9; real EL8 hosts that
#   meet the interpreter pre-flight work the same way. Add it back with
#   --images if a compatible controller/ansible-core combination appears.
#
# Env:
#   EMUDHRA_E2E_JOBS      concurrent scenarios for `all` (default 3; ~1GiB docker-VM
#                         memory per job — e.g. colima start --cpu 4 --memory 4)
#   EMUDHRA_E2E_CONNECTIVITY 0|1 (default 0) — 1 enables the live s_client check in wrapper scenario
#
# Execution: ansible-playbook runs from the repo .venv (community.docker connection
# plugin) against sibling containers — no controller container needed.
#
# Exit 0 = pass, non-zero = fail. Containers are named emudhra-e2e-<scenario>-<n>
# and torn down on exit via trap.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
E2E_DIR="${REPO_ROOT}/tests/e2e/emudhra-ca"
INVENTORY=""  # set per-scenario by write_inventory (parallel-safe)
ANSIBLE="${REPO_ROOT}/.venv/bin/ansible-playbook"
DEFAULT_IMAGES="ubuntu:22.04,ubuntu:24.04,rockylinux:9,debian:12,almalinux:9"
CONTAINERS=()

log() { echo "[e2e] $*"; }
die() { echo "[e2e] FAIL: $*" >&2; exit 1; }

# Map a distro tag to the e2e target image. Ubuntu/Alpine need python3 baked
# in (Ansible modules require an interpreter); Rocky ships it already.
# Derived images are built once and cached by Docker.
resolve_image() {
  local image="$1"
  case "$image" in
    ubuntu:*|debian:*)
      docker build -q -t "emudhra-e2e-${image//[:\/]/-}" \
        --build-arg BASE="$image" -f "${E2E_DIR}/images/Dockerfile.debian" "${E2E_DIR}/images" >/dev/null
      echo "emudhra-e2e-${image//[:\/]/-}"
      ;;
    rockylinux:*|almalinux:*)
      # The family recipe installs python39 alongside the system python when
      # the stock interpreter is too old for ansible-core 2.20 modules.
      docker build -q -t "emudhra-e2e-${image//[:\/]/-}" \
        --build-arg BASE="$image" -f "${E2E_DIR}/images/Dockerfile.redhat" "${E2E_DIR}/images" >/dev/null
      echo "emudhra-e2e-${image//[:\/]/-}"
      ;;
    alpine:*)
      docker build -q -t "emudhra-e2e-${image//[:\/]/-}" \
        --build-arg BASE="$image" -f "${E2E_DIR}/images/Dockerfile.alpine" "${E2E_DIR}/images" >/dev/null
      echo "emudhra-e2e-${image//[:\/]/-}"
      ;;
    *) echo "$image" ;;
  esac
}

cleanup_trap() {
  # Kill any scenario children still running (parallel mode) so their
  # containers don't linger; then sweep ALL e2e containers — in parallel
  # mode each child tracks its own containers, and a killed child's trap
  # never runs, so the parent must sweep by name prefix.
  local c
  if [[ -n "${ALL_PIDS:-}" ]]; then
    # shellcheck disable=SC2086 # ALL_PIDS is a deliberate space-separated pid list
    kill ${ALL_PIDS} 2>/dev/null || true
    # shellcheck disable=SC2086
    wait ${ALL_PIDS} 2>/dev/null || true
  fi
  for c in "${CONTAINERS[@]:-}"; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  docker ps -aq --filter name=emudhra-e2e- | xargs -r docker rm -f >/dev/null 2>&1 || true
  [[ -n "${INVENTORY:-}" ]] && rm -f "${INVENTORY}"
  rm -f "${E2E_DIR}"/.inventory-*.ini "${E2E_DIR}"/.run-*.log
}
trap cleanup_trap EXIT

up_container() {
  local name="$1" image="$2"
  image="$(resolve_image "$image")"
  # Defensive: remove any leftover with this name (prior crashed run).
  docker rm -f "$name" >/dev/null 2>&1 || true
  log "starting ${name} (${image})"
  docker run -d --name "$name" "$image" sleep infinity >/dev/null
  CONTAINERS+=("$name")
}

# Verify the target image has python3 (Ansible modules need it). Derived
# e2e images bake it in; this check makes a missing interpreter a loud,
# immediate failure instead of a confusing module error mid-play.
bootstrap_python() {
  local name="$1"
  docker exec "$name" sh -c 'command -v python3' >/dev/null 2>&1 \
    || die "${name}: no python3 in target image — bake it into the e2e image (see tests/e2e/emudhra-ca/images/)"
  log "${name}: python3 present"
}

# Detect the newest python3 (>=3.7) available in a container, for
# ansible_python_interpreter. Prefers the distro python3 when new enough;
# falls back to versioned interpreters (e.g. Rocky 8's python3.9) WITHOUT
# modifying the container's system python.
detect_python() {
  local name="$1"
  docker exec "$name" sh -c '
    for py in /usr/bin/python3 /usr/bin/python3.13 /usr/bin/python3.12 \
              /usr/bin/python3.11 /usr/bin/python3.10 /usr/bin/python3.9 \
              /usr/libexec/platform-python; do
      [ -x "$py" ] || continue
      if "$py" -c "import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)" 2>/dev/null; then
        echo "$py"
        exit 0
      fi
    done
    exit 1
  ' 2>/dev/null
}

write_inventory() {
  # Per-scenario inventory: scenarios can run in parallel without clobbering
  # each other's inventory file. The scenario name is derived from the
  # calling function (scenario_<name>), so callers pass ONLY host names.
  local caller="${FUNCNAME[1]#scenario_}"
  INVENTORY="${E2E_DIR}/.inventory-${caller}.ini"
  : > "${INVENTORY}"
  local name py
  for name in "$@"; do
    py="$(detect_python "$name")" \
      || die "${name}: no python3 >= 3.7 found — bake one into the e2e image (see tests/e2e/emudhra-ca/images/)"
    # HOME is often unset in minimal containers; the docker connection plugin
    # needs it for the remote tmp dir, so pin both explicitly.
    echo "${name} ansible_connection=community.docker.docker ansible_user=root ansible_python_interpreter=${py} ansible_remote_tmp=/tmp/ansible home=/root" >> "${INVENTORY}"
  done
  log "inventory written: $*"
}

# Run ansible-playbook from the local venv against the ephemeral inventory.
# Captures output to the caller; does NOT abort on playbook failure so
# scenarios can assert on the output (use run_playbook_ok to require success).
# ANSIBLE_CONFIG is pinned to the worktree's ansible.cfg so role resolution
# works regardless of the caller's CWD.
run_playbook() {
  export ANSIBLE_CACHE_PLUGIN=memory
  export ANSIBLE_CONFIG="${REPO_ROOT}/ansible.cfg"
  "${ANSIBLE}" -i "${INVENTORY}" "$@" 2>&1
}

run_playbook_ok() {
  local out
  out="$(run_playbook "$@")" || die "playbook failed: $*"
  echo "$out"
}

# Ad-hoc ansible command (smoke test uses this).
run_ansible() {
  export ANSIBLE_CACHE_PLUGIN=memory
  export ANSIBLE_CONFIG="${REPO_ROOT}/ansible.cfg"
  "${REPO_ROOT}/.venv/bin/ansible" -i "${INVENTORY}" "$@"
}

down_container() {
  docker rm -f "$1" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Distrusted-root data — loaded from the role's own vars/main.yml so the
# harness and the role can never drift. Provides:
#   BAD_ROOT_FPS[]   SHA-256 fingerprints (uppercase)
#   BAD_ROOT_CERTS[] cert filenames in roles/emudhra_ca/files/certs/
# ---------------------------------------------------------------------------
load_bad_roots() {
  BAD_ROOT_FPS=()
  BAD_ROOT_CERTS=()
  local yaml="${REPO_ROOT}/roles/emudhra_ca/vars/main.yml"
  local parsed
  parsed="$(python3 -c "
import yaml, sys
with open('${yaml}') as f:
    data = yaml.safe_load(f)
for root in data['emudhra_ca_bad_roots']:
    print(root['sha256'])
    print(root['cert'])
" 2>/dev/null)" || die "load_bad_roots: failed to parse ${yaml}"
  [[ -n "$parsed" ]] || die "load_bad_roots: no roots found in ${yaml}"
  local line kind=0
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    if [[ $kind -eq 0 ]]; then
      BAD_ROOT_FPS+=("$line")
      kind=1
    else
      BAD_ROOT_CERTS+=("$line")
      kind=0
    fi
  done <<<"$parsed"
  [[ ${#BAD_ROOT_FPS[@]} -eq ${#BAD_ROOT_CERTS[@]} ]] \
    || die "load_bad_roots: fingerprint/cert count mismatch"
  log "loaded ${#BAD_ROOT_FPS[@]} distrusted roots from role vars"
}

# Assert NO distrusted root remains in the container's active bundle.
# Every remediation assertion must use this — single-root checks are how
# the AAA miss slipped through.
assert_all_roots_absent() {
  local name="$1"
  local i
  for i in "${!BAD_ROOT_FPS[@]}"; do
    bundle_has_fingerprint "${name}" "${BAD_ROOT_FPS[$i]}" absent \
      || die "${name}: distrusted root ${BAD_ROOT_CERTS[$i]} still in bundle"
  done
}

# Assert a specific root IS in the bundle (injection sanity).
assert_root_present() {
  local name="$1" idx="$2"
  bundle_has_fingerprint "${name}" "${BAD_ROOT_FPS[$idx]}" present \
    || die "${name}: expected ${BAD_ROOT_CERTS[$idx]} in bundle after injection"
}

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

scenario_smoke() {
  local name="emudhra-e2e-smoke-1"
  local image
  image="$(echo "${1:-ubuntu:24.04}" | cut -d, -f1)"
  up_container "$name" "$image"
  bootstrap_python "$name"
  write_inventory "$name"
  local out
  out="$(run_ansible all -m setup -a 'filter=ansible_os_family')"
  echo "$out" | grep -q '"ansible_os_family": "Debian"' \
    || die "smoke: expected ansible_os_family Debian, got: ${out}"
  log "smoke: PASS"
}

# Fixture: inject a distrusted root the way an admin would (manual CA dir +
# trust refresh). Uses the role's own shipped certs. Trust-store tooling is
# baked into the e2e images (see tests/e2e/emudhra-ca/images/).
inject_root() {
  local name="$1" cert="$2"
  local cert_path="${REPO_ROOT}/roles/emudhra_ca/files/certs/${cert}"
  if docker exec "$name" sh -c 'command -v update-ca-certificates' >/dev/null 2>&1; then
    docker exec "$name" mkdir -p /usr/local/share/ca-certificates
    docker cp "$cert_path" "${name}:/usr/local/share/ca-certificates/${cert}" >/dev/null
    docker exec "$name" update-ca-certificates >/dev/null 2>&1
  else
    docker exec "$name" mkdir -p /etc/pki/ca-trust/source/anchors
    docker cp "$cert_path" "${name}:/etc/pki/ca-trust/source/anchors/${cert}" >/dev/null
    docker exec "$name" update-ca-trust >/dev/null 2>&1
  fi
}

# Fixture: construct a clean host by blocklisting every distrusted root the
# bundle still ships (Rocky pre-fix ships BOTH emSign ECC and Comodo AAA).
# Resolves the distrust dir at runtime: newer p11-kit uses blocklist/, older
# (Rocky 8 / EL8) uses blacklist/.
fixture_clean_redhat() {
  local name="$1"
  local bl_dir
  bl_dir="$(docker exec "$name" sh -c \
    'for d in /etc/pki/ca-trust/source/blocklist /etc/pki/ca-trust/source/blacklist; do [ -d "$d" ] && { echo "$d"; exit 0; }; done; mkdir -p /etc/pki/ca-trust/source/blocklist && echo /etc/pki/ca-trust/source/blocklist')"
  local cert
  for cert in "${BAD_ROOT_CERTS[@]}"; do
    docker cp "${REPO_ROOT}/roles/emudhra_ca/files/certs/${cert}" \
      "${name}:${bl_dir}/${cert}" >/dev/null
  done
  # Tolerant: a failure here leaves the root in the bundle, which the caller's
  # absence assertion reports with context — better than a silent set -e death.
  docker exec "$name" update-ca-trust >/dev/null 2>&1 || true
}

# Fixture: construct a clean Debian host by upgrading ca-certificates (the
# fixed package is in released Ubuntu repos).
fixture_clean_debian() {
  local name="$1"
  # Tolerant: a failure here leaves the root in place, which the caller's
  # absence assertion reports with context — better than a silent set -e death.
  docker exec "$name" sh -c 'apt-get update -qq && apt-get install -y -qq ca-certificates' >/dev/null 2>&1 || true
}

# Fixture: make the EXTENDED stores clean too. Upgrading ca-certificates only
# fixes the system bundle — Debian-family images ship python3-certifi with its
# own cacert.pem, which still carries the distrusted roots. A host that is
# "clean" in the system bundle but dirty in certifi is still legitimately
# affected, so the role remediates it and the zero-change assertion fails for
# the wrong reason. Excise the roots here so "clean" means clean in EVERY
# store the role manages.
fixture_clean_extended() {
  local name="$1"
  local fps="${BAD_ROOT_FPS[*]}"
  docker exec "$name" sh -c "
    set -u
    bad_fps=\"${fps}\"
    for pem in /usr/lib/python3/dist-packages/certifi/cacert.pem \
               /usr/lib/python3.*/site-packages/certifi/cacert.pem \
               /usr/local/lib/python3.*/*-packages/certifi/cacert.pem; do
      [ -f \"\$pem\" ] || continue
      d=\"\$(mktemp -d)\"
      awk -v d=\"\$d\" '/BEGIN CERTIFICATE/{f=sprintf(\"%s/c.%d.pem\",d,++i)} f{print > f} /END CERTIFICATE/{close(f); f=\"\"}' \"\$pem\"
      : > \"\$pem.clean\"
      for c in \"\$d\"/*.pem; do
        [ -f \"\$c\" ] || continue
        fp=\"\$(openssl x509 -in \"\$c\" -noout -fingerprint -sha256 2>/dev/null | tr -d ':' | awk -F= '{print toupper(\$2)}')\"
        case \" \$bad_fps \" in
          *\" \$fp \"*) continue ;;
        esac
        cat \"\$c\" >> \"\$pem.clean\"
      done
      mv \"\$pem.clean\" \"\$pem\"
      rm -rf \"\$d\"
    done
  " >/dev/null 2>&1 || true
}

# Fixture: assert a fingerprint is (or is not) in the container's active
# trust bundle, by splitting the bundle and fingerprinting each cert.
bundle_has_fingerprint() {
  local name="$1" fp="$2" want="$3"  # want: present|absent
  # shellcheck disable=SC2016 # the script runs inside the container; host-side expansion must NOT happen
  local script='
    for bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/pki/tls/certs/ca-bundle.trust.crt; do
      [ -f "$bundle" ] || continue
      d="$(mktemp -d)"; i=0; f=""
      awk -v d="$d" "/BEGIN CERTIFICATE/{f=sprintf(\"%s/c.%d.pem\",d,++i)} f{print > f} /END CERTIFICATE/{close(f); f=\"\"}" "$bundle"
      for pem in "$d"/*.pem; do
        openssl x509 -in "$pem" -noout -fingerprint -sha256 2>/dev/null |
          tr -d ":" | awk -F= "{print toupper(\$2)}"
      done
      rm -rf "$d"
    done | sort -u
  '
  local found
  found="$(docker exec "$name" sh -c "$script" 2>/dev/null)"
  # Anti-vacuous guard: a scan that produced NO fingerprints means the fixture
  # itself is broken (bad quoting, missing openssl, empty bundle) — that is NOT
  # "absent". Fail loudly instead of letting assertions pass vacuously.
  if [[ -z "${found//[$' \t\n']/}" ]]; then
    log "bundle_has_fingerprint: scan produced no fingerprints on ${name} — fixture broken, failing"
    return 2
  fi
  if [[ "$want" == present ]]; then
    grep -qi "$fp" <<<"$found" || return 1
  else
    grep -qi "$fp" <<<"$found" && return 1 || true
  fi
  return 0
}

# Fixture: inject a decoy cert with a name-similar CN but a different
# fingerprint — remediation must NOT touch it (fingerprint-only matching).
inject_decoy() {
  local name="$1"
  if docker exec "$name" sh -c 'command -v update-ca-certificates' >/dev/null 2>&1; then
    docker exec "$name" sh -c 'openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
      -subj "/CN=emSign Root CA - G1" -keyout /tmp/d.key -out /usr/local/share/ca-certificates/decoy-g1.crt 2>/dev/null \
      && update-ca-certificates >/dev/null 2>&1'
  else
    docker exec "$name" sh -c 'openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
      -subj "/CN=emSign Root CA - G1" -keyout /tmp/d.key -out /etc/pki/ca-trust/source/anchors/decoy-g1.crt 2>/dev/null \
      && update-ca-trust >/dev/null 2>&1'
  fi
}

# Clean: construct the clean state in the fixture (never via the role), then
# the playbook must be a zero-change no-op. Debian: upgrade ca-certificates
# directly. Rocky: upgrade; if the root survives (released repos lag), apply
# the advisory's blocklist in the fixture.
scenario_clean() {
  local images="$1"
  local fp_ecc=86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
  local image name out i=0
  for image in ${images//,/ }; do
    i=$((i + 1))
    name="emudhra-e2e-clean-${i}"
    up_container "$name" "$image"
    bootstrap_python "$name"
    # Tolerant fixture upgrade: a network/repo failure here must NOT kill the
    # scenario silently (set -e) — the fingerprint check below and the
    # zero-change assertion surface real problems with context instead.
    if docker exec "$name" sh -c 'command -v apt-get' >/dev/null 2>&1; then
      docker exec "$name" sh -c 'apt-get update -qq && apt-get install -y -qq ca-certificates' >/dev/null 2>&1 || true
    else
      docker exec "$name" sh -c 'dnf upgrade -y ca-certificates' >/dev/null 2>&1 || true
    fi
    # Rocky: if any distrusted root still ships, blocklist it in the fixture.
    # `|| rc=$?` is REQUIRED: set -e would otherwise kill the scenario on a
    # legitimate "absent" (rc=1 — the fixed package already shipped) before
    # the handled case branches below can run.
    rc=0
    bundle_has_fingerprint "$name" "$fp_ecc" present || rc=$?
    if [[ $rc -eq 2 ]]; then
      die "clean: ${name}: fingerprint fixture scan broken"
    fi
    if [[ $rc -eq 0 ]] || docker exec "$name" sh -c 'command -v dnf' >/dev/null 2>&1; then
      if docker exec "$name" sh -c 'command -v apt-get' >/dev/null 2>&1; then
        fixture_clean_debian "$name"
      else
        fixture_clean_redhat "$name"
      fi
    fi
    # Unconditional: the branch above only runs when the SYSTEM bundle is
    # still dirty, but certifi ships its own copy of the roots — on an image
    # whose ca-certificates upgrade already fixed the system bundle the
    # fixture was skipped entirely and the host was never actually clean.
    fixture_clean_extended "$name"
    write_inventory "$name"
    out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
    echo "$out" | grep -q 'changed=[1-9]' \
      && { echo "$out" | tail -30; die "clean: ${name}: run reported changes on a clean host"; }
    log "clean: ${name} zero-change no-op"
  done
  log "clean: PASS"
}

# Mixed fleet: all images up simultaneously, some affected some clean, ONE
# playbook run — per-host assertions prove family dispatch side-by-side.
scenario_mixed() {
  local images="$1"
  local fp_ecc=86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
  local -a names=()
  local i=0 image name
  for image in ${images//,/ }; do
    i=$((i + 1))
    name="emudhra-e2e-mixed-${i}"
    up_container "$name" "$image"
    bootstrap_python "$name"
    names+=("$name")
  done
  # Inject on the first two hosts; fixture-clean the rest (pristine Rocky is
  # genuinely affected — its stock bundle ships the root — so "clean" must be
  # constructed, not assumed).
  local cert_idx=0
  for cert in "${BAD_ROOT_CERTS[@]}"; do
    inject_root "${names[0]}" "$cert"
    if [[ ${#names[@]} -gt 1 ]]; then
      inject_root "${names[1]}" "$cert"
    fi
    cert_idx=$((cert_idx + 1))
  done
  local fp_ecc_clean=86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
  for name in "${names[@]:2}"; do
    # `|| rc=$?` is REQUIRED: set -e would otherwise kill the scenario on a
    # legitimate "absent" (rc=1 — the fixed package already shipped) before
    # the handled case branches below can run.
    rc=0
    bundle_has_fingerprint "$name" "$fp_ecc_clean" present || rc=$?
    log "mixed: fixture-clean check on ${name}: rc=${rc} (0=present, 1=absent, 2=broken)"
    case $rc in
      0) # present — fixture-clean this host
        if docker exec "$name" sh -c 'command -v update-ca-certificates' >/dev/null 2>&1; then
          fixture_clean_debian "$name"
        else
          fixture_clean_redhat "$name"
        fi
        ;;
      1) ;; # genuinely absent — nothing to do
      *) die "mixed: ${name}: fingerprint fixture scan broken" ;;
    esac
    # Unconditional: the system bundle being clean says nothing about the
    # extended stores, and rc=1 skips the branch above entirely.
    fixture_clean_extended "$name"
    # Verify the fixture-clean took effect before running the playbook.
    assert_all_roots_absent "$name" \
      || die "mixed: ${name}: fixture-clean did not clear all roots"
    log "mixed: ${name} fixture-clean verified (all roots absent)"
  done
  write_inventory "${names[@]}"
  local out
  out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
  # PLAY RECAP lines carry per-host changed counts: "<name> : ok=N changed=M ..."
  for name in "${names[@]:2}"; do
    echo "$out" | grep -E "^${name}\s+:\s+ok=[0-9]+\s+changed=0" >/dev/null \
      || { echo "$out" | grep -E 'affected=|RECAP|ok=' | tail -25; die "mixed: clean host ${name} reported changes"; }
  done
  for name in "${names[@]:0:2}"; do
    assert_all_roots_absent "$name" \
      || die "mixed: affected host ${name} still has bad root"
  done
  log "mixed: PASS"
}

# Extended trust stores: certifi (and Java where present) must be detected,
# remediated, and verified — WITHOUT ever installing an absent package.
# Fixture: inject a distrusted root into the container's certifi cacert.pem
# (the fixture may modify; the role never installs). Assert: root excised,
# second run idempotent, and a container WITHOUT certifi is skipped cleanly.
scenario_extended() {
  local images="$1"
  local image name out i=0
  for image in ${images//,/ }; do
    i=$((i + 1))
    name="emudhra-e2e-extended-${i}"
    up_container "$name" "$image"
    bootstrap_python "$name"
    # Fixture: append a distrusted root to the certifi bundle (if the image
    # ships one — the fixture bakes python3-certifi in; stock images skip).
    # `|| true`: both `ls` probes exit non-zero on an image without certifi,
    # and `set -o pipefail` would otherwise abort the whole scenario here —
    # which silently skipped the "role must NOT install certifi" assertion
    # below on every RedHat-family image in the matrix.
    local cert_pem
    cert_pem="$(docker exec "$name" sh -c 'ls /usr/lib/python3/dist-packages/certifi/cacert.pem 2>/dev/null || ls /usr/lib/python3.*/site-packages/certifi/cacert.pem 2>/dev/null' | head -1 || true)"
    if [[ -n "$cert_pem" ]]; then
      docker cp "${REPO_ROOT}/roles/emudhra_ca/files/certs/emSign_ECC_Root_CA_-_G3.crt" \
        "${name}:${cert_pem}.new" >/dev/null
      docker exec "$name" sh -c "cat '${cert_pem}.new' >> '${cert_pem}' && rm -f '${cert_pem}.new'"
      log "extended: ${name} injected root into ${cert_pem}"
    else
      log "extended: ${name} has no certifi — role must skip, not install"
    fi
    write_inventory "$name"

    out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
    if [[ -n "$cert_pem" ]]; then
      # The injected root must be gone from the certifi bundle.
      docker exec "$name" sh -c "
        pem='${cert_pem}'
        d=\$(mktemp -d); i=0; f=''
        awk -v d=\"\$d\" '/BEGIN CERTIFICATE/{f=sprintf(\"%s/c.%d.pem\",d,++i)} f{print > f} /END CERTIFICATE/{close(f); f=\"\"}' \"\$pem\"
        hit=0
        for c in \"\$d\"/*.pem; do
          fp=\$(openssl x509 -in \"\$c\" -noout -fingerprint -sha256 2>/dev/null | tr -d ':' | awk -F= '{print toupper(\$2)}')
          case \"\$fp\" in 86A1ECBA*) hit=1 ;; esac
        done
        rm -rf \"\$d\"
        exit \$hit
      " || die "extended: ${name}: distrusted root still in certifi bundle"
      log "extended: ${name} certifi excised"
    else
      # No certifi: the role must NOT have installed it.
      docker exec "$name" sh -c 'command -v apt-get >/dev/null && dpkg-query -W -f="\${Status}" python3-certifi 2>/dev/null | grep -q "install ok installed" && exit 1; exit 0' \
        || die "extended: ${name}: role installed python3-certifi (forbidden)"
      log "extended: ${name} skipped absent certifi (nothing installed)"
    fi

    # Idempotency: second run must be a no-op.
    out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
    echo "$out" | grep -q 'changed=[1-9]' \
      && die "extended: ${name}: second run reported changes (not idempotent)"
    log "extended: ${name} second run idempotent"
  done
  log "extended: PASS"
}

# Unsupported family: Alpine must be skipped with a warning, zero changes,
# exit 0.
scenario_unsupported() {
  local name="emudhra-e2e-unsupported-1"
  up_container "$name" alpine:3.20
  bootstrap_python "$name"
  write_inventory "$name"
  local out
  out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
  echo "$out" | grep -q 'unsupported OS family' \
    || die "unsupported: skip warning missing"
  echo "$out" | grep -q 'changed=[1-9]' \
    && die "unsupported: changes reported on unsupported host"
  log "unsupported: PASS"
}

# Wrapper: the real playbook (playbooks/emudhra-ca/distrust-emudhra-roots.yml)
# must be a thin target_hosts wrapper around the role, with the connectivity
# check skippable via variable (e2e always skips it — no egress guarantee).
scenario_wrapper() {
  local images="$1"
  local name="emudhra-e2e-wrapper-1"
  up_container "$name" "$(echo "$images" | cut -d, -f1)"
  bootstrap_python "$name"
  local cert
  for cert in "${BAD_ROOT_CERTS[@]}"; do
    inject_root "$name" "$cert"
  done
  write_inventory "$name"

  local out
  out="$(run_playbook "${REPO_ROOT}/playbooks/emudhra-ca/distrust-emudhra-roots.yml" \
    -e target_hosts=all -e emudhra_ca_run_connectivity_check=false)" || true
  assert_all_roots_absent "$name" \
    || { echo "$out" | tail -30; die "wrapper: bad root still in bundle"; }
  echo "$out" | grep -q 's_client' \
    && die "wrapper: connectivity check ran despite emudhra_ca_run_connectivity_check=false"
  grep -q '# Usage:' "${REPO_ROOT}/playbooks/emudhra-ca/distrust-emudhra-roots.yml" \
    || die "wrapper: playbook missing usage comment block"
  log "wrapper: remediated via wrapper, connectivity check skipped"

  # Idempotency through the wrapper.
  out="$(run_playbook "${REPO_ROOT}/playbooks/emudhra-ca/distrust-emudhra-roots.yml" \
    -e target_hosts=all -e emudhra_ca_run_connectivity_check=false)" || true
  echo "$out" | grep -q 'changed=[1-9]' \
    && die "wrapper: second run reported changes (not idempotent)"
  log "wrapper: second run idempotent"
  log "wrapper: PASS"
}

# Remediation: bad root (arbitrary filename) removed from the active bundle,
# name-similar decoy untouched, second run is a zero-change no-op.
# On Rocky the package upgrade alone cannot clear the package-shipped root
# (released repos lag the c9s fix), so the blocklist fallback (verify.yml)
# completes the remediation — that path is exercised here end-to-end.
scenario_remediate() {
  local images="$1"
  local image name out cert i
  local i=0
  for image in ${images//,/ }; do
    i=$((i + 1))
    name="emudhra-e2e-remediate-${i}"
    up_container "$name" "$image"
    bootstrap_python "$name"
    # Inject ALL distrusted roots, each under a random name
    # (name-independence) + a decoy.
    for cert in "${BAD_ROOT_CERTS[@]}"; do
      inject_root "$name" "$cert"
    done
    docker exec "$name" sh -c 'for d in /usr/local/share/ca-certificates /etc/pki/ca-trust/source/anchors; do [ -d "$d" ] || continue; i=0; for f in "$d"/emSign*.crt "$d"/Comodo*.crt; do [ -f "$f" ] || continue; i=$((i+1)); mv "$f" "$d/random-name-$i.crt"; done; done; command -v update-ca-certificates >/dev/null && update-ca-certificates || update-ca-trust' >/dev/null 2>&1
    inject_decoy "$name"
    write_inventory "$name"

    out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
    assert_all_roots_absent "$name" \
      || { echo "$out" | tail -40; die "remediate: ${name}: bad root still in bundle after run"; }
    docker exec "$name" sh -c 'ls /usr/local/share/ca-certificates/decoy-g1.crt /etc/pki/ca-trust/source/anchors/decoy-g1.crt 2>/dev/null | head -1 | grep -q decoy' \
      || die "remediate: ${name}: decoy cert was removed"
    echo "$out" | grep -q 'changed=' \
      || die "remediate: ${name}: no change reported"
    log "remediate: ${name} remediated (all ${#BAD_ROOT_FPS[@]} roots), decoy intact"

    # Idempotency: second run must be a no-op (changed=0 for the role).
    out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
    echo "$out" | grep -q 'changed=[1-9]' \
      && die "remediate: ${name}: second run reported changes (not idempotent)"
    log "remediate: ${name} second run idempotent"
  done
  log "remediate: PASS"
}

# Fallback scenario: force the Debian `!`-prefix fallback to actually run.
# The package-upgrade path clears the roots on every default-matrix Debian
# image (fixed packages reached the mirrors), so the fallback block in
# verify.yml is otherwise never entered — the .crt.crt bug (fixed in the
# review round) shipped invisibly because no scenario forced this path.
# Proxy for "fixed version not in repos": apt-mark hold ca-certificates so
# `state: latest` cannot upgrade it. The distrusted root must then survive
# the upgrade, forcing the `!`-prefix fallback — which must clear it.
scenario_fallback() {
  local images="$1"
  # Debian-family only (the `!`-prefix fallback is Debian-specific; Rocky's
  # blocklist fallback is exercised by the remediate scenario).
  local image name out conf_entry
  local -a debian_images=()
  for image in ${images//,/ }; do
    case "$image" in ubuntu:*|debian:*) debian_images+=("$image") ;;
    esac
  done
  [[ ${#debian_images[@]} -gt 0 ]] || die "fallback: no Debian-family image in matrix"
  image="${debian_images[0]}"
  name="emudhra-e2e-fallback-1"
  up_container "$name" "$image"
  bootstrap_python "$name"
  # Hold the package so the upgrade cannot clear the root (repo-lag proxy).
  docker exec "$name" sh -c 'command -v apt-mark >/dev/null' \
    || die "fallback: ${name}: apt-mark not available (non-Debian image?)"
  docker exec "$name" apt-mark hold ca-certificates >/dev/null
  log "fallback: ${name}: ca-certificates held (upgrade path blocked)"
  # Inject the root PACKAGE-STYLE: /usr/share/ca-certificates/mozilla/ + a
  # conf entry — mimicking a distro bundle that still ships it. A manual-copy
  # injection would be cleared by the role's manual-copy removal (no upgrade
  # needed), never reaching the fallback; package-style leaves the upgrade
  # (blocked by the hold) and the `!`-prefix fallback as the only paths.
  docker exec "$name" mkdir -p /usr/share/ca-certificates/mozilla
  docker cp "${REPO_ROOT}/roles/emudhra_ca/files/certs/emSign_ECC_Root_CA_-_G3.crt" \
    "${name}:/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt" >/dev/null
  docker exec "$name" sh -c \
    'grep -q "^mozilla/emSign_ECC_Root_CA_-_G3.crt$" /etc/ca-certificates.conf || echo "mozilla/emSign_ECC_Root_CA_-_G3.crt" >> /etc/ca-certificates.conf; update-ca-certificates' >/dev/null 2>&1
  write_inventory "$name"

  out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
  # The fallback MUST have fired (loud marker from verify.yml).
  echo "$out" | grep -q 'EMUDHRA_SCA_FALLBACK' \
    || { echo "$out" | tail -40; die "fallback: ${name}: fallback marker missing — fallback did not fire"; }
  # The root must be gone from the active bundle.
  assert_all_roots_absent "$name" \
    || { echo "$out" | tail -40; die "fallback: ${name}: bad root still in bundle after fallback"; }
  # The `!`-prefix must be present in /etc/ca-certificates.conf for the
  # injected root's entry (the mechanism the fallback relies on).
  conf_entry="$(docker exec "$name" sh -c 'grep -n "^!.*emSign_ECC_Root_CA" /etc/ca-certificates.conf | head -1' || true)"
  [[ -n "$conf_entry" ]] \
    || die "fallback: ${name}: no !-prefixed emSign_ECC entry in /etc/ca-certificates.conf"
  log "fallback: ${name}: fallback fired, root excised, conf entry !-prefixed"

  # Idempotency: re-run must be a no-op (the !-prefix converges, not doubles).
  out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
  echo "$out" | grep -q 'changed=[1-9]' \
    && die "fallback: ${name}: second run reported changes (not idempotent)"
  docker exec "$name" sh -c '! grep -q "^!!" /etc/ca-certificates.conf' \
    || die "fallback: ${name}: double-! prefix appeared (convergence broken)"
  log "fallback: ${name}: second run idempotent, no double-! prefix"

  # Unhold so the container teardown leaves nothing weird behind (it is
  # ephemeral, but the assertion output reads cleaner).
  docker exec "$name" apt-mark unhold ca-certificates >/dev/null 2>&1 || true
  log "fallback: PASS"
}

# Detection gate: injected host must report affected with the right
# fingerprint; pristine and missing-bundle hosts must report clean.
scenario_detect() {
  local images="$1"
  local fp_ecc=86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B

  # Case (a): injected first image -> affected=True, matched fp present
  local a="emudhra-e2e-detect-1"
  up_container "$a" "$(echo "$images" | cut -d, -f1)"
  bootstrap_python "$a"
  inject_root "$a" emSign_ECC_Root_CA_-_G3.crt
  write_inventory "$a"
  local out
  out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
  echo "$out" | grep -q 'affected=True' \
    || die "detect: injected host not reported affected"
  echo "$out" | grep -qi "$fp_ecc" \
    || die "detect: matched fingerprint missing from output"
  log "detect: case (a) injected->affected OK"

  # Case (b): pristine rockylinux:9 -> affected=True (stock ca-certificates
  # still ships emSign ECC Root CA - G3; the distro fix only landed in c9s on
  # 2026-10-21 and released repos lag — see docs/research/corpus-distro-records.md).
  # This is the natural package-shipped case; the remediated-clean case is
  # covered by the clean scenario (Task 7).
  local b="emudhra-e2e-detect-2"
  up_container "$b" rockylinux:9
  bootstrap_python "$b"
  write_inventory "$b"
  out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
  echo "$out" | grep -q 'affected=True' \
    || die "detect: pristine rocky host not reported affected (expected: stock bundle still ships the root)"
  log "detect: case (b) pristine-rocky->affected OK"

  # Case (c): missing bundle -> system-bundle scan clean, no crash.
  # NOTE: assert on the SYSTEM matched list (matched=), not affected= —
  # the container's certifi bundle may still ship the roots (extended
  # stores), which correctly sets affected=True. The case proves the
  # missing-bundle path is handled, not that the host is fully clean.
  local c="emudhra-e2e-detect-3"
  up_container "$c" "$(echo "$images" | cut -d, -f1)"
  bootstrap_python "$c"
  docker exec "$c" sh -c 'mv /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt.bak'
  write_inventory "$c"
  out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
  docker exec "$c" sh -c 'mv /etc/ssl/certs/ca-certificates.crt.bak /etc/ssl/certs/ca-certificates.crt'
  echo "$out" | grep -q 'matched= ' \
    || die "detect: missing-bundle host reported system-bundle matches"
  log "detect: case (c) missing-bundle->clean OK"
  log "detect: PASS"
}

# Prove family-var dispatch: Debian and RedHat hosts must each resolve their
# own bundle paths and refresh command from the role's vars.
scenario_vars() {
  local images="$1"
  local -a names=()
  local i=0 image
  for image in ${images//,/ }; do
    i=$((i + 1))
    local name="emudhra-e2e-vars-${i}"
    up_container "$name" "$image"
    bootstrap_python "$name"
    names+=("$name")
  done
  write_inventory "${names[@]}"
  local out
  out="$(run_playbook "${E2E_DIR}/probe-vars.yml")" || true
  echo "$out" | grep -q '/etc/ssl/certs/ca-certificates.crt' \
    || { echo "$out" | tail -40; die "vars: Debian bundle path missing from output"; }
  echo "$out" | grep -q 'update-ca-trust' \
    || die "vars: RedHat refresh command missing from output"
  log "vars: PASS"
}

main() {
  local scenario="${1:-}"
  [[ -n "$scenario" ]] || die "usage: run.sh <scenario> [--images <csv>]"
  shift || true
  local images="${DEFAULT_IMAGES}" # consumed by matrix scenarios
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --images) images="$2"; shift 2 ;;
      *) die "unknown arg: $1" ;;
    esac
  done

  # Single source of truth: every scenario drives the SAME root list the role
  # matches against, loaded from the role's own vars.
  load_bad_roots

  # Pre-build all target images up front so scenarios never race on docker
  # build (parallel-safe) and first-container startup is fast.
  local img
  for img in ${images//,/ }; do
    resolve_image "$img" >/dev/null
  done

  case "$scenario" in
    smoke) scenario_smoke "$images" ;;
    vars) scenario_vars "$images" ;;
    detect) scenario_detect "$images" ;;
    remediate) scenario_remediate "$images" ;;
    fallback) scenario_fallback "$images" ;;
    wrapper) scenario_wrapper "$images" ;;
    clean) scenario_clean "$images" ;;
    mixed) scenario_mixed "$images" ;;
    unsupported) scenario_unsupported "$images" ;;
    extended) scenario_extended "$images" ;;
    all)
      # Scenarios are independent (own containers, own inventory) — run them
      # concurrently. Concurrency is a parameter: EMUDHRA_E2E_JOBS (default 3;
      # each job needs roughly 1GiB of docker-VM memory — size your colima VM
      # accordingly, e.g. colima start --cpu 4 --memory 4 for 3 jobs).
      local jobs="${EMUDHRA_E2E_JOBS:-3}"
      local sc logf names=(smoke vars detect remediate fallback wrapper clean mixed unsupported extended)
      local -A pid_of=() status_of=()
      local running=0
      for sc in "${names[@]}"; do
        logf="/tmp/emudhra-e2e-${sc}.log"
        "scenario_${sc}" "$images" > "$logf" 2>&1 &
        pid_of[$!]=$sc
        ALL_PIDS="${ALL_PIDS:-}$! "
        running=$((running + 1))
        # Poll until fewer than $jobs are alive; reap each finished PID once.
        while [[ "$running" -ge "$jobs" ]]; do
          local p alive=0
          for p in ${ALL_PIDS}; do
            if [[ -z "${status_of[${pid_of[$p]}]:-}" ]]; then
              if kill -0 "$p" 2>/dev/null; then
                alive=$((alive + 1))
              else
                if wait "$p" 2>/dev/null; then
                  status_of[${pid_of[$p]}]=0
                else
                  status_of[${pid_of[$p]}]=$?
                fi
              fi
            fi
          done
          running=$alive
          [[ "$running" -ge "$jobs" ]] && sleep 2
        done
      done
      # Reap the rest.
      local p
      for p in ${ALL_PIDS}; do
        if [[ -z "${status_of[${pid_of[$p]}]:-}" ]]; then
          if wait "$p" 2>/dev/null; then
            status_of[${pid_of[$p]}]=0
          else
            status_of[${pid_of[$p]}]=$?
          fi
        fi
      done
      local failed=0
      for sc in "${names[@]}"; do
        if [[ "${status_of[$sc]}" -eq 0 ]]; then
          log "all: ${sc} PASS"
        else
          log "all: ${sc} FAIL (see /tmp/emudhra-e2e-${sc}.log)"
          tail -5 "/tmp/emudhra-e2e-${sc}.log" || true
          failed=1
        fi
      done
      if [[ $failed -eq 0 ]]; then
        log "all: PASS"
      else
        die "all: one or more scenarios failed"
      fi
      ;;
    *) die "unknown scenario: ${scenario}" ;;
  esac
}

main "$@"
