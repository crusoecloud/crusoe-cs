# Shell helpers for crusoe-cx-ansible.
# Sourced automatically by bootstrap.sh — do not edit the copy in ~/.zshrc.

# SSH into an Ansible inventory host by name.
# Usage: anssh <inventory-hostname> [ssh-args...]
anssh() {
  if [[ $# -eq 0 ]]; then
    echo "Usage: anssh <inventory-hostname> [ssh-args...]" >&2
    return 1
  fi
  local host="$1"; shift
  local ip
  ip=$(ansible-inventory --host "$host" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['ansible_host'])" 2>/dev/null)
  if [[ -z "$ip" ]]; then
    echo "anssh: could not resolve ansible_host for '$host'" >&2
    return 1
  fi
  ssh "ubuntu@$ip" "$@"
}
