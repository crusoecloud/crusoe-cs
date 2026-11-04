#!/usr/bin/env bash
set -euo pipefail

echo "==> Checking uv..."
if command -v uv &>/dev/null; then
  echo "    uv already installed, skipping."
else
  echo "    uv not found — installing via brew..."
  # brew (not the curl|sh installer): same channel as direnv below,
  # no shell-pipe-to-sh, and brew puts uv on PATH directly.
  brew install uv
fi

echo "==> Checking direnv..."
if command -v direnv &>/dev/null; then
  echo "    direnv already installed, skipping."
else
  echo "    direnv not found — installing via brew..."
  brew install direnv
  echo "  Add the following to your ~/.zshrc and restart your shell:"
  echo '    eval "$(direnv hook zsh)"'
fi

echo "==> Writing .envrc..."
ENVRC="$(dirname "$0")/../.envrc"
if [[ ! -f "${ENVRC}" ]]; then
  cat > "${ENVRC}" <<'EOF'
source .venv/bin/activate 2>/dev/null || true
PATH_add scripts
EOF
  echo "    .envrc created."
else
  echo "    .envrc already exists, skipping."
fi

echo "==> Allowing direnv for this project..."
direnv allow "$(dirname "$0")/.."

echo "==> Syncing project dependencies via uv..."
# --locked: fail if uv.lock is out of sync with pyproject.toml.
# --dev: the dev toolchain (pytest, ruff, mypy, ansible-lint).
uv sync --locked --dev

echo "==> Installing Ansible collections..."
uv run ansible-galaxy collection install -r requirements.yml

echo ""
echo "==> Done. direnv activates the venv on cd; or run commands with:"
echo "    uv run ansible --version"
echo "    uv run pytest"

