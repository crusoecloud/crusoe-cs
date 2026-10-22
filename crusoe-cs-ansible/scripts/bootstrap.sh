#!/usr/bin/env bash
set -euo pipefail

PYTHON_VERSION=$(cat "$(dirname "$0")/../.python-version" | tr -d '[:space:]')

echo "==> Checking pyenv..."
if ! command -v pyenv &>/dev/null; then
  echo "ERROR: pyenv is not installed. Install it with:" >&2
  echo "    brew install pyenv" >&2
  echo "    echo 'eval \"\$(pyenv init -)\"' >> ~/.zshrc && source ~/.zshrc" >&2
  exit 1
fi

echo "==> Installing Python ${PYTHON_VERSION} via pyenv (if needed)..."
pyenv install --skip-existing "${PYTHON_VERSION}"

echo "==> Setting local Python version to ${PYTHON_VERSION}..."
if [[ "$(cat .python-version 2>/dev/null | tr -d '[:space:]')" == "${PYTHON_VERSION}" ]]; then
  echo "    .python-version already set to ${PYTHON_VERSION}, skipping."
else
  pyenv local "${PYTHON_VERSION}"
fi

echo "==> Checking pipenv..."
if command -v pipenv &>/dev/null; then
  echo "    pipenv already installed, skipping."
else
  echo "    pipenv not found — installing via pip..."
  pip install --user pipenv
fi

echo "==> Checking direnv..."
if command -v direnv &>/dev/null; then
  echo "    direnv already installed, skipping."
else
  echo "    direnv not found — installing via brew..."
  brew install direnv
  echo "    Add the following to your ~/.zshrc and restart your shell:"
  echo '    eval "$(direnv hook zsh)"'
fi

echo "==> Writing .envrc..."
ENVRC="$(dirname "$0")/../.envrc"
if [[ ! -f "${ENVRC}" ]]; then
  cat > "${ENVRC}" <<'EOF'
export PIPENV_VENV_IN_PROJECT=1
source .venv/bin/activate 2>/dev/null || true
EOF
  echo "    .envrc created."
else
  echo "    .envrc already exists, skipping."
fi

echo "==> Allowing direnv for this project..."
direnv allow "$(dirname "$0")/.."

echo "==> Syncing project dependencies via pipenv..."
export PIPENV_VENV_IN_PROJECT=1
if pipenv --venv &>/dev/null 2>&1; then
  echo "    Virtualenv exists — syncing..."
fi
PIPENV_PYTHON="$(pyenv root)/versions/${PYTHON_VERSION}/bin/python" \
  pipenv install --dev

echo "==> Installing Ansible collections..."
pipenv run ansible-galaxy collection install -r requirements.yml

echo ""
echo "==> Done. Activate the environment with:"
echo "    pipenv shell"
echo ""
echo "    Or run commands directly with:"
echo "    pipenv run ansible --version"
echo "    pipenv run pytest"
