#!/usr/bin/env bash
# Host packages needed to run scripts/release-smoke.sh, including Linux P-09.
set -euo pipefail

if [[ "$(uname -s)" == Linux ]]; then
  sudo apt-get update
  sudo apt-get install -y ripgrep bubblewrap apparmor-profiles openssl
  if [[ -f /usr/share/apparmor/extra-profiles/bwrap-userns-restrict ]]; then
    sudo cp -f /usr/share/apparmor/extra-profiles/bwrap-userns-restrict \
      /etc/apparmor.d/bwrap-userns-restrict
    sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
  else
    printf '%s\n' \
      'profile bwrap /usr/bin/bwrap flags=(unconfined) {' \
      '  userns,' \
      '}' | sudo tee /etc/apparmor.d/bwrap >/dev/null
    sudo apparmor_parser -r /etc/apparmor.d/bwrap
  fi
  /usr/bin/bwrap --die-with-parent --unshare-user --uid "$(id -u)" --gid "$(id -g)" \
    --unshare-net --unshare-pid --ro-bind / / --proc /proc --dev /dev \
    --tmpfs /tmp --chdir /tmp -- /bin/true
else
  command -v rg >/dev/null || brew install ripgrep
fi
