#!/bin/sh
set -e
EXEC="dsc-agent-electron"
INSTALL_DIR="/opt/dsc-agent"
SANDBOX="$INSTALL_DIR/chrome-sandbox"
APPARMOR_DST="/etc/apparmor.d/dsc-agent"

# Launcher wrapper (handles running as root)
# Chromium refuses to start as root unless `--no-sandbox` is on the REAL
# command line (the check happens in native startup code before any JS runs,
# so app.commandLine.appendSwitch() is too late). The wrapper adds it only
# when the process actually runs as root.
cat > "$INSTALL_DIR/dsc-agent-wrapper.sh" <<'WRAPPER_EOF'
#!/bin/sh
# Resolve symlinks (e.g. /usr/bin/dsc-agent-electron -> ... -> this script) so
# EXEC_DIR always points at the real install dir, never at the symlink's dir.
SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"
EXEC_DIR="$(cd "$(dirname "$SELF")" && pwd)"
if [ "$(id -u)" = "0" ] && ! printf '%s\n' "$@" | grep -q -- '--no-sandbox'; then
  exec "$EXEC_DIR/dsc-agent-electron" --no-sandbox "$@"
fi
exec "$EXEC_DIR/dsc-agent-electron" "$@"
WRAPPER_EOF
chmod 755 "$INSTALL_DIR/dsc-agent-wrapper.sh"

# /usr/bin entry points at the wrapper (mirrors electron-builder default post-install)
if type update-alternatives >/dev/null 2>&1; then
  if [ -L "/usr/bin/$EXEC" ] && [ -e "/usr/bin/$EXEC" ]; then
    if [ "$(readlink "/usr/bin/$EXEC")" != "/etc/alternatives/$EXEC" ]; then
      rm -f "/usr/bin/$EXEC"
    fi
  fi
  update-alternatives --install "/usr/bin/$EXEC" "$EXEC" "$INSTALL_DIR/dsc-agent-wrapper.sh" 100 || ln -sf "$INSTALL_DIR/dsc-agent-wrapper.sh" "/usr/bin/$EXEC"
else
  ln -sf "$INSTALL_DIR/dsc-agent-wrapper.sh" "/usr/bin/$EXEC"
fi

# chrome-sandbox ownership/permissions (SUID root 4755)
if [ -f "$SANDBOX" ]; then
  echo "DSC Agent: fixing chrome-sandbox ownership/permissions..."
  chown root:root "$SANDBOX"
  chmod 4755 "$SANDBOX"
  MODE="$(stat -c '%a' "$SANDBOX")"
  if [ "$MODE" != "4755" ]; then
    echo "ERROR: chrome-sandbox mode is $MODE, expected 4755" >&2
    exit 1
  fi
  echo "post-install: chrome-sandbox OK (root:root 4755)"
else
  echo "WARNING: $SANDBOX not found; Chromium sandbox helper missing." >&2
fi

# AppArmor profile (DEB only)
if command -v apparmor_parser >/dev/null 2>&1; then
  echo "post-install: installing DSC Agent AppArmor profile..."
  mkdir -p /etc/apparmor.d
  cat > "$APPARMOR_DST" <<'PROFILE_EOF'
# vim:syntax=apparmor
# DSC Agent - AppArmor profile.
#
# Purpose: on Ubuntu 24.04+ (AppArmor 4.x) unprivileged user namespace creation
# is mediated; without a granting profile Chromium's own sandbox cannot start.
# This profile grants userns creation ONLY to the DSC Agent binary while leaving
# everything else allowed. It does NOT touch /etc/apparmor.d/unprivileged_userns
# and does not weaken global AppArmor policy.
include <tunables/global>
profile dsc-agent /opt/dsc-agent/dsc-agent-electron flags=(attach_disconnected,mediate_deleted) {
  include <abstractions/base>
  include <abstractions/nameservice>

  file,
  network,
  dbus,
  capability,
  signal,
  ptrace,

  # Chromium SUID sandbox helper (transition without profile confinement).
  /opt/dsc-agent/chrome-sandbox Ux,

  # Grant unprivileged user namespace creation (Chromium sandbox on 24.04).
  userns,
}
PROFILE_EOF
  if apparmor_parser -r -T --skip-cache "$APPARMOR_DST" 2>/dev/null; then
    echo "post-install: DSC Agent AppArmor profile loaded."
  else
    # Older AppArmor (3.x, Ubuntu <=22.04) does not support the "userns" rule.
    if grep -q '^[[:space:]]*userns,' "$APPARMOR_DST"; then
      echo "post-install: AppArmor 3.x detected; installing profile without userns rule."
      grep -v '^[[:space:]]*userns,' "$APPARMOR_DST" > "$APPARMOR_DST.tmp"
      mv "$APPARMOR_DST.tmp" "$APPARMOR_DST"
      if apparmor_parser -r -T --skip-cache "$APPARMOR_DST" 2>/dev/null; then
        echo "post-install: DSC Agent AppArmor profile loaded (AppArmor 3.x variant)."
      else
        echo "WARNING: AppArmor profile could not be loaded; Chromium sandbox may be unavailable." >&2
      fi
    else
      echo "WARNING: AppArmor profile could not be loaded; Chromium sandbox may be unavailable." >&2
    fi
  fi
fi
exit 0
