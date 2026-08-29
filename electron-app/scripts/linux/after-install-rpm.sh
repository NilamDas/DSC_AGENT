#!/bin/sh
set -e
EXEC="dsc-agent-electron"
INSTALL_DIR="/opt/dsc-agent"
SANDBOX="$INSTALL_DIR/chrome-sandbox"

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

# /usr/bin entry points at the wrapper
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
# RPM: no AppArmor/SELinux modifications (distribution-appropriate).
exit 0
