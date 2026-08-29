#!/bin/sh
set -e
EXEC="dsc-agent-electron"
APPARMOR_DST="/etc/apparmor.d/dsc-agent"

# Remove the /usr/bin symlink / alternative
if type update-alternatives >/dev/null 2>&1; then
  update-alternatives --remove "$EXEC" "/usr/bin/$EXEC" 2>/dev/null || true
fi
rm -f "/usr/bin/$EXEC"

# Remove the DSC Agent AppArmor profile
if [ -f "$APPARMOR_DST" ]; then
  echo "post-remove: removing DSC Agent AppArmor profile..."
  if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -R "$APPARMOR_DST" 2>/dev/null || \
      echo "WARNING: could not unload AppArmor profile (not loaded?)." >&2
  fi
  rm -f "$APPARMOR_DST"
  echo "post-remove: DSC Agent AppArmor profile removed."
fi
exit 0
