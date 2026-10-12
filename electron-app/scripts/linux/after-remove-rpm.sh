#!/bin/sh
set -e
EXEC="dsc-agent-electron"
# RPM post-remove: no AppArmor/SELinux configuration to remove.
if type update-alternatives >/dev/null 2>&1; then
  update-alternatives --remove "$EXEC" "/usr/bin/$EXEC" 2>/dev/null || true
fi
rm -f "/usr/bin/$EXEC"
exit 0
