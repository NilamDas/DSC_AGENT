#!/bin/bash
# fix-permissions.sh — manual repair helper for the DSC Agent Linux install.
#
# The .deb/.rpm post-install scripts already do this automatically; this helper
# exists so an operator can re-apply the same, loud (non-silent) repair after a
# partial/failed install or a manual copy. It NEVER swallows permission errors.
set -euo pipefail

INSTALL_DIR="/opt/dsc-agent"
SANDBOX="${INSTALL_DIR}/chrome-sandbox"
APPARMOR_PROFILE="/etc/apparmor.d/dsc-agent"

# Chromium/Electron refuses to run if the executable's directory is writable by
# group/others (credentials.cc FATAL). Ensure /opt/dsc-agent is 0755.
for d in "${INSTALL_DIR}" "${INSTALL_DIR}/resources" "${INSTALL_DIR}/locales"; do
  if [ -d "${d}" ]; then chmod 755 "${d}"; fi
done

# chrome-sandbox must be root:root + 4755 for the Chromium sandbox to work.
if [ -f "${SANDBOX}" ]; then
  chown root:root "${SANDBOX}"
  chmod 4755 "${SANDBOX}"
  MODE="$(stat -c '%a' "${SANDBOX}")"
  OWNER="$(stat -c '%U' "${SANDBOX}")"
  if [ "${OWNER}" != "root" ] || [ "${MODE}" != "4755" ]; then
    echo "ERROR: chrome-sandbox is owner=${OWNER} mode=${MODE}; expected root:root 4755" >&2
    exit 1
  fi
  echo "chrome-sandbox OK: root:root 4755"
fi

# Reload the AppArmor profile (DEB only). No-op if absent.
if [ -f "${APPARMOR_PROFILE}" ] && command -v apparmor_parser >/dev/null 2>&1; then
  apparmor_parser -r "${APPARMOR_PROFILE}" && echo "AppArmor profile reloaded."
fi
exit 0
