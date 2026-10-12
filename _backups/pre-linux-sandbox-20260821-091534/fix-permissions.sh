#!/bin/bash
# Fix directory permissions for the DSC Agent install directory.
# Chromium/Electron refuses to run if the executable's directory is
# writable by group or others (credentials.cc FATAL error).
# The .deb installs to /opt/DSC Agent with 0775, which triggers the
# credentials.cc FATAL error. This script fixes it.
INSTALL_DIR="/opt/DSC Agent"
if [ -d "$INSTALL_DIR" ]; then
  chmod 755 "$INSTALL_DIR"
  chmod 755 "$INSTALL_DIR/resources" 2>/dev/null
  chmod 755 "$INSTALL_DIR/locales" 2>/dev/null
fi
SANDBOX_BIN="$INSTALL_DIR/chrome-sandbox"
if [ -f "$SANDBOX_BIN" ]; then
  chown root:root "$SANDBOX_BIN" 2>/dev/null
  chmod 4755 "$SANDBOX_BIN" 2>/dev/null
fi
exit 0
