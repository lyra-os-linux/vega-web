#!/usr/bin/env bash
set -euo pipefail

# Isolate the D-Bus connection needed to construct AppState. Tests never
# invoke the host daemon or modify accounts/PAM. The shell exports the address
# before Rust starts, avoiding process-global environment mutations in tests.
exec dbus-run-session -- sh -c '
    export DBUS_SYSTEM_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS"
    exec cargo test --locked session_integration -- --ignored --nocapture
'
