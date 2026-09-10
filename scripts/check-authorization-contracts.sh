#!/usr/bin/env bash
set -euo pipefail

# Never connect the permissive fake daemon to the host system bus.
exec dbus-run-session -- sh -c '
    export DBUS_SYSTEM_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS"
    export VEGA_WEB_TEST_PRIVATE_BUS=1
    exec cargo test --locked authorization_integration -- --ignored --nocapture
'
