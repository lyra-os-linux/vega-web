#!/bin/sh
# Run from RPM %post (or dev-install) after the new binaries/units exist.
# Never leave an old HTTPS process holding supplementary groups/open files.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
test "$(id -u)" = 0

restart=false
if [ -d /run/systemd/system ]; then
    case "$(systemctl is-active vega-web.service || :)" in
        active|activating|reloading) restart=true ;;
    esac
    systemctl stop vega-web.service
fi

if getent passwd vega-web >/dev/null; then
    shadow_gid="$(getent group shadow | cut -d: -f3)"
    if [ -n "$shadow_gid" ]; then
        if [ "$(id -g vega-web)" = "$shadow_gid" ]; then
            echo 'vega-web: refusing migration: shadow is the primary group; service remains stopped' >&2
            exit 1
        fi
        case " $(id -G vega-web) " in
            *" $shadow_gid "*) gpasswd --delete vega-web shadow ;;
        esac
        case " $(id -G vega-web) " in
            *" $shadow_gid "*) echo 'vega-web: shadow membership remains; service will not restart' >&2; exit 1 ;;
        esac
    fi
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    if "$restart"; then systemctl start vega-web.service; fi
fi
