#!/usr/bin/env bash
# Reverses scripts/dev-install-vega-web.sh. Run as your normal user (not
# via sudo) — it calls sudo itself for the individual privileged steps, so
# you'll get one password prompt.
set -euo pipefail

echo "==> Parando e desabilitando vega-web.service"
sudo systemctl disable --now vega-web.service 2>/dev/null || true

echo "==> Removendo unit systemd"
sudo rm -f /usr/lib/systemd/system/vega-web.service
sudo systemctl daemon-reload

echo "==> Removendo binário"
sudo rm -f /usr/lib/vega/vega-web
# /usr/lib/vega/ é compartilhado com o vegad — não remove o diretório em si.

echo "==> Removendo serviço PAM"
sudo rm -f /etc/pam.d/vega-web

echo "==> Removendo diretórios de estado (inclui o certificado TLS autoassinado)"
sudo rm -f /usr/lib/tmpfiles.d/vega-web.conf
sudo rm -rf /etc/vega/web
sudo rm -rf /var/lib/vega-web

echo "==> Removendo usuário/grupo de sistema vega-web"
sudo rm -f /usr/lib/sysusers.d/vega-web.conf
sudo userdel vega-web 2>/dev/null || true
sudo groupdel vega-web 2>/dev/null || true

echo "vega-web removido."
