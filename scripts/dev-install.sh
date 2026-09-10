#!/usr/bin/env bash
# Builds vega-web from the local checkout and installs it as the live
# system service, for iterating on vega-web changes without a full
# RPM/zypper roundtrip. Run as your normal user (not via sudo) — it calls
# sudo itself for the individual privileged steps, so you'll get one
# password prompt.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
packaging_dir="$repo_root/packaging"

echo "==> Buildando vega-web a partir de $repo_root"
(
  cd "$repo_root"
  cargo build --release --locked
)

echo "==> Usuário de sistema vega-web"
sudo install -Dm644 "$packaging_dir/sysusers.d/vega-web.conf" /usr/lib/sysusers.d/vega-web.conf
sudo systemd-sysusers vega-web.conf

echo "==> Diretórios de estado (systemd-tmpfiles)"
sudo install -Dm644 "$packaging_dir/tmpfiles.d/vega-web.conf" /usr/lib/tmpfiles.d/vega-web.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/vega-web.conf

echo "==> Serviço PAM (auth via contas do sistema)"
sudo install -Dm644 "$packaging_dir/pam.d/vega-web" /etc/pam.d/vega-web

echo "==> Instalando binário em /usr/lib/vega/vega-web"
sudo install -Dm755 "$repo_root/target/release/vega-web" /usr/lib/vega/vega-web
sudo install -Dm755 "$repo_root/target/release/vega-web-terminal-helper" \
  /usr/lib/vega/vega-web-terminal-helper
sudo install -Dm755 "$repo_root/target/release/vega-web-auth-helper" \
  /usr/lib/vega/vega-web-auth-helper
sudo install -Dm755 "$packaging_dir/migrate-auth.sh" /usr/lib/vega/vega-web-migrate-auth

echo "==> Units systemd"
sudo install -Dm644 "$packaging_dir/vega-web.service" /usr/lib/systemd/system/vega-web.service
sudo install -Dm644 "$packaging_dir/vega-web-terminal.socket" \
  /usr/lib/systemd/system/vega-web-terminal.socket
sudo install -Dm644 "$packaging_dir/vega-web-terminal@.service" \
  /usr/lib/systemd/system/vega-web-terminal@.service
sudo install -Dm644 "$packaging_dir/vega-web-auth.socket" \
  /usr/lib/systemd/system/vega-web-auth.socket
sudo install -Dm644 "$packaging_dir/vega-web-auth@.service" \
  /usr/lib/systemd/system/vega-web-auth@.service
sudo /usr/lib/vega/vega-web-migrate-auth
sudo systemctl enable --now vega-web.service

echo "==> Pronto. Status:"
systemctl status vega-web.service --no-pager | head -8
echo "==> Painel em https://localhost:9090 (certificado autoassinado — aviso do navegador é esperado)"
