#!/usr/bin/env bash
# Builds vega-web from the local checkout and installs it as the live
# system service, for iterating on vega-web changes without a full
# RPM/zypper roundtrip. Run as your normal user (not via sudo) — it calls
# sudo itself for the individual privileged steps, so you'll get one
# password prompt.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
crate_dir="$repo_root/vega-web"
packaging_dir="$repo_root/packaging/vega-web"

echo "==> Buildando vega-web a partir de $crate_dir"
(
  cd "$crate_dir"
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
# Workspace Cargo: o binário sempre sai em target/ na raiz do repo, não em
# vega-web/target/ — mesmo buildando com "cd vega-web && cargo build".
sudo install -Dm755 "$repo_root/target/release/vega-web" /usr/lib/vega/vega-web

echo "==> Unit systemd"
sudo install -Dm644 "$packaging_dir/vega-web.service" /usr/lib/systemd/system/vega-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now vega-web.service

echo "==> Pronto. Status:"
systemctl status vega-web.service --no-pager | head -8
echo "==> Painel em https://localhost:9090 (certificado autoassinado — aviso do navegador é esperado)"
