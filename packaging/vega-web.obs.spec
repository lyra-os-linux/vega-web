# Empacotamento para o openSUSE Build Service (home:rodrigosbrito:vega).
# Cópia de packaging/opensuse/vega-web.spec adaptada só no Source0/%setup
# pra bater com o tarball que o _service (tar_scm) deste mesmo diretório
# gera — nome com sufixo de versão e diretório interno próprio, ao invés
# do tar "achatado" usado pelo empacotamento local. Resto do spec é
# idêntico ao de packaging/opensuse/.
#
# Version literal (não %%{version}/%%define) — o serviço set_version deste
# diretório faz substituição textual simples na linha "Version:" e não
# entende macro, então precisa achar um valor literal aqui pra reescrever.
#
# NOTA: este pacote ainda não existe no projeto OBS home:rodrigosbrito:vega
# — precisa ser criado lá manualmente (como vega-gtk/vegad/vega-cli já são)
# e ganhar seu próprio serviço cargo_vendor apontando para o workspace,
# igual ao que já existe para o pacote vega-gtk.
Name:           vega-web
Version:        0
Release:        1%{?dist}
Summary:        Painel web HTTPS (somente LAN) do Vega, centro de controle para Linux
License:        GPL-3.0-only
URL:            https://github.com/britors/Vega
Source0:        vega-src-%{version}.tar
# vendor.tar.gz gerado pelo _service cargo_vendor (rede exigida, que a VM
# de build do OBS não tem — sem isso, "cargo build" trava tentando baixar
# crates de index.crates.io e falha). Traz .cargo/config.toml + Cargo.lock
# + vendor/ prontos pra extrair na raiz do workspace.
Source1:        vendor.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  pam-devel
BuildRequires:  sysuser-tools
Requires:       vegad
Requires:       pam
Requires(pre):    sysuser-tools
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%sysusers_requires

%description
Interface web HTTPS do Vega, para administração pela rede local. Login via
PAM (contas do próprio sistema); sem certificado público — ver
docs/vega-web-privacidade.md para o que isso implica antes de expor além da
LAN. Nesta versão só lê dados através do vegad (painel, serviços,
snapshots); ações de escrita chegam numa fase seguinte, com reautenticação
e sem alterar as regras de polkit já usadas pelo vega-gtk/vega-cli.

%prep
%setup -q -n vega-src-%{version}
# .cargo/config.toml + Cargo.lock + vendor/ vão na raiz do workspace,
# junto do Cargo.toml — é onde o cargo procura por padrão.
tar xzf %{SOURCE1}

%build
cd vega-web
cargo build --release --locked --offline

%install
# Workspace Cargo: o binário sai em target/ na raiz do checkout, não em
# vega-web/target/, mesmo com "cd vega-web" no %%build.
install -Dm755 target/release/vega-web \
  %{buildroot}%{_prefix}/lib/vega/vega-web
install -Dm644 packaging/vega-web/vega-web.service \
  %{buildroot}%{_prefix}/lib/systemd/system/vega-web.service
install -Dm644 packaging/vega-web/sysusers.d/vega-web.conf \
  %{buildroot}%{_sysusersdir}/vega-web.conf
install -Dm644 packaging/vega-web/tmpfiles.d/vega-web.conf \
  %{buildroot}%{_prefix}/lib/tmpfiles.d/vega-web.conf
install -Dm644 packaging/vega-web/pam.d/vega-web \
  %{buildroot}%{_sysconfdir}/pam.d/vega-web

%files
%dir %{_prefix}/lib/vega
%{_prefix}/lib/vega/vega-web
%{_prefix}/lib/systemd/system/vega-web.service
%{_sysusersdir}/vega-web.conf
%{_prefix}/lib/tmpfiles.d/vega-web.conf
%config(noreplace) %{_sysconfdir}/pam.d/vega-web

%pre
%sysusers_create_package vega-web packaging/vega-web/sysusers.d/vega-web.conf

%post
systemd-tmpfiles --create %{_prefix}/lib/tmpfiles.d/vega-web.conf 2>/dev/null || true
systemctl daemon-reload

%preun
if [ "$1" = "0" ]; then
  systemctl disable --now vega-web.service 2>/dev/null || true
fi

%postun
systemctl daemon-reload

%changelog
