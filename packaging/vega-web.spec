# Empacotamento para Linux. Ainda não publicado
# em nenhum repositório oficial (OBS ou similar) — ver packaging/opensuse/
# no topo do repositório para o script de instalação manual equivalente.
#
# %%{version} é passado pela release/CI via `rpmbuild --define "version X.Y.Z"`
# (a tag `vX.Y.Z` sem o "v"). Buildar sem essa define usa o default abaixo.
%{!?version: %define version 0.0.0}

Name:           vega-web
Version:        %{version}
Release:        1%{?dist}
Summary:        Painel web HTTPS (somente LAN) do Vega, centro de controle para Linux
License:        GPL-3.0-only
URL:            https://github.com/britors/Vega
Source0:        vega-src.tar.gz

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
%setup -q -c -n vega-src

%build
cd vega-web
cargo build --release --locked

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

# Usuário de sistema dedicado (sem privilégio nenhum nesta fase — só lê o
# D-Bus público do vegad e checa senha via PAM/unix_chkpwd, que já é
# setuid-root e não exige que o vega-web tenha acesso a /etc/shadow).
%pre
%sysusers_create_package vega-web packaging/vega-web/sysusers.d/vega-web.conf

%post
systemd-tmpfiles --create %{_prefix}/lib/tmpfiles.d/vega-web.conf 2>/dev/null || true
systemctl daemon-reload
# Não habilitado por padrão: expor um painel de administração na rede é uma
# decisão explícita do administrador, não algo que a instalação do pacote
# deve ligar sozinha.

%preun
if [ "$1" = "0" ]; then
  systemctl disable --now vega-web.service 2>/dev/null || true
fi

%postun
systemctl daemon-reload

%changelog
