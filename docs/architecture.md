# Arquitetura do vega-web

Status: Fase 1 (painel somente-leitura) implementada. Fase 2 (ações
privilegiadas) ainda não iniciada — ver seção final.

## Objetivo e limites

`vega-web` é um quarto frontend do Vega, ao lado de `vega-gtk` e
`vega-cli`: um painel HTTPS pensado para uso dentro da LAN (não para
exposição pública), sem substituir nem duplicar a lógica de `vegad` — só
consome o mesmo contrato `dbus/org.lyraos.Vega1.*.xml`, através do cliente
tipado `lyra-vega-dbus` já compartilhado pelo `vega-gtk`.

## Restrição que define o desenho

`vegad` autoriza cada ação mutante via `pkcheck --system-bus-name <sender>`
(`vegad/internal/dbusserver/polkit.go`) e resolve o usuário via
`GetConnectionUnixUser` sobre essa mesma conexão
(`vegad/internal/dbusserver/desktopuser.go`) — ou seja, a identidade vem do
peer credential *real* da conexão D-Bus, não de qualquer dado que a
aplicação afirme. Isso significa que `vega-web`, rodando como um único
processo de longa duração, não pode "dizer que é o usuário X" para o
`vegad` — só preservaria as regras de polkit por usuário se a chamada D-Bus
fosse fisicamente feita por um processo com o UID real daquele usuário.
Esse é o motivo da Fase 1 ser só leitura: os métodos somente-leitura do
`vegad` (`List*`/`Get*`/`Status`) não passam por `requirePolkit`, então não
têm esse problema — qualquer usuário autenticado no `vega-web` pode
enxergá-los sem precisar impersonar UID nenhum.

## Estrutura (Fase 1)

```text
vega-web/
├── Cargo.toml
├── build.rs          # cargo:rustc-link-lib=pam — sem bindgen/clang
└── src/
    ├── main.rs        # wiring: TLS, D-Bus, rotas, servidor axum
    ├── state.rs        # AppState, SessionStore (em memória)
    ├── auth.rs         # login/logout, middleware require_session
    ├── pam_ffi.rs       # bindings manuais com libpam (auth + acct)
    ├── tls.rs          # certificado autoassinado (gerado no 1º start)
    ├── layout.rs        # HTML compartilhado (sem framework JS)
    └── pages/
        ├── dashboard.rs
        ├── services.rs
        └── snapshots.rs
```

### Por que bindings manuais de PAM, não a crate `pam`

A crate `pam` (e `pam-client`) dependem de `pam-sys`, que gera bindings via
`bindgen`/`clang-sys` em tempo de build — nesta máquina de desenvolvimento
isso falha sem `libclang.so` (não instalado por padrão) e, mesmo quando
disponível, adiciona `clang`+`llvm` ao `BuildRequires` só para chamar ~5
funções de uma ABI C estável e documentada há décadas. `vega-web/src/pam_ffi.rs`
declara essas funções à mão (`pam_start`, `pam_authenticate`,
`pam_acct_mgmt`, `pam_end`, `pam_strerror`) e linka contra `libpam` via
`build.rs`, exigindo só `pam-devel` — mesmo pacote que já fornece os headers
usados por qualquer outro software C que fale com PAM no openSUSE. Sendo
código de autenticação, o hand-roll também fica pequeno o bastante para
revisar por inteiro, em vez de confiar numa dependência externa com cadeia
de build maior.

### Por que rodar como usuário de sistema sem privilégio

`pam_unix.so`, quando o processo chamador não é root, delega a checagem de
senha para `/usr/sbin/unix_chkpwd` (setuid-root, grupo `shadow`) — então
`vega-web` autentica contas normais do sistema sem precisar ler
`/etc/shadow` nem rodar como root. Mas como `vega-web` está checando a
senha de **outro** usuário (quem faz login no painel, não a própria conta
de serviço), `unix_chkpwd` só autoriza isso se o chamador for root ou
estiver no grupo `shadow` — por isso `packaging/vega-web/sysusers.d/vega-web.conf`
inclui `m vega-web shadow` além de criar o usuário. Sem essa linha, o login
falha silenciosamente mesmo com a senha certa (foi exatamente o que
aconteceu na primeira instalação de teste, antes dessa linha existir). O
serviço systemd roda como o usuário dedicado `vega-web` (criado via
`sysusers.d`), consistente com o desenho de mínimo privilégio: nesta fase
ele só lê D-Bus público e checa senha via PAM, nada mais.

### Sessão e TLS

- Sessão: token aleatório de 32 bytes num cookie assinado/criptografado
  (`axum_extra::extract::cookie::PrivateCookieJar`); os dados da sessão
  (usuário autenticado) ficam só no servidor, num `HashMap` em memória. A
  chave de assinatura é gerada a cada start — reiniciar o serviço invalida
  todas as sessões, o que é intencional (evita guardar segredo persistente
  só para isso).
- TLS: certificado autoassinado gerado no primeiro start
  (`VEGA_WEB_TLS_DIR`, padrão `/etc/vega/web/tls`, permissão `0600`). O
  aviso de certificado não confiável no navegador é esperado — ver
  `docs/vega-web-privacidade.md`.

## Fase 2 — ações privilegiadas (ainda não implementada)

Para preservar as regras de polkit por usuário (`packaging/vegad/org.lyraos.vega.policy`,
todas `auth_admin` interativo) sem alterar `vegad`, a Fase 2 precisa de:

1. Reautenticação estilo `sudo` na sessão web antes de qualquer ação de
   escrita.
2. Um binário setuid pequeno e separado (`vega-web-helper`) que dropa
   privilégio para o UID real do usuário autenticado antes de abrir sua
   própria conexão ao system bus — só assim a chamada chega ao `vegad` com
   o peer credential correto.
3. Um agente `org.freedesktop.PolicyKit1.AuthenticationAgent` implementado
   pelo helper, para responder ao `auth_admin` interativo sem sessão
   gráfica (mesmo padrão do `cockpit-session`/`cockpit-polkit`).
4. Piloto numa ação só (`org.lyraos.vega.services.configure`, ligar/desligar
   um serviço) antes de expandir para as outras 16 ações mutantes.

Ver o plano completo desta decisão no histórico da issue/PR que introduziu
o `vega-web`.
